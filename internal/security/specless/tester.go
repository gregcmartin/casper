package specless

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
)

// Tester handles security testing without an OpenAPI specification
type Tester struct {
	logger *logrus.Logger
	client *http.Client
}

// TestResult represents the result of a security test
type TestResult struct {
	Endpoint    string
	Method      string
	TestName    string
	Description string
	Severity    string
	Status      string
	Details     string
}

// New creates a new specless tester instance
func New(logger *logrus.Logger, client *http.Client) *Tester {
	return &Tester{
		logger: logger,
		client: client,
	}
}

// RunTests performs security tests on discovered endpoints
func (t *Tester) RunTests(endpoints []APIEndpoint) ([]TestResult, error) {
	t.logger.Info("Starting specless security testing")

	var (
		results []TestResult
		wg      sync.WaitGroup
		mutex   sync.Mutex
	)

	for _, endpoint := range endpoints {
		wg.Add(1)
		go func(ep APIEndpoint) {
			defer wg.Done()

			// Validate endpoint is accessible before testing
			if !t.isEndpointActive(ep) {
				t.logger.Debugf("Skipping inactive endpoint: %s", ep.URL)
				return
			}

			// Run various security tests
			endpointResults := []TestResult{}

			// Only test endpoints that return valid responses
			if authResults := t.runAuthTests(ep); len(authResults) > 0 {
				endpointResults = append(endpointResults, authResults...)
			}
			if injResults := t.runInjectionTests(ep); len(injResults) > 0 {
				endpointResults = append(endpointResults, injResults...)
			}
			if headerResults := t.runHeaderTests(ep); len(headerResults) > 0 {
				endpointResults = append(endpointResults, headerResults...)
			}
			if methodResults := t.runMethodTests(ep); len(methodResults) > 0 {
				endpointResults = append(endpointResults, methodResults...)
			}

			mutex.Lock()
			results = append(results, endpointResults...)
			mutex.Unlock()
		}(endpoint)
	}

	wg.Wait()
	return results, nil
}

// isEndpointActive checks if an endpoint is actually active and responding
func (t *Tester) isEndpointActive(endpoint APIEndpoint) bool {
	req, err := http.NewRequest("GET", endpoint.URL, nil)
	if err != nil {
		return false
	}

	resp, err := t.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// Only consider endpoint active if it returns a valid status code
	return resp.StatusCode != http.StatusNotFound &&
		resp.StatusCode != http.StatusGone &&
		resp.StatusCode != http.StatusBadGateway &&
		resp.StatusCode != http.StatusServiceUnavailable
}

// runAuthTests performs authentication-related security tests
func (t *Tester) runAuthTests(endpoint APIEndpoint) []TestResult {
	var results []TestResult

	// Test missing authentication
	req, err := http.NewRequest(endpoint.Method, endpoint.URL, nil)
	if err != nil {
		return results
	}

	resp, err := t.client.Do(req)
	if err != nil {
		return results
	}
	defer resp.Body.Close()

	// Only check auth if endpoint returns successful response
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
		// Check response content for sensitive data
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return results
		}

		// Only report if sensitive data is found
		if t.containsSensitiveData(string(body)) {
			results = append(results, TestResult{
				Endpoint:    endpoint.URL,
				Method:      endpoint.Method,
				TestName:    "Missing Authentication Check",
				Description: "Endpoint returns sensitive data without authentication",
				Severity:    "High",
				Status:      "Failed",
				Details:     fmt.Sprintf("Endpoint returns sensitive data with status code: %d", resp.StatusCode),
			})
		}
	}

	// Test auth bypass only on endpoints that normally require auth
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		bypassResults := t.testAuthBypass(endpoint)
		results = append(results, bypassResults...)
	}

	return results
}

// testAuthBypass tests various authentication bypass techniques
func (t *Tester) testAuthBypass(endpoint APIEndpoint) []TestResult {
	var results []TestResult

	bypassHeaders := map[string]string{
		"X-Original-URL":     endpoint.URL,
		"X-Rewrite-URL":      endpoint.URL,
		"X-Forwarded-Host":   "trusted-domain.com",
		"X-Forwarded-Scheme": "http",
	}

	for header, value := range bypassHeaders {
		req, err := http.NewRequest(endpoint.Method, endpoint.URL, nil)
		if err != nil {
			continue
		}

		req.Header.Set(header, value)
		resp, err := t.client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		// Only report bypass if we get a successful response
		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
			body, _ := io.ReadAll(resp.Body)
			if t.containsSensitiveData(string(body)) {
				results = append(results, TestResult{
					Endpoint:    endpoint.URL,
					Method:      endpoint.Method,
					TestName:    "Auth Bypass Check",
					Description: fmt.Sprintf("Authentication bypass possible using %s header", header),
					Severity:    "High",
					Status:      "Failed",
					Details:     fmt.Sprintf("Bypass successful with header %s: %s", header, value),
				})
			}
		}
	}

	return results
}

// runInjectionTests performs injection-related security tests
func (t *Tester) runInjectionTests(endpoint APIEndpoint) []TestResult {
	var results []TestResult

	payloads := map[string][]string{
		"SQL Injection": {
			"' OR '1'='1",
			"1; DROP TABLE users--",
			"1 UNION SELECT * FROM users--",
		},
		"Command Injection": {
			"; ls -la",
			"| cat /etc/passwd",
			"& whoami",
		},
		"XSS": {
			"<script>alert(1)</script>",
			"javascript:alert(1)",
			"'><script>alert(document.domain)</script>",
		},
	}

	for testType, testPayloads := range payloads {
		for _, payload := range testPayloads {
			// Test in URL parameters
			testURL := fmt.Sprintf("%s?param=%s", endpoint.URL, payload)
			req, err := http.NewRequest(endpoint.Method, testURL, nil)
			if err != nil {
				continue
			}

			resp, err := t.client.Do(req)
			if err != nil {
				continue
			}

			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				continue
			}

			// Validate injection results based on type
			switch testType {
			case "SQL Injection":
				if t.validateSQLInjection(string(body), payload) {
					results = append(results, TestResult{
						Endpoint:    endpoint.URL,
						Method:      endpoint.Method,
						TestName:    testType,
						Description: "SQL Injection vulnerability confirmed",
						Severity:    "High",
						Status:      "Failed",
						Details:     fmt.Sprintf("Payload: %s successfully executed", payload),
					})
				}
			case "Command Injection":
				if t.validateCommandInjection(string(body), payload) {
					results = append(results, TestResult{
						Endpoint:    endpoint.URL,
						Method:      endpoint.Method,
						TestName:    testType,
						Description: "Command Injection vulnerability confirmed",
						Severity:    "High",
						Status:      "Failed",
						Details:     fmt.Sprintf("Payload: %s successfully executed", payload),
					})
				}
			case "XSS":
				if t.validateXSS(string(body), payload) {
					results = append(results, TestResult{
						Endpoint:    endpoint.URL,
						Method:      endpoint.Method,
						TestName:    testType,
						Description: "XSS vulnerability confirmed",
						Severity:    "High",
						Status:      "Failed",
						Details:     fmt.Sprintf("Payload: %s successfully reflected", payload),
					})
				}
			}
		}
	}

	return results
}

// runHeaderTests performs security header tests
func (t *Tester) runHeaderTests(endpoint APIEndpoint) []TestResult {
	var results []TestResult

	req, err := http.NewRequest(endpoint.Method, endpoint.URL, nil)
	if err != nil {
		return results
	}

	resp, err := t.client.Do(req)
	if err != nil {
		return results
	}
	defer resp.Body.Close()

	// Only check headers on active endpoints
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
		securityHeaders := map[string]string{
			"X-Frame-Options":           "",
			"X-Content-Type-Options":    "nosniff",
			"X-XSS-Protection":          "1; mode=block",
			"Content-Security-Policy":   "",
			"Strict-Transport-Security": "",
		}

		for header, expectedValue := range securityHeaders {
			value := resp.Header.Get(header)
			if value == "" {
				results = append(results, TestResult{
					Endpoint:    endpoint.URL,
					Method:      endpoint.Method,
					TestName:    "Security Headers",
					Description: fmt.Sprintf("Missing security header: %s", header),
					Severity:    "Medium",
					Status:      "Failed",
					Details:     "Header not present in response",
				})
			} else if expectedValue != "" && value != expectedValue {
				results = append(results, TestResult{
					Endpoint:    endpoint.URL,
					Method:      endpoint.Method,
					TestName:    "Security Headers",
					Description: fmt.Sprintf("Incorrect value for security header: %s", header),
					Severity:    "Medium",
					Status:      "Failed",
					Details:     fmt.Sprintf("Expected: %s, Got: %s", expectedValue, value),
				})
			}
		}
	}

	return results
}

// runMethodTests checks for dangerous HTTP methods
func (t *Tester) runMethodTests(endpoint APIEndpoint) []TestResult {
	var results []TestResult

	dangerousMethods := []string{"PUT", "DELETE", "TRACE", "OPTIONS"}

	// First check if endpoint is accessible with GET
	req, err := http.NewRequest("GET", endpoint.URL, nil)
	if err != nil {
		return results
	}

	resp, err := t.client.Do(req)
	if err != nil {
		return results
	}
	resp.Body.Close()

	// Only test methods if endpoint is active
	if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusMethodNotAllowed {
		for _, method := range dangerousMethods {
			req, err := http.NewRequest(method, endpoint.URL, nil)
			if err != nil {
				continue
			}

			resp, err := t.client.Do(req)
			if err != nil {
				continue
			}
			resp.Body.Close()

			// Only report if dangerous method is actually enabled and working
			if resp.StatusCode == http.StatusOK ||
				resp.StatusCode == http.StatusCreated ||
				resp.StatusCode == http.StatusAccepted {
				results = append(results, TestResult{
					Endpoint:    endpoint.URL,
					Method:      method,
					TestName:    "Dangerous HTTP Methods",
					Description: fmt.Sprintf("Dangerous HTTP method %s is enabled and functional", method),
					Severity:    "Medium",
					Status:      "Failed",
					Details:     fmt.Sprintf("Method %s returned status code %d", method, resp.StatusCode),
				})
			}
		}
	}

	return results
}

// validateSQLInjection checks if SQL injection was successful
func (t *Tester) validateSQLInjection(response, payload string) bool {
	sqlErrors := []string{
		"SQL syntax",
		"mysql_fetch",
		"ORA-",
		"PostgreSQL",
		"SQLite/JDBCDriver",
		"System.Data.SQLClient",
	}

	// Check for SQL error messages
	responseLower := strings.ToLower(response)
	for _, err := range sqlErrors {
		if strings.Contains(responseLower, strings.ToLower(err)) {
			return true
		}
	}

	// Check for successful data extraction
	if strings.Contains(responseLower, "username") ||
		strings.Contains(responseLower, "password") ||
		strings.Contains(responseLower, "email") {
		return true
	}

	return false
}

// validateCommandInjection checks if command injection was successful
func (t *Tester) validateCommandInjection(response, payload string) bool {
	// Check for common command output patterns
	cmdPatterns := []string{
		"root:",         // /etc/passwd content
		"/bin/bash",     // shell paths
		"uid=",          // id command output
		"total ",        // ls command output
		"drwx",          // file permissions
		"Directory of",  // Windows dir output
		"Volume Serial", // Windows system info
	}

	responseLower := strings.ToLower(response)
	for _, pattern := range cmdPatterns {
		if strings.Contains(responseLower, strings.ToLower(pattern)) {
			return true
		}
	}

	return false
}

// validateXSS checks if XSS payload was successfully reflected
func (t *Tester) validateXSS(response, payload string) bool {
	// Check if payload is reflected exactly as sent
	if strings.Contains(response, payload) {
		// Verify payload is in HTML context
		return strings.Contains(response, "<") && strings.Contains(response, ">")
	}

	// Check for successful script execution indicators
	xssPatterns := []string{
		"<script",
		"javascript:",
		"onerror=",
		"onload=",
	}

	responseLower := strings.ToLower(response)
	for _, pattern := range xssPatterns {
		if strings.Contains(responseLower, pattern) {
			// Verify it's not just in a code sample or error message
			return !strings.Contains(responseLower, "error") &&
				!strings.Contains(responseLower, "exception") &&
				!strings.Contains(responseLower, "sample")
		}
	}

	return false
}

// containsSensitiveData checks if response contains sensitive information
func (t *Tester) containsSensitiveData(response string) bool {
	sensitivePatterns := []string{
		"password",
		"secret",
		"token",
		"api_key",
		"credit_card",
		"ssn",
		"social security",
		"private_key",
	}

	// Check JSON responses
	var jsonData map[string]interface{}
	if json.NewDecoder(strings.NewReader(response)).Decode(&jsonData) == nil {
		// Check for sensitive field names
		for key := range jsonData {
			keyLower := strings.ToLower(key)
			for _, pattern := range sensitivePatterns {
				if strings.Contains(keyLower, pattern) {
					return true
				}
			}
		}
	}

	// Check raw response
	responseLower := strings.ToLower(response)
	for _, pattern := range sensitivePatterns {
		if strings.Contains(responseLower, pattern) {
			// Verify it's not just in an error message or documentation
			return !strings.Contains(responseLower, "error") &&
				!strings.Contains(responseLower, "invalid") &&
				!strings.Contains(responseLower, "example")
		}
	}

	return false
}

// APIEndpoint represents a discovered API endpoint
type APIEndpoint struct {
	URL     string
	Method  string
	Headers map[string][]string
}
