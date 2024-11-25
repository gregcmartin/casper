package specless

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

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
	// Set reasonable timeouts
	client.Timeout = 10 * time.Second

	return &Tester{
		logger: logger,
		client: client,
	}
}

// RunTests performs security tests on discovered endpoints
func (t *Tester) RunTests(endpoints []APIEndpoint) ([]TestResult, error) {
	t.logger.Info("Starting specless security testing")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	var (
		results []TestResult
		wg      sync.WaitGroup
		mutex   sync.Mutex
		errChan = make(chan error, len(endpoints))
	)

	for _, endpoint := range endpoints {
		wg.Add(1)
		go func(ep APIEndpoint) {
			defer wg.Done()

			// Validate endpoint is accessible before testing
			active, err := t.isEndpointActive(ctx, ep)
			if err != nil {
				if !strings.Contains(err.Error(), "no such host") {
					select {
					case errChan <- err:
					default:
					}
				}
				return
			}
			if !active {
				t.logger.Debugf("Skipping inactive endpoint: %s", ep.URL)
				return
			}

			// Run various security tests
			var endpointResults []TestResult

			// Run tests in parallel
			var testWg sync.WaitGroup
			var testMutex sync.Mutex
			testErrChan := make(chan error, 4) // 4 test types

			testWg.Add(4)
			go func() {
				defer testWg.Done()
				if results, err := t.runAuthTests(ctx, ep); err != nil {
					if !strings.Contains(err.Error(), "no such host") {
						testErrChan <- err
					}
				} else if len(results) > 0 {
					testMutex.Lock()
					endpointResults = append(endpointResults, results...)
					testMutex.Unlock()
				}
			}()

			go func() {
				defer testWg.Done()
				if results, err := t.runInjectionTests(ctx, ep); err != nil {
					if !strings.Contains(err.Error(), "no such host") {
						testErrChan <- err
					}
				} else if len(results) > 0 {
					testMutex.Lock()
					endpointResults = append(endpointResults, results...)
					testMutex.Unlock()
				}
			}()

			go func() {
				defer testWg.Done()
				if results, err := t.runHeaderTests(ctx, ep); err != nil {
					if !strings.Contains(err.Error(), "no such host") {
						testErrChan <- err
					}
				} else if len(results) > 0 {
					testMutex.Lock()
					endpointResults = append(endpointResults, results...)
					testMutex.Unlock()
				}
			}()

			go func() {
				defer testWg.Done()
				if results, err := t.runMethodTests(ctx, ep); err != nil {
					if !strings.Contains(err.Error(), "no such host") {
						testErrChan <- err
					}
				} else if len(results) > 0 {
					testMutex.Lock()
					endpointResults = append(endpointResults, results...)
					testMutex.Unlock()
				}
			}()

			testWg.Wait()
			close(testErrChan)

			// Collect test errors
			for err := range testErrChan {
				if err != nil && !strings.Contains(err.Error(), "no such host") {
					select {
					case errChan <- err:
					default:
					}
				}
			}

			// Add results to global results slice
			if len(endpointResults) > 0 {
				mutex.Lock()
				results = append(results, endpointResults...)
				mutex.Unlock()
			}
		}(endpoint)
	}

	wg.Wait()
	close(errChan)

	// Collect any errors
	var errs []error
	for err := range errChan {
		if err != nil && !strings.Contains(err.Error(), "no such host") {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return results, fmt.Errorf("multiple test failures: %v", errs)
	}
	return results, nil
}

// isEndpointActive checks if an endpoint is actually active and responding
func (t *Tester) isEndpointActive(ctx context.Context, endpoint APIEndpoint) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint.URL, nil)
	if err != nil {
		return false, err
	}

	resp, err := t.client.Do(req)
	if err != nil {
		// Skip DNS resolution errors
		if strings.Contains(err.Error(), "no such host") {
			return false, err
		}
		return false, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Only consider endpoint active if it returns a valid status code
	return resp.StatusCode != http.StatusNotFound &&
		resp.StatusCode != http.StatusGone &&
		resp.StatusCode != http.StatusBadGateway &&
		resp.StatusCode != http.StatusServiceUnavailable, nil
}

// runAuthTests performs authentication-related security tests
func (t *Tester) runAuthTests(ctx context.Context, endpoint APIEndpoint) ([]TestResult, error) {
	var results []TestResult

	// Test missing authentication
	req, err := http.NewRequestWithContext(ctx, endpoint.Method, endpoint.URL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := t.client.Do(req)
	if err != nil {
		// Skip DNS resolution errors
		if strings.Contains(err.Error(), "no such host") {
			return nil, err
		}
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Only check auth if endpoint returns successful response
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
		// Check response content for sensitive data
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
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
		bypassResults, err := t.testAuthBypass(ctx, endpoint)
		if err != nil {
			return results, err
		}
		results = append(results, bypassResults...)
	}

	return results, nil
}

// testAuthBypass tests various authentication bypass techniques
func (t *Tester) testAuthBypass(ctx context.Context, endpoint APIEndpoint) ([]TestResult, error) {
	var (
		results []TestResult
		wg      sync.WaitGroup
		mutex   sync.Mutex
		errChan = make(chan error, 4) // 4 bypass headers
	)

	bypassHeaders := map[string]string{
		"X-Original-URL":     endpoint.URL,
		"X-Rewrite-URL":      endpoint.URL,
		"X-Forwarded-Host":   "trusted-domain.com",
		"X-Forwarded-Scheme": "http",
	}

	for header, value := range bypassHeaders {
		wg.Add(1)
		go func(h, v string) {
			defer wg.Done()

			select {
			case <-ctx.Done():
				errChan <- ctx.Err()
				return
			default:
				req, err := http.NewRequestWithContext(ctx, endpoint.Method, endpoint.URL, nil)
				if err != nil {
					errChan <- err
					return
				}

				req.Header.Set(h, v)
				resp, err := t.client.Do(req)
				if err != nil {
					if !strings.Contains(err.Error(), "no such host") {
						errChan <- err
					}
					return
				}
				defer resp.Body.Close()

				// Only report bypass if we get a successful response
				if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
					body, err := io.ReadAll(resp.Body)
					if err != nil {
						errChan <- err
						return
					}

					if t.containsSensitiveData(string(body)) {
						mutex.Lock()
						results = append(results, TestResult{
							Endpoint:    endpoint.URL,
							Method:      endpoint.Method,
							TestName:    "Auth Bypass Check",
							Description: fmt.Sprintf("Authentication bypass possible using %s header", h),
							Severity:    "High",
							Status:      "Failed",
							Details:     fmt.Sprintf("Bypass successful with header %s: %s", h, v),
						})
						mutex.Unlock()
					}
				}
			}
		}(header, value)
	}

	wg.Wait()
	close(errChan)

	// Collect any errors
	var errs []error
	for err := range errChan {
		if err != nil && !strings.Contains(err.Error(), "no such host") {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return results, fmt.Errorf("multiple auth bypass test failures: %v", errs)
	}
	return results, nil
}

// runInjectionTests performs injection-related security tests
func (t *Tester) runInjectionTests(ctx context.Context, endpoint APIEndpoint) ([]TestResult, error) {
	var (
		results []TestResult
		wg      sync.WaitGroup
		mutex   sync.Mutex
		errChan = make(chan error, 10) // Approximate number of total payloads
	)

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
			wg.Add(1)
			go func(tt, p string) {
				defer wg.Done()

				select {
				case <-ctx.Done():
					errChan <- ctx.Err()
					return
				default:
					// Test in URL parameters
					testURL := fmt.Sprintf("%s?param=%s", endpoint.URL, p)
					req, err := http.NewRequestWithContext(ctx, endpoint.Method, testURL, nil)
					if err != nil {
						errChan <- err
						return
					}

					resp, err := t.client.Do(req)
					if err != nil {
						if !strings.Contains(err.Error(), "no such host") {
							errChan <- err
						}
						return
					}

					body, err := io.ReadAll(resp.Body)
					resp.Body.Close()
					if err != nil {
						errChan <- err
						return
					}

					// Validate injection results based on type
					var result *TestResult
					switch tt {
					case "SQL Injection":
						if t.validateSQLInjection(string(body), p) {
							result = &TestResult{
								Endpoint:    endpoint.URL,
								Method:      endpoint.Method,
								TestName:    tt,
								Description: "SQL Injection vulnerability confirmed",
								Severity:    "High",
								Status:      "Failed",
								Details:     fmt.Sprintf("Payload: %s successfully executed", p),
							}
						}
					case "Command Injection":
						if t.validateCommandInjection(string(body), p) {
							result = &TestResult{
								Endpoint:    endpoint.URL,
								Method:      endpoint.Method,
								TestName:    tt,
								Description: "Command Injection vulnerability confirmed",
								Severity:    "High",
								Status:      "Failed",
								Details:     fmt.Sprintf("Payload: %s successfully executed", p),
							}
						}
					case "XSS":
						if t.validateXSS(string(body), p) {
							result = &TestResult{
								Endpoint:    endpoint.URL,
								Method:      endpoint.Method,
								TestName:    tt,
								Description: "XSS vulnerability confirmed",
								Severity:    "High",
								Status:      "Failed",
								Details:     fmt.Sprintf("Payload: %s successfully reflected", p),
							}
						}
					}

					if result != nil {
						mutex.Lock()
						results = append(results, *result)
						mutex.Unlock()
					}
				}
			}(testType, payload)
		}
	}

	wg.Wait()
	close(errChan)

	// Collect any errors
	var errs []error
	for err := range errChan {
		if err != nil && !strings.Contains(err.Error(), "no such host") {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return results, fmt.Errorf("multiple injection test failures: %v", errs)
	}
	return results, nil
}

// runHeaderTests performs security header tests
func (t *Tester) runHeaderTests(ctx context.Context, endpoint APIEndpoint) ([]TestResult, error) {
	var results []TestResult

	req, err := http.NewRequestWithContext(ctx, endpoint.Method, endpoint.URL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := t.client.Do(req)
	if err != nil {
		// Skip DNS resolution errors
		if strings.Contains(err.Error(), "no such host") {
			return nil, err
		}
		return nil, fmt.Errorf("request failed: %w", err)
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

	return results, nil
}

// runMethodTests checks for dangerous HTTP methods
func (t *Tester) runMethodTests(ctx context.Context, endpoint APIEndpoint) ([]TestResult, error) {
	var (
		results []TestResult
		wg      sync.WaitGroup
		mutex   sync.Mutex
		errChan = make(chan error, 4) // 4 dangerous methods
	)

	// First check if endpoint is accessible with GET
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint.URL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := t.client.Do(req)
	if err != nil {
		// Skip DNS resolution errors
		if strings.Contains(err.Error(), "no such host") {
			return nil, err
		}
		return nil, fmt.Errorf("request failed: %w", err)
	}
	resp.Body.Close()

	// Only test methods if endpoint is active
	if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusMethodNotAllowed {
		dangerousMethods := []string{"PUT", "DELETE", "TRACE", "OPTIONS"}

		for _, method := range dangerousMethods {
			wg.Add(1)
			go func(m string) {
				defer wg.Done()

				select {
				case <-ctx.Done():
					errChan <- ctx.Err()
					return
				default:
					req, err := http.NewRequestWithContext(ctx, m, endpoint.URL, nil)
					if err != nil {
						errChan <- err
						return
					}

					resp, err := t.client.Do(req)
					if err != nil {
						if !strings.Contains(err.Error(), "no such host") {
							errChan <- err
						}
						return
					}
					resp.Body.Close()

					// Only report if dangerous method is actually enabled and working
					if resp.StatusCode == http.StatusOK ||
						resp.StatusCode == http.StatusCreated ||
						resp.StatusCode == http.StatusAccepted {
						mutex.Lock()
						results = append(results, TestResult{
							Endpoint:    endpoint.URL,
							Method:      m,
							TestName:    "Dangerous HTTP Methods",
							Description: fmt.Sprintf("Dangerous HTTP method %s is enabled and functional", m),
							Severity:    "Medium",
							Status:      "Failed",
							Details:     fmt.Sprintf("Method %s returned status code %d", m, resp.StatusCode),
						})
						mutex.Unlock()
					}
				}
			}(method)
		}

		wg.Wait()
		close(errChan)

		// Collect any errors
		var errs []error
		for err := range errChan {
			if err != nil && !strings.Contains(err.Error(), "no such host") {
				errs = append(errs, err)
			}
		}

		if len(errs) > 0 {
			return results, fmt.Errorf("multiple method test failures: %v", errs)
		}
	}

	return results, nil
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
