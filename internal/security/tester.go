package security

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-openapi/loads"
	"github.com/go-openapi/spec"
	"github.com/sirupsen/logrus"
)

// Tester handles API security testing
type Tester struct {
	logger  *logrus.Logger
	client  *http.Client
	baseURL string
	headers map[string]string
}

// New creates a new security tester instance
func New(logger *logrus.Logger, baseURL string) *Tester {
	return &Tester{
		logger:  logger,
		client:  &http.Client{Timeout: 30 * time.Second},
		baseURL: strings.TrimRight(baseURL, "/"),
		headers: make(map[string]string),
	}
}

// SetHeader sets a custom header for all requests
func (t *Tester) SetHeader(key, value string) {
	t.headers[key] = value
}

// RunTests performs security tests against the API using the OpenAPI spec file
func (t *Tester) RunTests(specPath string) error {
	t.logger.Info("Starting security tests")

	// Load the specification
	doc, err := loads.Spec(specPath)
	if err != nil {
		return fmt.Errorf("failed to load spec file: %w", err)
	}
	t.logger.Debug("Successfully loaded spec file")

	swagger := doc.Spec()

	// Test each endpoint
	for path, pathItem := range swagger.Paths.Paths {
		if err := t.testPath(path, pathItem); err != nil {
			return fmt.Errorf("failed testing path %s: %w", path, err)
		}
	}

	return nil
}

// testPath runs security tests for a specific path
func (t *Tester) testPath(path string, pathItem spec.PathItem) error {
	operations := map[string]*spec.Operation{
		"GET":     pathItem.Get,
		"POST":    pathItem.Post,
		"PUT":     pathItem.Put,
		"DELETE":  pathItem.Delete,
		"PATCH":   pathItem.Patch,
		"HEAD":    pathItem.Head,
		"OPTIONS": pathItem.Options,
	}

	for method, op := range operations {
		if op != nil {
			if err := t.testOperation(method, path, op); err != nil {
				return err
			}
		}
	}

	return nil
}

// testOperation runs security tests for a specific operation
func (t *Tester) testOperation(method, path string, op *spec.Operation) error {
	t.logger.Infof("Testing %s %s", method, path)

	tests := []struct {
		name string
		fn   func(string, string, *spec.Operation) error
	}{
		{"Authentication Bypass", t.testAuthBypass},
		{"SQL Injection", t.testSQLInjection},
		{"XSS", t.testXSS},
		{"Rate Limiting", t.testRateLimiting},
		{"CORS Misconfiguration", t.testCORS},
		{"Information Disclosure", t.testInfoDisclosure},
		{"Mass Assignment", t.testMassAssignment},
		{"SSRF", t.testSSRF},
		{"JWT Security", t.testJWTSecurity},
	}

	for _, test := range tests {
		if err := test.fn(method, path, op); err != nil {
			t.logger.Warnf("%s test failed for %s %s: %v", test.name, method, path, err)
		}
	}

	return nil
}

// testAuthBypass attempts to bypass authentication
func (t *Tester) testAuthBypass(method, path string, op *spec.Operation) error {
	if len(op.Security) == 0 && op.Security != nil {
		// Try accessing endpoint without authentication
		resp, err := t.makeRequest(method, path, nil)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusUnauthorized {
			return fmt.Errorf("endpoint accessible without authentication: %d", resp.StatusCode)
		}

		// Try with fake tokens
		fakeTokens := []string{
			"Bearer invalid_token",
			"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
			"Basic invalid:credentials",
		}

		for _, token := range fakeTokens {
			headers := map[string]string{
				"Authorization": token,
			}
			resp, err := t.makeRequest(method, path, headers)
			if err != nil {
				return err
			}
			resp.Body.Close()

			if resp.StatusCode != http.StatusUnauthorized {
				t.logger.Warnf("Endpoint might be vulnerable to auth bypass with token: %s", token)
			}
		}
	}
	return nil
}

// testSQLInjection tests for SQL injection vulnerabilities
func (t *Tester) testSQLInjection(method, path string, op *spec.Operation) error {
	payloads := []string{
		"' OR '1'='1",
		"1; DROP TABLE users--",
		"1 UNION SELECT * FROM users--",
		"1' OR '1'='1'--",
		"' OR 1=1--",
		"admin'--",
		"admin' #",
		"admin'/*",
		"' or '1'='1",
		"' or 1=1--",
		"' or 1=1#",
		"' or 1=1/*",
		"') or '1'='1--",
		"') or ('1'='1--",
	}

	for _, payload := range payloads {
		headers := map[string]string{
			"X-Test": payload,
		}

		resp, err := t.makeRequest(method, path, headers)
		if err != nil {
			return err
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()

		if err != nil {
			return err
		}

		// Check for SQL error patterns
		errorPatterns := []string{
			"SQL", "MySQL", "ORA-", "PostgreSQL",
			"SQLite", "SQL Server", "syntax error",
		}

		respStr := string(body)
		for _, pattern := range errorPatterns {
			if strings.Contains(respStr, pattern) {
				return fmt.Errorf("possible SQL injection vulnerability detected with payload: %s", payload)
			}
		}
	}
	return nil
}

// testXSS tests for Cross-Site Scripting vulnerabilities
func (t *Tester) testXSS(method, path string, op *spec.Operation) error {
	payloads := []string{
		"<script>alert(1)</script>",
		"javascript:alert(1)",
		"'><script>alert(1)</script>",
		"><script>alert(1)</script>",
		"<img src=x onerror=alert(1)>",
		"<svg/onload=alert(1)>",
		"<iframe src=javascript:alert(1)>",
		"<body onload=alert(1)>",
		"\"><script>alert(1)</script>",
		"'><img src=x onerror=alert(1)>",
	}

	for _, payload := range payloads {
		headers := map[string]string{
			"X-Test": payload,
		}

		resp, err := t.makeRequest(method, path, headers)
		if err != nil {
			return err
		}

		// Check security headers
		securityHeaders := map[string]string{
			"X-XSS-Protection":        "1; mode=block",
			"Content-Security-Policy": "",
			"X-Content-Type-Options":  "nosniff",
		}

		for header, expectedValue := range securityHeaders {
			if value := resp.Header.Get(header); value == "" {
				t.logger.Warnf("Missing security header: %s", header)
			} else if expectedValue != "" && value != expectedValue {
				t.logger.Warnf("Incorrect security header value: %s: %s", header, value)
			}
		}

		resp.Body.Close()
	}
	return nil
}

// testRateLimiting tests for rate limiting implementation
func (t *Tester) testRateLimiting(method, path string, op *spec.Operation) error {
	// Make multiple requests in quick succession
	for i := 0; i < 50; i++ {
		resp, err := t.makeRequest(method, path, nil)
		if err != nil {
			return err
		}
		resp.Body.Close()

		// Check for rate limiting headers
		rateLimitHeaders := []string{
			"X-RateLimit-Limit",
			"X-RateLimit-Remaining",
			"X-RateLimit-Reset",
			"Retry-After",
		}

		hasRateLimiting := false
		for _, header := range rateLimitHeaders {
			if resp.Header.Get(header) != "" {
				hasRateLimiting = true
				break
			}
		}

		if !hasRateLimiting {
			t.logger.Warn("No rate limiting headers detected")
		}

		if resp.StatusCode == 429 {
			// Rate limiting is implemented
			return nil
		}
	}

	t.logger.Warn("No rate limiting detected after 50 requests")
	return nil
}

// testCORS tests for CORS misconfigurations
func (t *Tester) testCORS(method, path string, op *spec.Operation) error {
	origins := []string{
		"http://evil.com",
		"https://attacker.com",
		"null",
		"*",
		"file://",
	}

	for _, origin := range origins {
		headers := map[string]string{
			"Origin": origin,
		}

		resp, err := t.makeRequest(method, path, headers)
		if err != nil {
			return err
		}
		resp.Body.Close()

		if allowOrigin := resp.Header.Get("Access-Control-Allow-Origin"); allowOrigin == "*" {
			t.logger.Warn("CORS allows all origins")
		} else if allowOrigin == origin && origin != "" {
			t.logger.Warnf("CORS allows potentially dangerous origin: %s", origin)
		}

		if resp.Header.Get("Access-Control-Allow-Credentials") == "true" {
			t.logger.Warn("CORS allows credentials with potentially dangerous origin")
		}
	}
	return nil
}

// testInfoDisclosure tests for information disclosure vulnerabilities
func (t *Tester) testInfoDisclosure(method, path string, op *spec.Operation) error {
	sensitiveHeaders := []string{
		"Server",
		"X-Powered-By",
		"X-AspNet-Version",
		"X-AspNetMvc-Version",
	}

	resp, err := t.makeRequest(method, path, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	for _, header := range sensitiveHeaders {
		if value := resp.Header.Get(header); value != "" {
			t.logger.Warnf("Sensitive header exposed: %s: %s", header, value)
		}
	}

	// Check for detailed error messages
	if resp.StatusCode >= 400 {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		sensitivePatterns := []string{
			"stack trace",
			"exception",
			"error in",
			"syntax error",
			"failed to",
			"unable to",
			"debug",
			"localhost",
			"127.0.0.1",
		}

		respStr := strings.ToLower(string(body))
		for _, pattern := range sensitivePatterns {
			if strings.Contains(respStr, pattern) {
				t.logger.Warnf("Detailed error message might expose sensitive information: contains '%s'", pattern)
			}
		}
	}

	return nil
}

// testMassAssignment tests for mass assignment vulnerabilities
func (t *Tester) testMassAssignment(method, path string, op *spec.Operation) error {
	if method == "POST" || method == "PUT" || method == "PATCH" {
		sensitiveFields := []string{
			"admin",
			"role",
			"permissions",
			"isAdmin",
			"superuser",
			"isSuperuser",
			"verified",
			"isVerified",
		}

		payload := make(map[string]interface{})
		for _, field := range sensitiveFields {
			payload[field] = true
		}

		jsonPayload, err := json.Marshal(payload)
		if err != nil {
			return err
		}

		headers := map[string]string{
			"Content-Type": "application/json",
		}

		req, err := http.NewRequest(method, t.baseURL+path, strings.NewReader(string(jsonPayload)))
		if err != nil {
			return err
		}

		for k, v := range headers {
			req.Header.Set(k, v)
		}

		resp, err := t.client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
			t.logger.Warn("Endpoint might be vulnerable to mass assignment")
		}
	}
	return nil
}

// testSSRF tests for Server-Side Request Forgery vulnerabilities
func (t *Tester) testSSRF(method, path string, op *spec.Operation) error {
	ssrfTargets := []string{
		"http://localhost",
		"http://127.0.0.1",
		"http://169.254.169.254",          // AWS metadata
		"http://metadata.google.internal", // GCP metadata
		"file:///etc/passwd",
		"http://10.0.0.0",
		"http://172.16.0.0",
		"http://192.168.0.0",
	}

	for _, target := range ssrfTargets {
		headers := map[string]string{
			"X-Forwarded-For":           target,
			"X-Forwarded-Host":          target,
			"X-Remote-Addr":             target,
			"X-Remote-IP":               target,
			"X-Original-URL":            target,
			"X-Rewrite-URL":             target,
			"X-Custom-IP-Authorization": target,
		}

		resp, err := t.makeRequest(method, path, headers)
		if err != nil {
			return err
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusUnauthorized {
			t.logger.Warnf("Potential SSRF vulnerability with target: %s", target)
		}
	}
	return nil
}

// testJWTSecurity tests for JWT security issues
func (t *Tester) testJWTSecurity(method, path string, op *spec.Operation) error {
	if auth := t.findAuthHeader(op); auth != nil && strings.Contains(strings.ToLower(auth.Description), "jwt") {
		weakTokens := []string{
			// None algorithm
			"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.",
			// Empty signature
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.",
		}

		for _, token := range weakTokens {
			headers := map[string]string{
				"Authorization": "Bearer " + token,
			}

			resp, err := t.makeRequest(method, path, headers)
			if err != nil {
				return err
			}
			resp.Body.Close()

			if resp.StatusCode != http.StatusUnauthorized {
				t.logger.Warn("Endpoint might accept invalid JWT tokens")
			}
		}
	}
	return nil
}

// findAuthHeader looks for authorization parameter in operation
func (t *Tester) findAuthHeader(op *spec.Operation) *spec.Parameter {
	for _, param := range op.Parameters {
		if param.In == "header" && strings.ToLower(param.Name) == "authorization" {
			return &param
		}
	}
	return nil
}

// makeRequest performs an HTTP request
func (t *Tester) makeRequest(method, path string, additionalHeaders map[string]string) (*http.Response, error) {
	url := t.baseURL + path
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}

	// Add default headers
	for k, v := range t.headers {
		req.Header.Set(k, v)
	}

	// Add additional headers
	for k, v := range additionalHeaders {
		req.Header.Set(k, v)
	}

	return t.client.Do(req)
}
