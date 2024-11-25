package core

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/go-openapi/loads"
	"github.com/go-openapi/spec"
	"github.com/sirupsen/logrus"
)

// Tester handles core security testing
type Tester struct {
	logger  *logrus.Logger
	client  *http.Client
	baseURL string
	headers map[string]string
}

// New creates a new core security tester instance
func New(logger *logrus.Logger, client *http.Client, baseURL string) *Tester {
	return &Tester{
		logger:  logger,
		client:  client,
		baseURL: baseURL,
		headers: make(map[string]string),
	}
}

// SetHeader sets a custom header for all requests
func (t *Tester) SetHeader(key, value string) {
	t.headers[key] = value
}

// RunTests performs core security tests against the API
func (t *Tester) RunTests(specPath string) error {
	t.logger.Info("Starting core security tests")

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

	// Run global security tests
	if err := t.testGlobalSecurity(); err != nil {
		return fmt.Errorf("global security tests failed: %w", err)
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
		{"Authentication", t.testAuthentication},
		{"Authorization", t.testAuthorization},
		{"Input Validation", t.testInputValidation},
		{"Rate Limiting", t.testRateLimiting},
		{"Error Handling", t.testErrorHandling},
		{"Data Validation", t.testDataValidation},
		{"Security Headers", t.testSecurityHeaders},
	}

	for _, test := range tests {
		if err := test.fn(method, path, op); err != nil {
			t.logger.Warnf("%s test failed for %s %s: %v", test.name, method, path, err)
		}
	}

	return nil
}

// testGlobalSecurity runs security tests that apply to the entire API
func (t *Tester) testGlobalSecurity() error {
	tests := []struct {
		name string
		fn   func() error
	}{
		{"TLS Configuration", t.testTLSConfig},
		{"CORS Configuration", t.testCORSConfig},
		{"Security Headers", t.testGlobalSecurityHeaders},
	}

	for _, test := range tests {
		if err := test.fn(); err != nil {
			t.logger.Warnf("%s test failed: %v", test.name, err)
		}
	}

	return nil
}

// Test implementations

func (t *Tester) testAuthentication(method, path string, op *spec.Operation) error {
	// Test authentication mechanisms
	if len(op.Security) > 0 {
		resp, err := t.makeRequest(method, path, nil)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusUnauthorized {
			t.logger.Warn("Endpoint accessible without proper authentication")
		}
	}
	return nil
}

func (t *Tester) testAuthorization(method, path string, op *spec.Operation) error {
	// Test authorization levels
	headers := map[string]string{
		"Authorization": "Bearer invalid-token",
	}

	resp, err := t.makeRequest(method, path, headers)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.logger.Warn("Endpoint accepts invalid authorization tokens")
	}
	return nil
}

func (t *Tester) testInputValidation(method, path string, op *spec.Operation) error {
	// Test input validation
	payloads := []string{
		"<script>alert(1)</script>",
		"'; DROP TABLE users--",
		strings.Repeat("A", 10000),
	}

	for _, payload := range payloads {
		headers := map[string]string{
			"Content-Type": "application/json",
		}
		resp, err := t.makeRequestWithBody(method, path, headers, payload)
		if err != nil {
			return err
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusBadRequest {
			t.logger.Warnf("Endpoint accepts potentially malicious input: %s", payload)
		}
	}
	return nil
}

func (t *Tester) testRateLimiting(method, path string, op *spec.Operation) error {
	// Test rate limiting
	for i := 0; i < 20; i++ {
		resp, err := t.makeRequest(method, path, nil)
		if err != nil {
			return err
		}
		resp.Body.Close()

		if i > 10 && resp.StatusCode != http.StatusTooManyRequests {
			t.logger.Warn("No rate limiting detected")
		}
	}
	return nil
}

func (t *Tester) testErrorHandling(method, path string, op *spec.Operation) error {
	// Test error handling
	headers := map[string]string{
		"Content-Type": "invalid",
	}

	resp, err := t.makeRequest(method, path, headers)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if strings.Contains(string(body), "stack trace") {
		t.logger.Warn("Error response contains sensitive information")
	}
	return nil
}

func (t *Tester) testDataValidation(method, path string, op *spec.Operation) error {
	// Test data validation
	if method == "POST" || method == "PUT" {
		invalidData := `{"invalid": true}`
		headers := map[string]string{
			"Content-Type": "application/json",
		}

		resp, err := t.makeRequestWithBody(method, path, headers, invalidData)
		if err != nil {
			return err
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusBadRequest {
			t.logger.Warn("Endpoint accepts invalid data structure")
		}
	}
	return nil
}

func (t *Tester) testSecurityHeaders(method, path string, op *spec.Operation) error {
	// Test security headers
	resp, err := t.makeRequest(method, path, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	requiredHeaders := []string{
		"X-Content-Type-Options",
		"X-Frame-Options",
		"X-XSS-Protection",
	}

	for _, header := range requiredHeaders {
		if resp.Header.Get(header) == "" {
			t.logger.Warnf("Missing security header: %s", header)
		}
	}
	return nil
}

func (t *Tester) testTLSConfig() error {
	// Test TLS configuration
	if !strings.HasPrefix(t.baseURL, "https://") {
		t.logger.Warn("API not using HTTPS")
	}

	resp, err := t.makeRequest("GET", "", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.TLS != nil && resp.TLS.Version < tls.VersionTLS12 {
		t.logger.Warn("TLS version below 1.2")
	}
	return nil
}

func (t *Tester) testCORSConfig() error {
	// Test CORS configuration
	headers := map[string]string{
		"Origin": "http://evil.com",
	}

	resp, err := t.makeRequest("OPTIONS", "", headers)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.Header.Get("Access-Control-Allow-Origin") == "*" {
		t.logger.Warn("CORS allows all origins")
	}
	return nil
}

func (t *Tester) testGlobalSecurityHeaders() error {
	// Test global security headers
	resp, err := t.makeRequest("GET", "", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.Header.Get("Strict-Transport-Security") == "" {
		t.logger.Warn("HSTS not implemented")
	}
	return nil
}

// Helper methods

func (t *Tester) makeRequest(method, path string, headers map[string]string) (*http.Response, error) {
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
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	return t.client.Do(req)
}

func (t *Tester) makeRequestWithBody(method, path string, headers map[string]string, body string) (*http.Response, error) {
	url := t.baseURL + path
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		return nil, err
	}

	// Add default headers
	for k, v := range t.headers {
		req.Header.Set(k, v)
	}

	// Add additional headers
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	return t.client.Do(req)
}
