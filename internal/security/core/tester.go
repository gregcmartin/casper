package core

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
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

	// Detect spec version and validate accordingly
	if strings.HasSuffix(specPath, ".yaml") || strings.HasSuffix(specPath, ".yml") {
		// Try OpenAPI 3 first
		if doc, err := openapi3.NewLoader().LoadFromFile(specPath); err == nil {
			return t.runOpenAPI3Tests(doc)
		}
	}

	// Fallback to Swagger 2.0
	doc, err := loads.Spec(specPath)
	if err != nil {
		return fmt.Errorf("failed to load spec file: %w", err)
	}
	return t.runSwagger2Tests(doc)
}

// runSwagger2Tests runs tests for Swagger 2.0 specs
func (t *Tester) runSwagger2Tests(doc *loads.Document) error {
	t.logger.Debug("Running Swagger 2.0 tests")
	swagger := doc.Spec()

	// Test each endpoint
	for path, pathItem := range swagger.Paths.Paths {
		if err := t.testSwagger2Path(path, pathItem); err != nil {
			return fmt.Errorf("failed testing path %s: %w", path, err)
		}
	}

	// Run global security tests
	if err := t.testGlobalSecurity(); err != nil {
		return fmt.Errorf("global security tests failed: %w", err)
	}

	return nil
}

// runOpenAPI3Tests runs tests for OpenAPI 3.0 specs
func (t *Tester) runOpenAPI3Tests(doc *openapi3.T) error {
	t.logger.Debug("Running OpenAPI 3.0 tests")

	// Test each endpoint
	if doc.Paths != nil {
		for path, pathItem := range doc.Paths.Map() {
			if err := t.testOpenAPI3Path(path, pathItem); err != nil {
				return fmt.Errorf("failed testing path %s: %w", path, err)
			}
		}
	}

	// Run global security tests
	if err := t.testGlobalSecurity(); err != nil {
		return fmt.Errorf("global security tests failed: %w", err)
	}

	return nil
}

// testSwagger2Path tests a Swagger 2.0 path
func (t *Tester) testSwagger2Path(path string, pathItem spec.PathItem) error {
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
			if err := t.testOperation(method, path, op.Security != nil); err != nil {
				return err
			}
		}
	}

	return nil
}

// testOpenAPI3Path tests an OpenAPI 3.0 path
func (t *Tester) testOpenAPI3Path(path string, pathItem *openapi3.PathItem) error {
	operations := map[string]*openapi3.Operation{
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
			requiresSecurity := false
			if op.Security != nil {
				requiresSecurity = len(*op.Security) > 0
			}
			if err := t.testOperation(method, path, requiresSecurity); err != nil {
				return err
			}
		}
	}

	return nil
}

// testOperation runs security tests for a specific operation
func (t *Tester) testOperation(method, path string, requiresSecurity bool) error {
	t.logger.Infof("Testing %s %s", method, path)

	tests := []struct {
		name string
		fn   func(string, string, bool) error
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
		if err := test.fn(method, path, requiresSecurity); err != nil {
			t.logger.Warnf("%s test failed for %s %s: %v", test.name, method, path, err)
		}
	}

	return nil
}

// Test implementations

func (t *Tester) testAuthentication(method, path string, requiresSecurity bool) error {
	if requiresSecurity {
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

func (t *Tester) testAuthorization(method, path string, requiresSecurity bool) error {
	headers := map[string]string{
		"Authorization": "Bearer invalid-token",
	}

	resp, err := t.makeRequest(method, path, headers)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if requiresSecurity && resp.StatusCode != http.StatusUnauthorized {
		t.logger.Warn("Endpoint accepts invalid authorization tokens")
	}
	return nil
}

func (t *Tester) testInputValidation(method, path string, requiresSecurity bool) error {
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

func (t *Tester) testRateLimiting(method, path string, requiresSecurity bool) error {
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

func (t *Tester) testErrorHandling(method, path string, requiresSecurity bool) error {
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

func (t *Tester) testDataValidation(method, path string, requiresSecurity bool) error {
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

func (t *Tester) testSecurityHeaders(method, path string, requiresSecurity bool) error {
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

func (t *Tester) testGlobalSecurity() error {
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

	// Test CORS configuration
	headers := map[string]string{
		"Origin": "http://evil.com",
	}

	resp, err = t.makeRequest("OPTIONS", "", headers)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.Header.Get("Access-Control-Allow-Origin") == "*" {
		t.logger.Warn("CORS allows all origins")
	}

	// Test global security headers
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
