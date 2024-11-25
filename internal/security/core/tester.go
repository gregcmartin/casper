package core

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

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
	// Set reasonable timeouts
	client.Timeout = 10 * time.Second

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

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Detect spec version and validate accordingly
	if strings.HasSuffix(specPath, ".yaml") || strings.HasSuffix(specPath, ".yml") {
		// Try OpenAPI 3 first
		if doc, err := openapi3.NewLoader().LoadFromFile(specPath); err == nil {
			return t.runOpenAPI3Tests(ctx, doc)
		}
	}

	// Fallback to Swagger 2.0
	doc, err := loads.Spec(specPath)
	if err != nil {
		return fmt.Errorf("failed to load spec file: %w", err)
	}
	return t.runSwagger2Tests(ctx, doc)
}

// runSwagger2Tests runs tests for Swagger 2.0 specs
func (t *Tester) runSwagger2Tests(ctx context.Context, doc *loads.Document) error {
	t.logger.Debug("Running Swagger 2.0 tests")
	swagger := doc.Spec()

	var wg sync.WaitGroup
	errChan := make(chan error, len(swagger.Paths.Paths))

	// Test each endpoint
	for path, pathItem := range swagger.Paths.Paths {
		wg.Add(1)
		go func(p string, pi spec.PathItem) {
			defer wg.Done()
			if err := t.testSwagger2Path(ctx, p, pi); err != nil {
				select {
				case errChan <- fmt.Errorf("failed testing path %s: %w", p, err):
				default:
				}
			}
		}(path, pathItem)
	}

	// Run global security tests in parallel
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := t.testGlobalSecurity(ctx); err != nil {
			select {
			case errChan <- fmt.Errorf("global security tests failed: %w", err):
			default:
			}
		}
	}()

	// Wait for all tests to complete
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
		return fmt.Errorf("multiple test failures: %v", errs)
	}
	return nil
}

// runOpenAPI3Tests runs tests for OpenAPI 3.0 specs
func (t *Tester) runOpenAPI3Tests(ctx context.Context, doc *openapi3.T) error {
	t.logger.Debug("Running OpenAPI 3.0 tests")

	var wg sync.WaitGroup
	errChan := make(chan error, len(doc.Paths.Map()))

	// Test each endpoint
	if doc.Paths != nil {
		for path, pathItem := range doc.Paths.Map() {
			wg.Add(1)
			go func(p string, pi *openapi3.PathItem) {
				defer wg.Done()
				if err := t.testOpenAPI3Path(ctx, p, pi); err != nil {
					select {
					case errChan <- fmt.Errorf("failed testing path %s: %w", p, err):
					default:
					}
				}
			}(path, pathItem)
		}
	}

	// Run global security tests in parallel
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := t.testGlobalSecurity(ctx); err != nil {
			select {
			case errChan <- fmt.Errorf("global security tests failed: %w", err):
			default:
			}
		}
	}()

	// Wait for all tests to complete
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
		return fmt.Errorf("multiple test failures: %v", errs)
	}
	return nil
}

// testSwagger2Path tests a Swagger 2.0 path
func (t *Tester) testSwagger2Path(ctx context.Context, path string, pathItem spec.PathItem) error {
	operations := map[string]*spec.Operation{
		"GET":     pathItem.Get,
		"POST":    pathItem.Post,
		"PUT":     pathItem.Put,
		"DELETE":  pathItem.Delete,
		"PATCH":   pathItem.Patch,
		"HEAD":    pathItem.Head,
		"OPTIONS": pathItem.Options,
	}

	var wg sync.WaitGroup
	errChan := make(chan error, len(operations))

	for method, op := range operations {
		if op != nil {
			wg.Add(1)
			go func(m string, o *spec.Operation) {
				defer wg.Done()
				if err := t.testOperation(ctx, m, path, o.Security != nil); err != nil {
					select {
					case errChan <- err:
					default:
					}
				}
			}(method, op)
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
		return fmt.Errorf("multiple operation test failures: %v", errs)
	}
	return nil
}

// testOpenAPI3Path tests an OpenAPI 3.0 path
func (t *Tester) testOpenAPI3Path(ctx context.Context, path string, pathItem *openapi3.PathItem) error {
	operations := map[string]*openapi3.Operation{
		"GET":     pathItem.Get,
		"POST":    pathItem.Post,
		"PUT":     pathItem.Put,
		"DELETE":  pathItem.Delete,
		"PATCH":   pathItem.Patch,
		"HEAD":    pathItem.Head,
		"OPTIONS": pathItem.Options,
	}

	var wg sync.WaitGroup
	errChan := make(chan error, len(operations))

	for method, op := range operations {
		if op != nil {
			wg.Add(1)
			go func(m string, o *openapi3.Operation) {
				defer wg.Done()
				requiresSecurity := false
				if o.Security != nil {
					requiresSecurity = len(*o.Security) > 0
				}
				if err := t.testOperation(ctx, m, path, requiresSecurity); err != nil {
					select {
					case errChan <- err:
					default:
					}
				}
			}(method, op)
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
		return fmt.Errorf("multiple operation test failures: %v", errs)
	}
	return nil
}

// testOperation runs security tests for a specific operation
func (t *Tester) testOperation(ctx context.Context, method, path string, requiresSecurity bool) error {
	t.logger.Infof("Testing %s %s", method, path)

	tests := []struct {
		name string
		fn   func(context.Context, string, string, bool) error
	}{
		{"Authentication", t.testAuthentication},
		{"Authorization", t.testAuthorization},
		{"Input Validation", t.testInputValidation},
		{"Rate Limiting", t.testRateLimiting},
		{"Error Handling", t.testErrorHandling},
		{"Data Validation", t.testDataValidation},
		{"Security Headers", t.testSecurityHeaders},
	}

	var wg sync.WaitGroup
	errChan := make(chan error, len(tests))

	for _, test := range tests {
		wg.Add(1)
		go func(tt struct {
			name string
			fn   func(context.Context, string, string, bool) error
		}) {
			defer wg.Done()
			if err := tt.fn(ctx, method, path, requiresSecurity); err != nil {
				if !strings.Contains(err.Error(), "no such host") {
					t.logger.Warnf("%s test failed for %s %s: %v", tt.name, method, path, err)
					select {
					case errChan <- err:
					default:
					}
				}
			}
		}(test)
	}

	wg.Wait()
	close(errChan)

	return nil
}

// Test implementations

func (t *Tester) testAuthentication(ctx context.Context, method, path string, requiresSecurity bool) error {
	if requiresSecurity {
		resp, err := t.makeRequest(ctx, method, path, nil)
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

func (t *Tester) testAuthorization(ctx context.Context, method, path string, requiresSecurity bool) error {
	headers := map[string]string{
		"Authorization": "Bearer invalid-token",
	}

	resp, err := t.makeRequest(ctx, method, path, headers)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if requiresSecurity && resp.StatusCode != http.StatusUnauthorized {
		t.logger.Warn("Endpoint accepts invalid authorization tokens")
	}
	return nil
}

func (t *Tester) testInputValidation(ctx context.Context, method, path string, requiresSecurity bool) error {
	payloads := []string{
		"<script>alert(1)</script>",
		"'; DROP TABLE users--",
		strings.Repeat("A", 10000),
	}

	for _, payload := range payloads {
		headers := map[string]string{
			"Content-Type": "application/json",
		}
		resp, err := t.makeRequestWithBody(ctx, method, path, headers, payload)
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

func (t *Tester) testRateLimiting(ctx context.Context, method, path string, requiresSecurity bool) error {
	for i := 0; i < 20; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			resp, err := t.makeRequest(ctx, method, path, nil)
			if err != nil {
				return err
			}
			resp.Body.Close()

			if i > 10 && resp.StatusCode != http.StatusTooManyRequests {
				t.logger.Warn("No rate limiting detected")
			}
		}
	}
	return nil
}

func (t *Tester) testErrorHandling(ctx context.Context, method, path string, requiresSecurity bool) error {
	headers := map[string]string{
		"Content-Type": "invalid",
	}

	resp, err := t.makeRequest(ctx, method, path, headers)
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

func (t *Tester) testDataValidation(ctx context.Context, method, path string, requiresSecurity bool) error {
	if method == "POST" || method == "PUT" {
		invalidData := `{"invalid": true}`
		headers := map[string]string{
			"Content-Type": "application/json",
		}

		resp, err := t.makeRequestWithBody(ctx, method, path, headers, invalidData)
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

func (t *Tester) testSecurityHeaders(ctx context.Context, method, path string, requiresSecurity bool) error {
	resp, err := t.makeRequest(ctx, method, path, nil)
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

func (t *Tester) testGlobalSecurity(ctx context.Context) error {
	// Test TLS configuration
	if !strings.HasPrefix(t.baseURL, "https://") {
		t.logger.Warn("API not using HTTPS")
	}

	resp, err := t.makeRequest(ctx, "GET", "", nil)
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

	resp, err = t.makeRequest(ctx, "OPTIONS", "", headers)
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

func (t *Tester) makeRequest(ctx context.Context, method, path string, headers map[string]string) (*http.Response, error) {
	url := t.baseURL + path
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
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

	resp, err := t.client.Do(req)
	if err != nil {
		// Skip DNS resolution errors
		if strings.Contains(err.Error(), "no such host") {
			return nil, err
		}
		return nil, fmt.Errorf("request failed: %w", err)
	}

	return resp, nil
}

func (t *Tester) makeRequestWithBody(ctx context.Context, method, path string, headers map[string]string, body string) (*http.Response, error) {
	url := t.baseURL + path
	req, err := http.NewRequestWithContext(ctx, method, url, strings.NewReader(body))
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

	resp, err := t.client.Do(req)
	if err != nil {
		// Skip DNS resolution errors
		if strings.Contains(err.Error(), "no such host") {
			return nil, err
		}
		return nil, fmt.Errorf("request failed: %w", err)
	}

	return resp, nil
}
