package core

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/gregcmartin/casper/internal/reporter"
	"github.com/sirupsen/logrus"
)

// Tester handles core security testing
type Tester struct {
	logger        *logrus.Logger
	client        *http.Client
	baseURL       string
	headers       map[string]string
	skipURLEncode bool
	reporter      *reporter.Reporter
}

// New creates a new core security tester instance
func New(logger *logrus.Logger, client *http.Client, baseURL string, reporter *reporter.Reporter) *Tester {
	return &Tester{
		logger:        logger,
		client:        client,
		baseURL:       strings.TrimSuffix(baseURL, "/"),
		headers:       make(map[string]string),
		skipURLEncode: false,
		reporter:      reporter,
	}
}

// SetHeader sets a custom header for all requests
func (t *Tester) SetHeader(key, value string) {
	t.headers[key] = value
}

// SetURLEncoding sets whether to skip URL encoding
func (t *Tester) SetURLEncoding(encode bool) {
	t.skipURLEncode = !encode
}

// RunTests performs core security tests using a spec file
func (t *Tester) RunTests(specPath string) error {
	t.logger.Info("Starting core security tests with spec")
	return t.runCoreTests(true)
}

// RunTestsWithoutSpec performs core security tests without a spec file
func (t *Tester) RunTestsWithoutSpec() error {
	t.logger.Info("Starting core security tests without spec")
	return t.runCoreTests(false)
}

// RunDirectTests performs direct core security tests
func (t *Tester) RunDirectTests() error {
	t.logger.Info("Starting direct core security tests")
	return t.runCoreTests(false)
}

// RunRawTests performs raw core security tests
func (t *Tester) RunRawTests() error {
	t.logger.Info("Starting raw core security tests")
	return t.testRawSecurity()
}

// runCoreTests performs the core security test suite
func (t *Tester) runCoreTests(useSpec bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	tests := []struct {
		name string
		fn   func(context.Context) error
	}{
		{"Authentication", t.testAuthentication},
		{"Authorization", t.testAuthorization},
		{"Input Validation", t.testInputValidation},
		{"Rate Limiting", t.testRateLimiting},
		{"Error Handling", t.testErrorHandling},
		{"Security Headers", t.testSecurityHeaders},
		{"TLS Configuration", t.testTLSConfig},
	}

	for _, test := range tests {
		t.logger.Infof("Running %s tests...", test.name)
		if err := test.fn(ctx); err != nil {
			t.logger.Warnf("%s tests failed: %v", test.name, err)
		}
	}

	return nil
}

// Test implementations

func (t *Tester) testAuthentication(ctx context.Context) error {
	endpoints := []string{
		"/api/login",
		"/api/auth",
		"/api/token",
	}

	for _, endpoint := range endpoints {
		resp, err := t.makeRequest(ctx, "POST", endpoint, nil, nil)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusUnauthorized {
			t.reporter.LogIssue(
				"Authentication Bypass",
				"High",
				"Endpoint accessible without proper authentication",
				endpoint,
				fmt.Sprintf("Status code: %d", resp.StatusCode),
			)
		}
	}

	return nil
}

func (t *Tester) testAuthorization(ctx context.Context) error {
	endpoints := []string{
		"/api/admin",
		"/api/users",
		"/api/settings",
	}

	headers := map[string]string{
		"Authorization": "Bearer invalid-token",
	}

	for _, endpoint := range endpoints {
		resp, err := t.makeRequest(ctx, "GET", endpoint, headers, nil)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusUnauthorized {
			t.reporter.LogIssue(
				"Authorization Bypass",
				"High",
				"Endpoint accepts invalid authorization token",
				endpoint,
				fmt.Sprintf("Status code: %d with invalid token", resp.StatusCode),
			)
		}
	}

	return nil
}

func (t *Tester) testInputValidation(ctx context.Context) error {
	payloads := []struct {
		value       string
		issueType   string
		description string
	}{
		{
			"<script>alert(1)</script>",
			"XSS",
			"Endpoint accepts XSS payload",
		},
		{
			"'; DROP TABLE users--",
			"SQL Injection",
			"Endpoint accepts SQL injection payload",
		},
		{
			strings.Repeat("A", 10000),
			"Buffer Overflow",
			"Endpoint accepts large input without validation",
		},
	}

	for _, payload := range payloads {
		resp, err := t.makeRequestWithBody(ctx, "POST", "/api/data", nil, payload.value)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusBadRequest {
			t.reporter.LogIssue(
				payload.issueType,
				"High",
				payload.description,
				"/api/data",
				fmt.Sprintf("Payload: %s, Status: %d", payload.value, resp.StatusCode),
			)
		}
	}

	return nil
}

func (t *Tester) testRateLimiting(ctx context.Context) error {
	endpoint := "/api/test"
	requests := 0
	start := time.Now()

	for i := 0; i < 50; i++ {
		resp, err := t.makeRequest(ctx, "GET", endpoint, nil, nil)
		if err != nil {
			continue
		}
		resp.Body.Close()
		requests++

		if i > 30 && resp.StatusCode != http.StatusTooManyRequests {
			t.reporter.LogIssue(
				"Rate Limiting",
				"Medium",
				"No rate limiting detected on endpoint",
				endpoint,
				fmt.Sprintf("%d requests in %v without rate limiting", requests, time.Since(start)),
			)
			break
		}
	}

	return nil
}

func (t *Tester) testErrorHandling(ctx context.Context) error {
	endpoints := []string{
		"/api/invalid",
		"/api/error",
		"/api/undefined",
	}

	for _, endpoint := range endpoints {
		resp, err := t.makeRequest(ctx, "GET", endpoint, nil, nil)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode >= 500 {
			t.reporter.LogIssue(
				"Error Handling",
				"Medium",
				"Server error detected",
				endpoint,
				fmt.Sprintf("Status code: %d", resp.StatusCode),
			)
		}
	}

	return nil
}

func (t *Tester) testSecurityHeaders(ctx context.Context) error {
	resp, err := t.makeRequest(ctx, "GET", "/", nil, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	requiredHeaders := []string{
		"X-Content-Type-Options",
		"X-Frame-Options",
		"X-XSS-Protection",
		"Content-Security-Policy",
		"Strict-Transport-Security",
	}

	for _, header := range requiredHeaders {
		if resp.Header.Get(header) == "" {
			t.reporter.LogIssue(
				"Missing Security Headers",
				"Medium",
				fmt.Sprintf("Missing security header: %s", header),
				"/",
				"Header not present in response",
			)
		}
	}

	return nil
}

func (t *Tester) testTLSConfig(ctx context.Context) error {
	if !strings.HasPrefix(t.baseURL, "https://") {
		t.reporter.LogIssue(
			"TLS Configuration",
			"High",
			"API not using HTTPS",
			t.baseURL,
			"Non-HTTPS URL in use",
		)
		return nil
	}

	resp, err := t.makeRequest(ctx, "GET", "/", nil, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.TLS != nil {
		if resp.TLS.Version < tls.VersionTLS12 {
			t.reporter.LogIssue(
				"TLS Configuration",
				"High",
				"TLS version below 1.2",
				t.baseURL,
				fmt.Sprintf("TLS Version: %x", resp.TLS.Version),
			)
		}
	}

	return nil
}

func (t *Tester) testRawSecurity() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Test basic endpoints without validation
	endpoints := []string{
		"/",
		"/api",
		"/auth",
		"/login",
		"/admin",
	}

	for _, endpoint := range endpoints {
		resp, err := t.makeRequest(ctx, "GET", endpoint, nil, nil)
		if err != nil {
			continue
		}
		resp.Body.Close()

		t.logger.Infof("Endpoint %s returned status: %d", endpoint, resp.StatusCode)
	}

	return nil
}

// Helper methods

func (t *Tester) makeRequest(ctx context.Context, method, endpoint string, headers map[string]string, params map[string]string) (*http.Response, error) {
	// Build URL
	u, err := url.Parse(t.baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}

	// Ensure endpoint starts with /
	if !strings.HasPrefix(endpoint, "/") {
		endpoint = "/" + endpoint
	}

	// Set path
	u.Path = path.Join(u.Path, endpoint)

	// Add query parameters if any
	if params != nil {
		q := u.Query()
		for k, v := range params {
			q.Set(k, v)
		}
		u.RawQuery = q.Encode()
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, method, u.String(), nil)
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

	// Make request
	resp, err := t.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	return resp, nil
}

func (t *Tester) makeRequestWithBody(ctx context.Context, method, endpoint string, headers map[string]string, body string) (*http.Response, error) {
	// Build URL
	u, err := url.Parse(t.baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}

	// Ensure endpoint starts with /
	if !strings.HasPrefix(endpoint, "/") {
		endpoint = "/" + endpoint
	}

	// Set path
	u.Path = path.Join(u.Path, endpoint)

	// Create request with body
	req, err := http.NewRequestWithContext(ctx, method, u.String(), strings.NewReader(body))
	if err != nil {
		return nil, err
	}

	// Set content type
	req.Header.Set("Content-Type", "application/json")

	// Add default headers
	for k, v := range t.headers {
		req.Header.Set(k, v)
	}

	// Add additional headers
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	// Make request
	resp, err := t.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	return resp, nil
}
