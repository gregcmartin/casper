package vuln

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// Tester handles vulnerability testing
type Tester struct {
	logger  *logrus.Logger
	client  *http.Client
	baseURL string
	headers map[string]string
}

// New creates a new vulnerability tester instance
func New(logger *logrus.Logger, client *http.Client, baseURL string) *Tester {
	// Ensure baseURL ends without a slash
	baseURL = strings.TrimSuffix(baseURL, "/")

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

// RunTests performs vulnerability tests against specified paths
func (t *Tester) RunTests(paths []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	for _, p := range paths {
		if err := t.testPath(ctx, p); err != nil {
			t.logger.Warnf("Vulnerability testing failed for path %s: %v", p, err)
		}
	}

	return nil
}

// testPath tests a specific path for vulnerabilities
func (t *Tester) testPath(ctx context.Context, path string) error {
	tests := []struct {
		name string
		fn   func(context.Context, string) error
	}{
		{"SQL Injection", t.testSQLInjection},
		{"XSS", t.testXSS},
		{"Command Injection", t.testCommandInjection},
		{"Path Traversal", t.testPathTraversal},
		{"Information Disclosure", t.testInfoDisclosure},
	}

	for _, test := range tests {
		if err := test.fn(ctx, path); err != nil {
			t.logger.Warnf("%s test failed for path %s: %v", test.name, path, err)
		}
	}

	return nil
}

// Test implementations

func (t *Tester) testSQLInjection(ctx context.Context, endpoint string) error {
	payloads := map[string]string{
		"id":     "' OR '1'='1",
		"userId": "1; DROP TABLE users--",
		"filter": "' UNION SELECT * FROM users--",
	}

	for param, payload := range payloads {
		resp, err := t.makeRequest(ctx, "GET", endpoint, nil, map[string]string{param: payload})
		if err != nil {
			return err
		}
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			t.logger.Warnf("Potential SQL injection vulnerability found with payload: %s", payload)
		}
	}

	return nil
}

func (t *Tester) testXSS(ctx context.Context, endpoint string) error {
	payloads := map[string]string{
		"q":      "<script>alert(1)</script>",
		"search": "<img src=x onerror=alert(1)>",
		"input":  "javascript:alert(1)",
	}

	for param, payload := range payloads {
		resp, err := t.makeRequest(ctx, "GET", endpoint, nil, map[string]string{param: payload})
		if err != nil {
			return err
		}
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			t.logger.Warnf("Potential XSS vulnerability found with payload: %s", payload)
		}
	}

	return nil
}

func (t *Tester) testCommandInjection(ctx context.Context, endpoint string) error {
	payloads := map[string]string{
		"cmd":     "; ls",
		"exec":    "| cat /etc/passwd",
		"command": "`whoami`",
	}

	for param, payload := range payloads {
		resp, err := t.makeRequest(ctx, "GET", endpoint, nil, map[string]string{param: payload})
		if err != nil {
			return err
		}
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			t.logger.Warnf("Potential command injection vulnerability found with payload: %s", payload)
		}
	}

	return nil
}

func (t *Tester) testPathTraversal(ctx context.Context, endpoint string) error {
	payloads := map[string]string{
		"file":     "../../../etc/passwd",
		"path":     "..\\..\\..\\windows\\win.ini",
		"document": "%2e%2e%2f%2e%2e%2f",
	}

	for param, payload := range payloads {
		resp, err := t.makeRequest(ctx, "GET", endpoint, nil, map[string]string{param: payload})
		if err != nil {
			return err
		}
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			t.logger.Warnf("Potential path traversal vulnerability found with payload: %s", payload)
		}
	}

	return nil
}

func (t *Tester) testInfoDisclosure(ctx context.Context, endpoint string) error {
	resp, err := t.makeRequest(ctx, "GET", endpoint, nil, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check response headers for sensitive information
	sensitiveHeaders := []string{
		"Server",
		"X-Powered-By",
		"X-AspNet-Version",
		"X-AspNetMvc-Version",
	}

	for _, header := range sensitiveHeaders {
		if value := resp.Header.Get(header); value != "" {
			t.logger.Warnf("Information disclosure in header %s: %s", header, value)
		}
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
