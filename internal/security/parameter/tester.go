package parameter

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// Tester handles parameter-based security testing
type Tester struct {
	logger        *logrus.Logger
	client        *http.Client
	baseURL       string
	headers       map[string]string
	skipURLEncode bool
}

// New creates a new parameter tester instance
func New(logger *logrus.Logger, client *http.Client, baseURL string) *Tester {
	return &Tester{
		logger:        logger,
		client:        client,
		baseURL:       baseURL,
		headers:       make(map[string]string),
		skipURLEncode: false,
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

// RunTests performs parameter-based security tests using a spec file
func (t *Tester) RunTests(specPath string) error {
	t.logger.Info("Starting parameter-based security tests")
	return t.runParameterTests()
}

// RunDirectTests performs direct parameter-based security tests
func (t *Tester) RunDirectTests() error {
	t.logger.Info("Starting direct parameter-based security tests")
	return t.runParameterTests()
}

// runParameterTests performs the parameter security test suite
func (t *Tester) runParameterTests() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	tests := []struct {
		name string
		fn   func(context.Context) error
	}{
		{"Parameter Pollution", t.testParameterPollution},
		{"Type Confusion", t.testTypeConfusion},
		{"Array Manipulation", t.testArrayManipulation},
		{"Object Injection", t.testObjectInjection},
		{"Parameter Traversal", t.testParameterTraversal},
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

func (t *Tester) testParameterPollution(ctx context.Context) error {
	tests := []struct {
		endpoint string
		params   map[string][]string
	}{
		{
			endpoint: "/api/search",
			params: map[string][]string{
				"q":    {"test", "test2"},
				"sort": {"asc", "desc"},
			},
		},
		{
			endpoint: "/api/filter",
			params: map[string][]string{
				"type":   {"user", "admin"},
				"status": {"active", "inactive"},
			},
		},
	}

	for _, test := range tests {
		for param, values := range test.params {
			resp, err := t.makeRequestWithParams(ctx, "GET", test.endpoint, param, values)
			if err != nil {
				continue
			}
			resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				t.logger.Warnf("Potential HPP vulnerability found at %s with parameter %s", test.endpoint, param)
			}
		}
	}

	return nil
}

func (t *Tester) testTypeConfusion(ctx context.Context) error {
	tests := []struct {
		endpoint string
		param    string
		values   []string
	}{
		{
			endpoint: "/api/user",
			param:    "id",
			values:   []string{"123", "\"123\"", "[123]", "{\"id\":123}"},
		},
		{
			endpoint: "/api/item",
			param:    "quantity",
			values:   []string{"10", "\"10\"", "10.0", "true"},
		},
	}

	for _, test := range tests {
		for _, value := range test.values {
			resp, err := t.makeRequestWithParam(ctx, "GET", test.endpoint, test.param, value)
			if err != nil {
				continue
			}
			resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				t.logger.Warnf("Potential type confusion at %s with value %s", test.endpoint, value)
			}
		}
	}

	return nil
}

func (t *Tester) testArrayManipulation(ctx context.Context) error {
	tests := []struct {
		endpoint string
		param    string
		arrays   []string
	}{
		{
			endpoint: "/api/items",
			param:    "ids",
			arrays:   []string{"[1,2,3]", "[1;2;3]", "1,2,3", "{\"ids\":[1,2,3]}"},
		},
		{
			endpoint: "/api/batch",
			param:    "users",
			arrays:   []string{"[\"user1\",\"user2\"]", "user1,user2", "{\"users\":[\"user1\"]}"},
		},
	}

	for _, test := range tests {
		for _, array := range test.arrays {
			resp, err := t.makeRequestWithParam(ctx, "GET", test.endpoint, test.param, array)
			if err != nil {
				continue
			}
			resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				t.logger.Warnf("Potential array manipulation at %s with value %s", test.endpoint, array)
			}
		}
	}

	return nil
}

func (t *Tester) testObjectInjection(ctx context.Context) error {
	tests := []struct {
		endpoint string
		param    string
		objects  []string
	}{
		{
			endpoint: "/api/update",
			param:    "data",
			objects: []string{
				"{\"id\":1}",
				"{\"id\":1,\"admin\":true}",
				"{\"$where\":\"1=1\"}",
				"{\"__proto__\":{\"admin\":true}}",
			},
		},
	}

	for _, test := range tests {
		for _, obj := range test.objects {
			resp, err := t.makeRequestWithParam(ctx, "POST", test.endpoint, test.param, obj)
			if err != nil {
				continue
			}
			resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				t.logger.Warnf("Potential object injection at %s with value %s", test.endpoint, obj)
			}
		}
	}

	return nil
}

func (t *Tester) testParameterTraversal(ctx context.Context) error {
	tests := []struct {
		endpoint string
		param    string
		paths    []string
	}{
		{
			endpoint: "/api/file",
			param:    "path",
			paths: []string{
				"../../../etc/passwd",
				"..\\..\\..\\windows\\win.ini",
				"%2e%2e%2f%2e%2e%2f",
			},
		},
	}

	for _, test := range tests {
		for _, path := range test.paths {
			resp, err := t.makeRequestWithParam(ctx, "GET", test.endpoint, test.param, path)
			if err != nil {
				continue
			}
			resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				t.logger.Warnf("Potential parameter traversal at %s with value %s", test.endpoint, path)
			}
		}
	}

	return nil
}

// Helper methods

func (t *Tester) makeRequestWithParam(ctx context.Context, method, path, param, value string) (*http.Response, error) {
	urlPath := path
	if !t.skipURLEncode {
		urlPath = url.QueryEscape(path)
		value = url.QueryEscape(value)
	}

	fullURL := fmt.Sprintf("%s%s?%s=%s", t.baseURL, urlPath, param, value)
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}

	// Add default headers
	for k, v := range t.headers {
		req.Header.Set(k, v)
	}

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	return resp, nil
}

func (t *Tester) makeRequestWithParams(ctx context.Context, method, path, param string, values []string) (*http.Response, error) {
	urlPath := path
	if !t.skipURLEncode {
		urlPath = url.QueryEscape(path)
	}

	var params []string
	for _, value := range values {
		if !t.skipURLEncode {
			value = url.QueryEscape(value)
		}
		params = append(params, fmt.Sprintf("%s=%s", param, value))
	}

	fullURL := fmt.Sprintf("%s%s?%s", t.baseURL, urlPath, strings.Join(params, "&"))
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}

	// Add default headers
	for k, v := range t.headers {
		req.Header.Set(k, v)
	}

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	return resp, nil
}
