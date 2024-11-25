package parameter

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
		baseURL:       strings.TrimSuffix(baseURL, "/"),
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
	endpoints := []string{
		"/users/v1/login",
		"/users/v1/register",
		"/books/v1",
		"/users/v1/{username}/email",
	}

	for _, endpoint := range endpoints {
		// Test duplicate parameters
		params := map[string][]string{
			"username": {"user1", "admin"},
			"email":    {"user@test.com", "admin@test.com"},
			"id":       {"1", "2"},
		}

		for param, values := range params {
			resp, err := t.makeRequestWithParams(ctx, "GET", endpoint, param, values)
			if err != nil {
				continue
			}
			resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				t.logger.Warnf("Potential HPP vulnerability: %s accepts duplicate parameters", endpoint)
			}
		}

		// Test parameter splitting
		splitParams := []string{
			"username=user1,admin",
			"email=user@test.com;admin@test.com",
			"id=1|2",
		}

		for _, param := range splitParams {
			resp, err := t.makeRequest(ctx, "GET", endpoint+"?"+param, nil, nil)
			if err != nil {
				continue
			}
			resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				t.logger.Warnf("Potential parameter splitting vulnerability: %s accepts split parameters", endpoint)
			}
		}
	}

	return nil
}

func (t *Tester) testTypeConfusion(ctx context.Context) error {
	endpoints := []string{
		"/users/v1/{username}",
		"/books/v1/{book_title}",
		"/users/v1/{username}/email",
	}

	tests := []struct {
		param string
		tests []struct {
			value    string
			dataType string
		}
	}{
		{
			param: "id",
			tests: []struct {
				value    string
				dataType string
			}{
				{"123", "number"},
				{"\"123\"", "string"},
				{"[123]", "array"},
				{"{\"id\":123}", "object"},
				{"true", "boolean"},
				{"null", "null"},
				{"undefined", "undefined"},
				{"NaN", "NaN"},
				{"Infinity", "Infinity"},
			},
		},
		{
			param: "email",
			tests: []struct {
				value    string
				dataType string
			}{
				{"test@test.com", "string"},
				{"[\"test@test.com\"]", "array"},
				{"{\"email\":\"test@test.com\"}", "object"},
				{"123", "number"},
				{"true", "boolean"},
			},
		},
	}

	for _, endpoint := range endpoints {
		for _, test := range tests {
			for _, typeTest := range test.tests {
				resp, err := t.makeRequestWithParam(ctx, "GET", endpoint, test.param, typeTest.value)
				if err != nil {
					continue
				}
				resp.Body.Close()

				if resp.StatusCode == http.StatusOK {
					t.logger.Warnf("Potential type confusion: %s accepts %s as %s", endpoint, test.param, typeTest.dataType)
				}
			}
		}
	}

	return nil
}

func (t *Tester) testArrayManipulation(ctx context.Context) error {
	endpoints := []string{
		"/books/v1",
		"/users/v1",
	}

	tests := []struct {
		param  string
		arrays []string
	}{
		{
			param: "ids",
			arrays: []string{
				"[1,2,3]",
				"[1;2;3]",
				"1,2,3",
				"{\"ids\":[1,2,3]}",
				"[[1],[2],[3]]",
				"[1][2][3]",
				"1;2;3",
				"1|2|3",
			},
		},
		{
			param: "usernames",
			arrays: []string{
				"[\"user1\",\"user2\"]",
				"user1,user2",
				"{\"users\":[\"user1\"]}",
				"[[\"user1\"],[\"user2\"]]",
				"[\"user1\"][\"user2\"]",
				"user1;user2",
				"user1|user2",
			},
		},
	}

	for _, endpoint := range endpoints {
		for _, test := range tests {
			for _, array := range test.arrays {
				resp, err := t.makeRequestWithParam(ctx, "GET", endpoint, test.param, array)
				if err != nil {
					continue
				}
				resp.Body.Close()

				if resp.StatusCode == http.StatusOK {
					t.logger.Warnf("Potential array manipulation: %s accepts %s with value %s", endpoint, test.param, array)
				}
			}
		}
	}

	return nil
}

func (t *Tester) testObjectInjection(ctx context.Context) error {
	endpoints := []string{
		"/users/v1/register",
		"/books/v1",
		"/users/v1/{username}/email",
	}

	tests := []struct {
		param   string
		objects []string
	}{
		{
			param: "data",
			objects: []string{
				"{\"id\":1}",
				"{\"id\":1,\"admin\":true}",
				"{\"$where\":\"1=1\"}",
				"{\"__proto__\":{\"admin\":true}}",
				"{\"constructor\":{\"prototype\":{\"admin\":true}}}",
				"{\"toString\":\"[object Object]\"}",
				"{\"valueOf\":\"[object Object]\"}",
				"{\"hasOwnProperty\":true}",
			},
		},
	}

	for _, endpoint := range endpoints {
		for _, test := range tests {
			for _, obj := range test.objects {
				resp, err := t.makeRequestWithParam(ctx, "POST", endpoint, test.param, obj)
				if err != nil {
					continue
				}
				resp.Body.Close()

				if resp.StatusCode == http.StatusOK {
					t.logger.Warnf("Potential object injection: %s accepts %s with value %s", endpoint, test.param, obj)
				}
			}
		}
	}

	return nil
}

func (t *Tester) testParameterTraversal(ctx context.Context) error {
	endpoints := []string{
		"/books/v1",
		"/users/v1",
	}

	tests := []struct {
		param string
		paths []string
	}{
		{
			param: "path",
			paths: []string{
				"../../../etc/passwd",
				"..\\..\\..\\windows\\win.ini",
				"%2e%2e%2f%2e%2e%2f",
				"....//....//",
				"..;/..;/",
				"..%252f..%252f",
				"..%c0%af..%c0%af",
				"..%u2215..%u2215",
				"..%c1%9c..%c1%9c",
			},
		},
		{
			param: "file",
			paths: []string{
				"/etc/passwd",
				"C:\\Windows\\win.ini",
				"file:///etc/passwd",
				"file://C:/Windows/win.ini",
				"php://filter/convert.base64-encode/resource=index.php",
				"data:text/plain;base64,SGVsbG8sIFdvcmxkIQ==",
				"expect://id",
				"phar://test.phar/test.txt",
			},
		},
	}

	for _, endpoint := range endpoints {
		for _, test := range tests {
			for _, path := range test.paths {
				resp, err := t.makeRequestWithParam(ctx, "GET", endpoint, test.param, path)
				if err != nil {
					continue
				}
				resp.Body.Close()

				if resp.StatusCode == http.StatusOK {
					t.logger.Warnf("Potential parameter traversal: %s accepts %s with value %s", endpoint, test.param, path)
				}
			}
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

func (t *Tester) makeRequestWithParam(ctx context.Context, method, endpoint, param, value string) (*http.Response, error) {
	params := map[string]string{param: value}
	return t.makeRequest(ctx, method, endpoint, nil, params)
}

func (t *Tester) makeRequestWithParams(ctx context.Context, method, endpoint, param string, values []string) (*http.Response, error) {
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

	// Add query parameters
	q := u.Query()
	for _, value := range values {
		q.Add(param, value) // Use Add instead of Set to allow multiple values
	}
	u.RawQuery = q.Encode()

	// Create request
	req, err := http.NewRequestWithContext(ctx, method, u.String(), nil)
	if err != nil {
		return nil, err
	}

	// Add default headers
	for k, v := range t.headers {
		req.Header.Set(k, v)
	}

	// Make request
	resp, err := t.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	return resp, nil
}
