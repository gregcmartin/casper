package parameter

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/go-openapi/loads"
	"github.com/sirupsen/logrus"
)

// Tester handles parameter-based security testing
type Tester struct {
	logger  *logrus.Logger
	client  *http.Client
	baseURL string
}

// New creates a new parameter tester instance
func New(logger *logrus.Logger, client *http.Client, baseURL string) *Tester {
	return &Tester{
		logger:  logger,
		client:  client,
		baseURL: baseURL,
	}
}

// RunTests performs parameter-based security tests against the API
func (t *Tester) RunTests(specPath string) error {
	t.logger.Info("Starting parameter-based security tests")

	// Load the specification
	doc, err := loads.Spec(specPath)
	if err != nil {
		return fmt.Errorf("failed to load spec file: %w", err)
	}

	swagger := doc.Spec()

	// Test each endpoint
	for path, pathItem := range swagger.Paths.Paths {
		operations := map[string]bool{
			"GET":     pathItem.Get != nil,
			"POST":    pathItem.Post != nil,
			"PUT":     pathItem.Put != nil,
			"DELETE":  pathItem.Delete != nil,
			"PATCH":   pathItem.Patch != nil,
			"HEAD":    pathItem.Head != nil,
			"OPTIONS": pathItem.Options != nil,
		}

		for method, exists := range operations {
			if exists {
				if err := t.TestParameterVulnerabilities(path, method); err != nil {
					t.logger.Warnf("Parameter testing failed for %s %s: %v", method, path, err)
				}
			}
		}
	}

	return nil
}

// TestParameterVulnerabilities runs parameter-based security tests
func (t *Tester) TestParameterVulnerabilities(path string, method string) error {
	tests := []struct {
		name string
		fn   func(string, string) error
	}{
		{"GUID/UUID Bypass", t.testGUIDBypass},
		{"Array Wrapping", t.testArrayWrapping},
		{"JSON Object Wrapping", t.testJSONObjectWrapping},
		{"Parameter Pollution", t.testParameterPollution},
		{"JSON Parameter Pollution", t.testJSONParameterPollution},
		{"Wildcard Testing", t.testWildcards},
		{"Content Type Manipulation", t.testContentTypeManipulation},
		{"Version Parameter Testing", t.testVersionParameters},
		{"Environment Detection", t.testEnvironmentDetection},
		{"Export Injection", t.testExportInjection},
		{"API Version Testing", t.testAPIVersions},
	}

	for _, test := range tests {
		if err := test.fn(path, method); err != nil {
			t.logger.Warnf("%s test failed for %s %s: %v", test.name, method, path, err)
		}
	}

	return nil
}

// testGUIDBypass tests numeric ID substitution for GUID/UUID
func (t *Tester) testGUIDBypass(path, method string) error {
	numericPaths := []string{
		strings.Replace(path, "/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "/1", -1),
		strings.Replace(path, "/[0-9a-f]{32}", "/1", -1),
	}

	for _, testPath := range numericPaths {
		resp, err := t.makeRequest(method, testPath, nil)
		if err != nil {
			return err
		}
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			t.logger.Warnf("GUID/UUID bypass possible with numeric ID: %s", testPath)
		}
	}
	return nil
}

// testArrayWrapping tests array wrapping vulnerabilities
func (t *Tester) testArrayWrapping(path, method string) error {
	payloads := []string{
		`{"id":111}`,
		`{"id":[111]}`,
		`{"id":["111"]}`,
		`[{"id":111}]`,
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

		if resp.StatusCode == http.StatusOK {
			t.logger.Warnf("Array wrapping accepted: %s", payload)
		}
	}
	return nil
}

// testJSONObjectWrapping tests JSON object wrapping vulnerabilities
func (t *Tester) testJSONObjectWrapping(path, method string) error {
	payloads := []string{
		`{"id":111}`,
		`{"id":{"id":111}}`,
		`{"data":{"id":111}}`,
		`{"id":{"data":{"id":111}}}`,
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

		if resp.StatusCode == http.StatusOK {
			t.logger.Warnf("JSON object wrapping accepted: %s", payload)
		}
	}
	return nil
}

// testParameterPollution tests HTTP parameter pollution
func (t *Tester) testParameterPollution(path, method string) error {
	pollutedPaths := []string{
		path + "?id=legit&id=victim",
		path + "?id=victim&id=legit",
		path + "?id[]=legit&id[]=victim",
		path + "?user_id=legit&user_id=victim",
		path + "?user_id[]=legit&user_id[]=victim",
	}

	for _, testPath := range pollutedPaths {
		resp, err := t.makeRequest(method, testPath, nil)
		if err != nil {
			return err
		}
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			t.logger.Warnf("Parameter pollution possible: %s", testPath)
		}
	}
	return nil
}

// testJSONParameterPollution tests JSON parameter pollution
func (t *Tester) testJSONParameterPollution(path, method string) error {
	payloads := []string{
		`{"user_id":"legit","user_id":"victim"}`,
		`{"user_id":["legit","victim"]}`,
		`{"user_id":{"legit":"victim"}}`,
		`{"data":{"user_id":"legit"},"user_id":"victim"}`,
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

		if resp.StatusCode == http.StatusOK {
			t.logger.Warnf("JSON parameter pollution possible: %s", payload)
		}
	}
	return nil
}

// testWildcards tests wildcard character handling
func (t *Tester) testWildcards(path, method string) error {
	wildcards := []string{
		"*", "%", "_", ".",
		strings.Replace(path, "/users/1", "/users/*", -1),
		strings.Replace(path, "/users/1", "/users/%", -1),
		strings.Replace(path, "/users/1", "/users/_", -1),
		strings.Replace(path, "/users/1", "/users/.", -1),
	}

	for _, wildcard := range wildcards {
		resp, err := t.makeRequest(method, wildcard, nil)
		if err != nil {
			return err
		}
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			t.logger.Warnf("Wildcard character accepted: %s", wildcard)
		}
	}
	return nil
}

// testContentTypeManipulation tests content type manipulation
func (t *Tester) testContentTypeManipulation(path, method string) error {
	contentTypes := []string{
		"application/xml",
		"application/yaml",
		"text/plain",
		"text/html",
		"application/x-www-form-urlencoded",
		"multipart/form-data",
	}

	payload := `{"id":111}`

	for _, contentType := range contentTypes {
		headers := map[string]string{
			"Content-Type": contentType,
		}

		resp, err := t.makeRequestWithBody(method, path, headers, payload)
		if err != nil {
			return err
		}
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			t.logger.Warnf("Content-Type %s accepted with JSON payload", contentType)
		}
	}
	return nil
}

// testVersionParameters tests API version parameters
func (t *Tester) testVersionParameters(path, method string) error {
	versions := []string{
		"v1", "v2", "v3", "beta", "dev", "test",
		"api/v1", "api/v2", "api/v3",
		"mobile/v1", "mobile/v2",
		"web/v1", "web/v2",
	}

	for _, version := range versions {
		testPath := strings.Replace(path, "v1", version, 1)
		resp, err := t.makeRequest(method, testPath, nil)
		if err != nil {
			return err
		}
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			t.logger.Infof("API version %s accessible", version)
		}
	}
	return nil
}

// testEnvironmentDetection tests non-production environment detection
func (t *Tester) testEnvironmentDetection(path, method string) error {
	environments := []string{
		"dev", "development", "staging", "stage", "qa",
		"test", "testing", "uat", "prod-test", "beta",
	}

	for _, env := range environments {
		headers := map[string]string{
			"Host":             fmt.Sprintf("%s.example.com", env),
			"X-Forwarded-Host": fmt.Sprintf("%s.example.com", env),
		}

		resp, err := t.makeRequest(method, path, headers)
		if err != nil {
			return err
		}
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			t.logger.Warnf("Non-production environment detected: %s", env)
		}
	}
	return nil
}

// testExportInjection tests export functionality injection
func (t *Tester) testExportInjection(path, method string) error {
	exportPaths := []string{
		path + "?export=true",
		path + "?export=1",
		path + "?format=pdf",
		path + "?format=csv",
		path + "?download=true",
		path + "?file=export.pdf",
	}

	for _, testPath := range exportPaths {
		resp, err := t.makeRequest(method, testPath, nil)
		if err != nil {
			return err
		}
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			t.logger.Warnf("Export functionality detected: %s", testPath)
		}
	}
	return nil
}

// testAPIVersions tests different API versions
func (t *Tester) testAPIVersions(path, method string) error {
	versionTests := []struct {
		header string
		value  string
	}{
		{"Accept", "application/vnd.api+json;version=1.0"},
		{"Accept", "application/vnd.api+json;version=2.0"},
		{"X-API-Version", "1.0"},
		{"X-API-Version", "2.0"},
		{"Api-Version", "1"},
		{"Api-Version", "2"},
	}

	for _, test := range versionTests {
		headers := map[string]string{
			test.header: test.value,
		}

		resp, err := t.makeRequest(method, path, headers)
		if err != nil {
			return err
		}
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			t.logger.Infof("API version accessible via %s: %s", test.header, test.value)
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
