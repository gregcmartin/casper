package parameter

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

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
	// Set reasonable timeouts
	client.Timeout = 10 * time.Second

	return &Tester{
		logger:  logger,
		client:  client,
		baseURL: baseURL,
	}
}

// RunTests performs parameter-based security tests against the API
func (t *Tester) RunTests(specPath string) error {
	t.logger.Info("Starting parameter-based security tests")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Load the specification
	doc, err := loads.Spec(specPath)
	if err != nil {
		return fmt.Errorf("failed to load spec file: %w", err)
	}

	swagger := doc.Spec()

	var wg sync.WaitGroup
	errChan := make(chan error, len(swagger.Paths.Paths)*7) // 7 is max number of operations per path

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
				wg.Add(1)
				go func(p, m string) {
					defer wg.Done()
					if err := t.TestParameterVulnerabilities(ctx, p, m); err != nil {
						if !strings.Contains(err.Error(), "no such host") {
							t.logger.Warnf("Parameter testing failed for %s %s: %v", m, p, err)
							select {
							case errChan <- err:
							default:
							}
						}
					}
				}(path, method)
			}
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
		return fmt.Errorf("multiple test failures: %v", errs)
	}
	return nil
}

// TestParameterVulnerabilities runs parameter-based security tests
func (t *Tester) TestParameterVulnerabilities(ctx context.Context, path string, method string) error {
	tests := []struct {
		name string
		fn   func(context.Context, string, string) error
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

	var wg sync.WaitGroup
	errChan := make(chan error, len(tests))

	for _, test := range tests {
		wg.Add(1)
		go func(tt struct {
			name string
			fn   func(context.Context, string, string) error
		}) {
			defer wg.Done()
			if err := tt.fn(ctx, path, method); err != nil {
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

// testGUIDBypass tests numeric ID substitution for GUID/UUID
func (t *Tester) testGUIDBypass(ctx context.Context, path, method string) error {
	numericPaths := []string{
		strings.Replace(path, "/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "/1", -1),
		strings.Replace(path, "/[0-9a-f]{32}", "/1", -1),
	}

	var wg sync.WaitGroup
	errChan := make(chan error, len(numericPaths))

	for _, testPath := range numericPaths {
		wg.Add(1)
		go func(tp string) {
			defer wg.Done()

			select {
			case <-ctx.Done():
				errChan <- ctx.Err()
				return
			default:
				resp, err := t.makeRequest(ctx, method, tp, nil)
				if err != nil {
					if !strings.Contains(err.Error(), "no such host") {
						errChan <- err
					}
					return
				}
				resp.Body.Close()

				if resp.StatusCode == http.StatusOK {
					t.logger.Warnf("GUID/UUID bypass possible with numeric ID: %s", tp)
				}
			}
		}(testPath)
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
		return fmt.Errorf("multiple GUID bypass test failures: %v", errs)
	}
	return nil
}

// testArrayWrapping tests array wrapping vulnerabilities
func (t *Tester) testArrayWrapping(ctx context.Context, path, method string) error {
	payloads := []string{
		`{"id":111}`,
		`{"id":[111]}`,
		`{"id":["111"]}`,
		`[{"id":111}]`,
	}

	var wg sync.WaitGroup
	errChan := make(chan error, len(payloads))

	for _, payload := range payloads {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()

			select {
			case <-ctx.Done():
				errChan <- ctx.Err()
				return
			default:
				headers := map[string]string{
					"Content-Type": "application/json",
				}

				resp, err := t.makeRequestWithBody(ctx, method, path, headers, p)
				if err != nil {
					if !strings.Contains(err.Error(), "no such host") {
						errChan <- err
					}
					return
				}
				resp.Body.Close()

				if resp.StatusCode == http.StatusOK {
					t.logger.Warnf("Array wrapping accepted: %s", p)
				}
			}
		}(payload)
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
		return fmt.Errorf("multiple array wrapping test failures: %v", errs)
	}
	return nil
}

// testJSONObjectWrapping tests JSON object wrapping vulnerabilities
func (t *Tester) testJSONObjectWrapping(ctx context.Context, path, method string) error {
	payloads := []string{
		`{"id":111}`,
		`{"id":{"id":111}}`,
		`{"data":{"id":111}}`,
		`{"id":{"data":{"id":111}}}`,
	}

	var wg sync.WaitGroup
	errChan := make(chan error, len(payloads))

	for _, payload := range payloads {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()

			select {
			case <-ctx.Done():
				errChan <- ctx.Err()
				return
			default:
				headers := map[string]string{
					"Content-Type": "application/json",
				}

				resp, err := t.makeRequestWithBody(ctx, method, path, headers, p)
				if err != nil {
					if !strings.Contains(err.Error(), "no such host") {
						errChan <- err
					}
					return
				}
				resp.Body.Close()

				if resp.StatusCode == http.StatusOK {
					t.logger.Warnf("JSON object wrapping accepted: %s", p)
				}
			}
		}(payload)
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
		return fmt.Errorf("multiple JSON object wrapping test failures: %v", errs)
	}
	return nil
}

// testParameterPollution tests HTTP parameter pollution
func (t *Tester) testParameterPollution(ctx context.Context, path, method string) error {
	pollutedPaths := []string{
		path + "?id=legit&id=victim",
		path + "?id=victim&id=legit",
		path + "?id[]=legit&id[]=victim",
		path + "?user_id=legit&user_id=victim",
		path + "?user_id[]=legit&user_id[]=victim",
	}

	var wg sync.WaitGroup
	errChan := make(chan error, len(pollutedPaths))

	for _, testPath := range pollutedPaths {
		wg.Add(1)
		go func(tp string) {
			defer wg.Done()

			select {
			case <-ctx.Done():
				errChan <- ctx.Err()
				return
			default:
				resp, err := t.makeRequest(ctx, method, tp, nil)
				if err != nil {
					if !strings.Contains(err.Error(), "no such host") {
						errChan <- err
					}
					return
				}
				resp.Body.Close()

				if resp.StatusCode == http.StatusOK {
					t.logger.Warnf("Parameter pollution possible: %s", tp)
				}
			}
		}(testPath)
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
		return fmt.Errorf("multiple parameter pollution test failures: %v", errs)
	}
	return nil
}

// testJSONParameterPollution tests JSON parameter pollution
func (t *Tester) testJSONParameterPollution(ctx context.Context, path, method string) error {
	payloads := []string{
		`{"user_id":"legit","user_id":"victim"}`,
		`{"user_id":["legit","victim"]}`,
		`{"user_id":{"legit":"victim"}}`,
		`{"data":{"user_id":"legit"},"user_id":"victim"}`,
	}

	var wg sync.WaitGroup
	errChan := make(chan error, len(payloads))

	for _, payload := range payloads {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()

			select {
			case <-ctx.Done():
				errChan <- ctx.Err()
				return
			default:
				headers := map[string]string{
					"Content-Type": "application/json",
				}

				resp, err := t.makeRequestWithBody(ctx, method, path, headers, p)
				if err != nil {
					if !strings.Contains(err.Error(), "no such host") {
						errChan <- err
					}
					return
				}
				resp.Body.Close()

				if resp.StatusCode == http.StatusOK {
					t.logger.Warnf("JSON parameter pollution possible: %s", p)
				}
			}
		}(payload)
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
		return fmt.Errorf("multiple JSON parameter pollution test failures: %v", errs)
	}
	return nil
}

// testWildcards tests wildcard character handling
func (t *Tester) testWildcards(ctx context.Context, path, method string) error {
	wildcards := []string{
		"*", "%", "_", ".",
		strings.Replace(path, "/users/1", "/users/*", -1),
		strings.Replace(path, "/users/1", "/users/%", -1),
		strings.Replace(path, "/users/1", "/users/_", -1),
		strings.Replace(path, "/users/1", "/users/.", -1),
	}

	var wg sync.WaitGroup
	errChan := make(chan error, len(wildcards))

	for _, wildcard := range wildcards {
		wg.Add(1)
		go func(w string) {
			defer wg.Done()

			select {
			case <-ctx.Done():
				errChan <- ctx.Err()
				return
			default:
				resp, err := t.makeRequest(ctx, method, w, nil)
				if err != nil {
					if !strings.Contains(err.Error(), "no such host") {
						errChan <- err
					}
					return
				}
				resp.Body.Close()

				if resp.StatusCode == http.StatusOK {
					t.logger.Warnf("Wildcard character accepted: %s", w)
				}
			}
		}(wildcard)
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
		return fmt.Errorf("multiple wildcard test failures: %v", errs)
	}
	return nil
}

// testContentTypeManipulation tests content type manipulation
func (t *Tester) testContentTypeManipulation(ctx context.Context, path, method string) error {
	contentTypes := []string{
		"application/xml",
		"application/yaml",
		"text/plain",
		"text/html",
		"application/x-www-form-urlencoded",
		"multipart/form-data",
	}

	payload := `{"id":111}`

	var wg sync.WaitGroup
	errChan := make(chan error, len(contentTypes))

	for _, contentType := range contentTypes {
		wg.Add(1)
		go func(ct string) {
			defer wg.Done()

			select {
			case <-ctx.Done():
				errChan <- ctx.Err()
				return
			default:
				headers := map[string]string{
					"Content-Type": ct,
				}

				resp, err := t.makeRequestWithBody(ctx, method, path, headers, payload)
				if err != nil {
					if !strings.Contains(err.Error(), "no such host") {
						errChan <- err
					}
					return
				}
				resp.Body.Close()

				if resp.StatusCode == http.StatusOK {
					t.logger.Warnf("Content-Type %s accepted with JSON payload", ct)
				}
			}
		}(contentType)
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
		return fmt.Errorf("multiple content type manipulation test failures: %v", errs)
	}
	return nil
}

// testVersionParameters tests API version parameters
func (t *Tester) testVersionParameters(ctx context.Context, path, method string) error {
	versions := []string{
		"v1", "v2", "v3", "beta", "dev", "test",
		"api/v1", "api/v2", "api/v3",
		"mobile/v1", "mobile/v2",
		"web/v1", "web/v2",
	}

	var wg sync.WaitGroup
	errChan := make(chan error, len(versions))

	for _, version := range versions {
		wg.Add(1)
		go func(v string) {
			defer wg.Done()

			select {
			case <-ctx.Done():
				errChan <- ctx.Err()
				return
			default:
				testPath := strings.Replace(path, "v1", v, 1)
				resp, err := t.makeRequest(ctx, method, testPath, nil)
				if err != nil {
					if !strings.Contains(err.Error(), "no such host") {
						errChan <- err
					}
					return
				}
				resp.Body.Close()

				if resp.StatusCode == http.StatusOK {
					t.logger.Infof("API version %s accessible", v)
				}
			}
		}(version)
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
		return fmt.Errorf("multiple version parameter test failures: %v", errs)
	}
	return nil
}

// testEnvironmentDetection tests non-production environment detection
func (t *Tester) testEnvironmentDetection(ctx context.Context, path, method string) error {
	environments := []string{
		"dev", "development", "staging", "stage", "qa",
		"test", "testing", "uat", "prod-test", "beta",
	}

	var wg sync.WaitGroup
	errChan := make(chan error, len(environments))

	for _, env := range environments {
		wg.Add(1)
		go func(e string) {
			defer wg.Done()

			select {
			case <-ctx.Done():
				errChan <- ctx.Err()
				return
			default:
				headers := map[string]string{
					"Host":             fmt.Sprintf("%s.example.com", e),
					"X-Forwarded-Host": fmt.Sprintf("%s.example.com", e),
				}

				resp, err := t.makeRequest(ctx, method, path, headers)
				if err != nil {
					if !strings.Contains(err.Error(), "no such host") {
						errChan <- err
					}
					return
				}
				resp.Body.Close()

				if resp.StatusCode == http.StatusOK {
					t.logger.Warnf("Non-production environment detected: %s", e)
				}
			}
		}(env)
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
		return fmt.Errorf("multiple environment detection test failures: %v", errs)
	}
	return nil
}

// testExportInjection tests export functionality injection
func (t *Tester) testExportInjection(ctx context.Context, path, method string) error {
	exportPaths := []string{
		path + "?export=true",
		path + "?export=1",
		path + "?format=pdf",
		path + "?format=csv",
		path + "?download=true",
		path + "?file=export.pdf",
	}

	var wg sync.WaitGroup
	errChan := make(chan error, len(exportPaths))

	for _, testPath := range exportPaths {
		wg.Add(1)
		go func(tp string) {
			defer wg.Done()

			select {
			case <-ctx.Done():
				errChan <- ctx.Err()
				return
			default:
				resp, err := t.makeRequest(ctx, method, tp, nil)
				if err != nil {
					if !strings.Contains(err.Error(), "no such host") {
						errChan <- err
					}
					return
				}
				resp.Body.Close()

				if resp.StatusCode == http.StatusOK {
					t.logger.Warnf("Export functionality detected: %s", tp)
				}
			}
		}(testPath)
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
		return fmt.Errorf("multiple export injection test failures: %v", errs)
	}
	return nil
}

// testAPIVersions tests different API versions
func (t *Tester) testAPIVersions(ctx context.Context, path, method string) error {
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

	var wg sync.WaitGroup
	errChan := make(chan error, len(versionTests))

	for _, test := range versionTests {
		wg.Add(1)
		go func(tt struct {
			header string
			value  string
		}) {
			defer wg.Done()

			select {
			case <-ctx.Done():
				errChan <- ctx.Err()
				return
			default:
				headers := map[string]string{
					tt.header: tt.value,
				}

				resp, err := t.makeRequest(ctx, method, path, headers)
				if err != nil {
					if !strings.Contains(err.Error(), "no such host") {
						errChan <- err
					}
					return
				}
				resp.Body.Close()

				if resp.StatusCode == http.StatusOK {
					t.logger.Infof("API version accessible via %s: %s", tt.header, tt.value)
				}
			}
		}(test)
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
		return fmt.Errorf("multiple API version test failures: %v", errs)
	}
	return nil
}

// makeRequest performs an HTTP request
func (t *Tester) makeRequest(ctx context.Context, method, path string, headers map[string]string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, t.baseURL+path, nil)
	if err != nil {
		return nil, err
	}

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

// makeRequestWithBody performs an HTTP request with a body
func (t *Tester) makeRequestWithBody(ctx context.Context, method, path string, headers map[string]string, body string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, t.baseURL+path, strings.NewReader(body))
	if err != nil {
		return nil, err
	}

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
