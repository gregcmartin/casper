package bola

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// Tester handles BOLA (Broken Object Level Authorization) testing
type Tester struct {
	logger     *logrus.Logger
	client     *http.Client
	baseURL    string
	headers    map[string]string
	userTokens map[string]string // Map of user IDs to their auth tokens
}

// New creates a new BOLA tester instance
func New(logger *logrus.Logger, client *http.Client, baseURL string) *Tester {
	// Set reasonable timeouts
	client.Timeout = 10 * time.Second

	return &Tester{
		logger:     logger,
		client:     client,
		baseURL:    strings.TrimRight(baseURL, "/"),
		headers:    make(map[string]string),
		userTokens: make(map[string]string),
	}
}

// SetHeader sets a custom header for all requests
func (t *Tester) SetHeader(key, value string) {
	t.headers[key] = value
}

// SetUserToken adds a user's authentication token for testing
func (t *Tester) SetUserToken(userID, token string) {
	t.userTokens[userID] = token
}

// RunTests performs BOLA testing against the API
func (t *Tester) RunTests(paths []string) error {
	t.logger.Info("Starting BOLA security tests")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	var wg sync.WaitGroup
	errChan := make(chan error, len(paths))

	// Test each path for BOLA vulnerabilities
	for _, path := range paths {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			if err := t.testPath(ctx, p); err != nil {
				if !strings.Contains(err.Error(), "no such host") {
					t.logger.Warnf("BOLA testing failed for path %s: %v", p, err)
					select {
					case errChan <- err:
					default:
					}
				}
			}
		}(path)
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

// testPath runs BOLA tests for a specific path
func (t *Tester) testPath(ctx context.Context, path string) error {
	// Skip paths without potential object identifiers
	if !t.hasObjectIdentifier(path) {
		return nil
	}

	tests := []struct {
		name string
		fn   func(context.Context, string) error
	}{
		{"Direct Object Reference", t.testDirectObjectReference},
		{"Mass Assignment", t.testMassAssignment},
		{"Horizontal Access", t.testHorizontalAccess},
		{"Vertical Access", t.testVerticalAccess},
		{"Reference Chaining", t.testReferenceChaining},
	}

	var wg sync.WaitGroup
	errChan := make(chan error, len(tests))

	for _, test := range tests {
		wg.Add(1)
		go func(tt struct {
			name string
			fn   func(context.Context, string) error
		}) {
			defer wg.Done()
			if err := tt.fn(ctx, path); err != nil {
				if !strings.Contains(err.Error(), "no such host") {
					t.logger.Warnf("%s test failed for path %s: %v", tt.name, path, err)
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

// hasObjectIdentifier checks if a path contains potential object identifiers
func (t *Tester) hasObjectIdentifier(path string) bool {
	patterns := []string{
		`/\d+`,           // Numeric IDs
		`/[a-f0-9]{24}`,  // MongoDB ObjectIDs
		`/[A-Za-z0-9-]+`, // UUIDs or similar
	}

	for _, pattern := range patterns {
		if matched, _ := regexp.MatchString(pattern, path); matched {
			return true
		}
	}
	return false
}

// testDirectObjectReference tests for direct object reference vulnerabilities
func (t *Tester) testDirectObjectReference(ctx context.Context, path string) error {
	var wg sync.WaitGroup
	errChan := make(chan error, len(t.userTokens))

	for userID, token := range t.userTokens {
		wg.Add(1)
		go func(uid, tok string) {
			defer wg.Done()

			select {
			case <-ctx.Done():
				errChan <- ctx.Err()
				return
			default:
				headers := map[string]string{
					"Authorization": fmt.Sprintf("Bearer %s", tok),
				}

				resp, err := t.makeRequest(ctx, "GET", path, headers, nil)
				if err != nil {
					if !strings.Contains(err.Error(), "no such host") {
						errChan <- err
					}
					return
				}
				defer resp.Body.Close()

				if resp.StatusCode == http.StatusOK {
					if !t.verifyObjectOwnership(path, uid) {
						errChan <- fmt.Errorf("BOLA: unauthorized access granted to %s for user %s", path, uid)
					}
				}
			}
		}(userID, token)
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

// testMassAssignment tests for mass assignment vulnerabilities
func (t *Tester) testMassAssignment(ctx context.Context, path string) error {
	sensitiveFields := []string{
		"role", "permissions", "isAdmin", "owner",
		"userId", "adminFlag", "privilegeLevel",
	}

	var wg sync.WaitGroup
	errChan := make(chan error, len(sensitiveFields)*len(t.userTokens))

	for _, field := range sensitiveFields {
		for _, token := range t.userTokens {
			wg.Add(1)
			go func(f, tok string) {
				defer wg.Done()

				select {
				case <-ctx.Done():
					errChan <- ctx.Err()
					return
				default:
					payload := map[string]interface{}{
						f: "admin",
					}

					headers := map[string]string{
						"Authorization": fmt.Sprintf("Bearer %s", tok),
					}

					resp, err := t.makeRequest(ctx, "PUT", path, headers, payload)
					if err != nil {
						if !strings.Contains(err.Error(), "no such host") {
							errChan <- err
						}
						return
					}
					defer resp.Body.Close()

					if resp.StatusCode == http.StatusOK {
						t.logger.Warnf("Potential mass assignment vulnerability: field '%s' was updated", f)
					}
				}
			}(field, token)
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

// testHorizontalAccess tests for horizontal privilege escalation
func (t *Tester) testHorizontalAccess(ctx context.Context, path string) error {
	var wg sync.WaitGroup
	errChan := make(chan error, len(t.userTokens))

	for userID, token := range t.userTokens {
		wg.Add(1)
		go func(uid, tok string) {
			defer wg.Done()

			select {
			case <-ctx.Done():
				errChan <- ctx.Err()
				return
			default:
				otherObjects, err := t.getOtherUserObjects(uid)
				if err != nil {
					errChan <- err
					return
				}

				for _, objPath := range otherObjects {
					headers := map[string]string{
						"Authorization": fmt.Sprintf("Bearer %s", tok),
					}

					resp, err := t.makeRequest(ctx, "GET", objPath, headers, nil)
					if err != nil {
						if !strings.Contains(err.Error(), "no such host") {
							errChan <- err
						}
						return
					}
					defer resp.Body.Close()

					if resp.StatusCode == http.StatusOK {
						t.logger.Warn("Horizontal privilege escalation detected")
					}
				}
			}
		}(userID, token)
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

// testVerticalAccess tests for vertical privilege escalation
func (t *Tester) testVerticalAccess(ctx context.Context, path string) error {
	adminPaths := []string{
		"/admin", "/manage", "/internal",
		"/users/all", "/system", "/config",
	}

	var wg sync.WaitGroup
	errChan := make(chan error, len(adminPaths)*len(t.userTokens))

	for _, adminPath := range adminPaths {
		if strings.Contains(path, adminPath) {
			for _, token := range t.userTokens {
				wg.Add(1)
				go func(ap, tok string) {
					defer wg.Done()

					select {
					case <-ctx.Done():
						errChan <- ctx.Err()
						return
					default:
						headers := map[string]string{
							"Authorization": fmt.Sprintf("Bearer %s", tok),
						}

						resp, err := t.makeRequest(ctx, "GET", path, headers, nil)
						if err != nil {
							if !strings.Contains(err.Error(), "no such host") {
								errChan <- err
							}
							return
						}
						defer resp.Body.Close()

						if resp.StatusCode == http.StatusOK {
							t.logger.Warn("Vertical privilege escalation detected")
						}
					}
				}(adminPath, token)
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

// testReferenceChaining tests for nested object reference vulnerabilities
func (t *Tester) testReferenceChaining(ctx context.Context, path string) error {
	relatedPaths := t.findRelatedPaths(path)

	var wg sync.WaitGroup
	errChan := make(chan error, len(relatedPaths)*len(t.userTokens))

	for _, relPath := range relatedPaths {
		for _, token := range t.userTokens {
			wg.Add(1)
			go func(rp, tok string) {
				defer wg.Done()

				select {
				case <-ctx.Done():
					errChan <- ctx.Err()
					return
				default:
					headers := map[string]string{
						"Authorization": fmt.Sprintf("Bearer %s", tok),
					}

					resp, err := t.makeRequest(ctx, "GET", rp, headers, nil)
					if err != nil {
						if !strings.Contains(err.Error(), "no such host") {
							errChan <- err
						}
						return
					}
					defer resp.Body.Close()

					if resp.StatusCode == http.StatusOK {
						if !t.verifyRelatedObjectAccess(path, rp) {
							t.logger.Warn("Reference chaining vulnerability detected")
						}
					}
				}
			}(relPath, token)
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

// Helper methods

func (t *Tester) makeRequest(ctx context.Context, method, path string, headers map[string]string, payload interface{}) (*http.Response, error) {
	var body io.Reader

	if payload != nil {
		jsonData, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = strings.NewReader(string(jsonData))
	}

	url := t.baseURL + path
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}

	// Add default headers
	for k, v := range t.headers {
		req.Header.Set(k, v)
	}

	// Add request-specific headers
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
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

func (t *Tester) verifyObjectOwnership(path, userID string) bool {
	// Implementation would check if the user owns or has rights to the object
	// This is a placeholder that should be implemented based on the API's
	// specific authorization model
	return false
}

func (t *Tester) getOtherUserObjects(userID string) ([]string, error) {
	// Implementation would discover objects owned by other users
	// This is a placeholder that should be implemented based on the API's
	// specific data model and discovery mechanisms
	return []string{}, nil
}

func (t *Tester) findRelatedPaths(path string) []string {
	// Implementation would find paths to related objects
	// This is a placeholder that should be implemented based on the API's
	// specific object relationships
	return []string{}
}

func (t *Tester) verifyRelatedObjectAccess(path, relatedPath string) bool {
	// Implementation would verify if access to related object is allowed
	// This is a placeholder that should be implemented based on the API's
	// specific authorization model
	return false
}
