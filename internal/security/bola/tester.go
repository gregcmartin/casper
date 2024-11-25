package bola

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"

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

	// Test each path for BOLA vulnerabilities
	for _, path := range paths {
		if err := t.testPath(path); err != nil {
			t.logger.Warnf("BOLA testing failed for path %s: %v", path, err)
		}
	}

	return nil
}

// testPath runs BOLA tests for a specific path
func (t *Tester) testPath(path string) error {
	// Skip paths without potential object identifiers
	if !t.hasObjectIdentifier(path) {
		return nil
	}

	tests := []struct {
		name string
		fn   func(string) error
	}{
		{"Direct Object Reference", t.testDirectObjectReference},
		{"Mass Assignment", t.testMassAssignment},
		{"Horizontal Access", t.testHorizontalAccess},
		{"Vertical Access", t.testVerticalAccess},
		{"Reference Chaining", t.testReferenceChaining},
	}

	for _, test := range tests {
		if err := test.fn(path); err != nil {
			t.logger.Warnf("%s test failed for path %s: %v", test.name, path, err)
		}
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
func (t *Tester) testDirectObjectReference(path string) error {
	// Test accessing objects with different user tokens
	var wg sync.WaitGroup
	results := make(chan error, len(t.userTokens))

	for userID, token := range t.userTokens {
		wg.Add(1)
		go func(uid, tok string) {
			defer wg.Done()

			// Try to access the object with this user's token
			headers := map[string]string{
				"Authorization": fmt.Sprintf("Bearer %s", tok),
			}

			resp, err := t.makeRequest("GET", path, headers, nil)
			if err != nil {
				results <- err
				return
			}
			defer resp.Body.Close()

			// Check if access was incorrectly granted
			if resp.StatusCode == http.StatusOK {
				// Verify if this user should have access to this object
				if !t.verifyObjectOwnership(path, uid) {
					results <- fmt.Errorf("BOLA: unauthorized access granted to %s for user %s", path, uid)
				}
			}
		}(userID, token)
	}

	// Wait for all tests to complete
	wg.Wait()
	close(results)

	// Check for any errors
	for err := range results {
		if err != nil {
			return err
		}
	}

	return nil
}

// testMassAssignment tests for mass assignment vulnerabilities
func (t *Tester) testMassAssignment(path string) error {
	// Test updating objects with additional fields
	sensitiveFields := []string{
		"role", "permissions", "isAdmin", "owner",
		"userId", "adminFlag", "privilegeLevel",
	}

	for _, field := range sensitiveFields {
		payload := map[string]interface{}{
			field: "admin", // Attempt privilege escalation
		}

		for _, token := range t.userTokens {
			headers := map[string]string{
				"Authorization": fmt.Sprintf("Bearer %s", token),
			}

			resp, err := t.makeRequest("PUT", path, headers, payload)
			if err != nil {
				return err
			}
			defer resp.Body.Close()

			// Check if the update was successful
			if resp.StatusCode == http.StatusOK {
				t.logger.Warnf("Potential mass assignment vulnerability: field '%s' was updated", field)
			}
		}
	}

	return nil
}

// testHorizontalAccess tests for horizontal privilege escalation
func (t *Tester) testHorizontalAccess(path string) error {
	// Test accessing objects owned by other users at the same privilege level
	for userID, token := range t.userTokens {
		// Get objects owned by other users
		otherObjects, err := t.getOtherUserObjects(userID)
		if err != nil {
			return err
		}

		for _, objPath := range otherObjects {
			headers := map[string]string{
				"Authorization": fmt.Sprintf("Bearer %s", token),
			}

			resp, err := t.makeRequest("GET", objPath, headers, nil)
			if err != nil {
				return err
			}
			defer resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				t.logger.Warn("Horizontal privilege escalation detected")
			}
		}
	}

	return nil
}

// testVerticalAccess tests for vertical privilege escalation
func (t *Tester) testVerticalAccess(path string) error {
	// Test accessing admin-only endpoints with regular user tokens
	adminPaths := []string{
		"/admin", "/manage", "/internal",
		"/users/all", "/system", "/config",
	}

	for _, adminPath := range adminPaths {
		if strings.Contains(path, adminPath) {
			for _, token := range t.userTokens {
				headers := map[string]string{
					"Authorization": fmt.Sprintf("Bearer %s", token),
				}

				resp, err := t.makeRequest("GET", path, headers, nil)
				if err != nil {
					return err
				}
				defer resp.Body.Close()

				if resp.StatusCode == http.StatusOK {
					t.logger.Warn("Vertical privilege escalation detected")
				}
			}
		}
	}

	return nil
}

// testReferenceChaining tests for nested object reference vulnerabilities
func (t *Tester) testReferenceChaining(path string) error {
	// Test accessing objects through related object references
	relatedPaths := t.findRelatedPaths(path)

	for _, relPath := range relatedPaths {
		for _, token := range t.userTokens {
			headers := map[string]string{
				"Authorization": fmt.Sprintf("Bearer %s", token),
			}

			resp, err := t.makeRequest("GET", relPath, headers, nil)
			if err != nil {
				return err
			}
			defer resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				// Check if access to related object should be allowed
				if !t.verifyRelatedObjectAccess(path, relPath) {
					t.logger.Warn("Reference chaining vulnerability detected")
				}
			}
		}
	}

	return nil
}

// Helper methods

func (t *Tester) makeRequest(method, path string, headers map[string]string, payload interface{}) (*http.Response, error) {
	var body io.Reader

	if payload != nil {
		jsonData, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = strings.NewReader(string(jsonData))
	}

	url := t.baseURL + path
	req, err := http.NewRequest(method, url, body)
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

	return t.client.Do(req)
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
