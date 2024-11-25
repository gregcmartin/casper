package business

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-openapi/loads"
	"github.com/go-openapi/spec"
	"github.com/sirupsen/logrus"
)

// BusinessTester handles API business logic testing
type BusinessTester struct {
	logger  *logrus.Logger
	client  *http.Client
	baseURL string
	headers map[string]string
}

// New creates a new business logic tester instance
func New(logger *logrus.Logger, baseURL string) *BusinessTester {
	return &BusinessTester{
		logger:  logger,
		client:  &http.Client{Timeout: 30 * time.Second},
		baseURL: strings.TrimRight(baseURL, "/"),
		headers: make(map[string]string),
	}
}

// RunTests performs business logic tests against the API
func (t *BusinessTester) RunTests(specPath string) error {
	t.logger.Info("Starting business logic tests")

	// Load the specification
	doc, err := loads.Spec(specPath)
	if err != nil {
		return fmt.Errorf("failed to load spec file: %w", err)
	}

	swagger := doc.Spec()

	// Test each endpoint
	for path, pathItem := range swagger.Paths.Paths {
		if err := t.testPath(path, pathItem); err != nil {
			return fmt.Errorf("failed testing path %s: %w", path, err)
		}
	}

	return nil
}

// testPath runs business logic tests for a specific path
func (t *BusinessTester) testPath(path string, pathItem spec.PathItem) error {
	operations := map[string]*spec.Operation{
		"GET":     pathItem.Get,
		"POST":    pathItem.Post,
		"PUT":     pathItem.Put,
		"DELETE":  pathItem.Delete,
		"PATCH":   pathItem.Patch,
		"HEAD":    pathItem.Head,
		"OPTIONS": pathItem.Options,
	}

	for method, op := range operations {
		if op != nil {
			if err := t.testOperation(method, path, op); err != nil {
				return err
			}
		}
	}

	return nil
}

// testOperation runs business logic tests for a specific operation
func (t *BusinessTester) testOperation(method, path string, op *spec.Operation) error {
	t.logger.Infof("Testing business logic for %s %s", method, path)

	tests := []struct {
		name string
		fn   func(string, string, *spec.Operation) error
	}{
		{"Resource Dependencies", t.testResourceDependencies},
		{"State Transitions", t.testStateTransitions},
		{"Data Consistency", t.testDataConsistency},
		{"Access Control", t.testAccessControl},
	}

	for _, test := range tests {
		if err := test.fn(method, path, op); err != nil {
			t.logger.Warnf("%s test failed for %s %s: %v", test.name, method, path, err)
		}
	}

	return nil
}

// testResourceDependencies checks for proper handling of resource dependencies
func (t *BusinessTester) testResourceDependencies(method, path string, op *spec.Operation) error {
	// Test creation/deletion order of dependent resources
	if strings.Contains(path, "/") {
		// Try to access child resource without parent
		resp, err := t.makeRequest(method, path, nil)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusNotFound {
			t.logger.Warn("Child resource accessible without parent")
		}
	}
	return nil
}

// testStateTransitions verifies valid state transitions
func (t *BusinessTester) testStateTransitions(method, path string, op *spec.Operation) error {
	if method == "PUT" || method == "PATCH" {
		// Check for state transition validation
		invalidStates := []string{"invalid_state", "unknown", "undefined"}
		for _, state := range invalidStates {
			headers := map[string]string{
				"X-State-Transition": state,
			}
			resp, err := t.makeRequest(method, path, headers)
			if err != nil {
				return err
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusBadRequest {
				t.logger.Warn("Invalid state transition not properly handled")
			}
		}
	}
	return nil
}

// testDataConsistency checks for data consistency across operations
func (t *BusinessTester) testDataConsistency(method, path string, op *spec.Operation) error {
	if method == "POST" || method == "PUT" {
		// Test idempotency
		resp1, err := t.makeRequest(method, path, nil)
		if err != nil {
			return err
		}
		resp1.Body.Close()

		resp2, err := t.makeRequest(method, path, nil)
		if err != nil {
			return err
		}
		resp2.Body.Close()

		if method == "POST" && resp2.StatusCode != http.StatusConflict {
			t.logger.Warn("POST operation might not be properly handling duplicates")
		}
		if method == "PUT" && resp2.StatusCode != resp1.StatusCode {
			t.logger.Warn("PUT operation might not be idempotent")
		}
	}
	return nil
}

// testAccessControl verifies proper access control implementation
func (t *BusinessTester) testAccessControl(method, path string, op *spec.Operation) error {
	// Test role-based access
	roles := []string{"user", "admin", "guest", ""}
	for _, role := range roles {
		headers := map[string]string{
			"X-Role": role,
		}
		resp, err := t.makeRequest(method, path, headers)
		if err != nil {
			return err
		}
		resp.Body.Close()

		// Check if access control is implemented
		if role == "" && resp.StatusCode != http.StatusUnauthorized {
			t.logger.Warn("Endpoint accessible without role")
		}
	}
	return nil
}

// makeRequest performs an HTTP request
func (t *BusinessTester) makeRequest(method, path string, additionalHeaders map[string]string) (*http.Response, error) {
	url := t.baseURL + path
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}

	// Add default headers
	for k, v := range t.headers {
		req.Header.Set(k, v)
	}

	// Add additional headers
	for k, v := range additionalHeaders {
		req.Header.Set(k, v)
	}

	return t.client.Do(req)
}
