package bola

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

// Tester handles BOLA (Broken Object Level Authorization) testing
type Tester struct {
	logger  *logrus.Logger
	client  *http.Client
	baseURL string
	headers map[string]string
	tokens  map[string]string // userID -> token mapping
}

// New creates a new BOLA tester instance
func New(logger *logrus.Logger, client *http.Client, baseURL string) *Tester {
	return &Tester{
		logger:  logger,
		client:  client,
		baseURL: strings.TrimSuffix(baseURL, "/"),
		headers: make(map[string]string),
		tokens:  make(map[string]string),
	}
}

// SetHeader sets a custom header for all requests
func (t *Tester) SetHeader(key, value string) {
	t.headers[key] = value
}

// SetUserToken sets a user token for testing
func (t *Tester) SetUserToken(userID, token string) {
	t.tokens[userID] = token
}

// RunTests performs BOLA tests against specified paths
func (t *Tester) RunTests(paths []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Test specific endpoints that might be vulnerable to BOLA
	endpoints := []string{
		"/users/v1/{username}",
		"/books/v1/{book_title}",
		"/me",
		"/users/v1/{username}/email",
		"/users/v1/{username}/password",
	}

	// Add any path that contains an ID or username parameter
	for _, p := range paths {
		if strings.Contains(p, "{") && strings.Contains(p, "}") {
			endpoints = append(endpoints, p)
		}
	}

	// Test each endpoint
	for _, endpoint := range endpoints {
		if err := t.testEndpoint(ctx, endpoint); err != nil {
			t.logger.Warnf("BOLA testing failed for endpoint %s: %v", endpoint, err)
		}
	}

	return nil
}

// testEndpoint tests a specific endpoint for BOLA vulnerabilities
func (t *Tester) testEndpoint(ctx context.Context, endpoint string) error {
	// Test cases for BOLA
	tests := []struct {
		name        string
		method      string
		paramValues []string
		userTokens  []string
	}{
		{
			name:        "User Data Access",
			method:      "GET",
			paramValues: []string{"name1", "name2", "admin"},
			userTokens:  []string{"user1token", "user2token"},
		},
		{
			name:        "Book Access",
			method:      "GET",
			paramValues: []string{"book1", "book2", "adminbook"},
			userTokens:  []string{"user1token", "user2token"},
		},
		{
			name:        "Email Update",
			method:      "PUT",
			paramValues: []string{"name1", "name2", "admin"},
			userTokens:  []string{"user1token", "user2token"},
		},
		{
			name:        "Password Update",
			method:      "PUT",
			paramValues: []string{"name1", "name2", "admin"},
			userTokens:  []string{"user1token", "user2token"},
		},
	}

	for _, test := range tests {
		// Try accessing with different user tokens
		for _, token := range test.userTokens {
			for _, value := range test.paramValues {
				// Replace path parameters
				finalEndpoint := strings.ReplaceAll(endpoint, "{username}", value)
				finalEndpoint = strings.ReplaceAll(finalEndpoint, "{book_title}", value)

				// Set auth header
				headers := map[string]string{
					"Authorization": fmt.Sprintf("Bearer %s", token),
				}

				// Make request
				resp, err := t.makeRequest(ctx, test.method, finalEndpoint, headers, nil)
				if err != nil {
					continue
				}
				resp.Body.Close()

				// Check for potential BOLA
				if resp.StatusCode == http.StatusOK {
					t.logger.Warnf("Potential BOLA vulnerability: %s endpoint allows access with different user token", finalEndpoint)
				}
			}
		}

		// Try accessing without authentication
		resp, err := t.makeRequest(ctx, test.method, endpoint, nil, nil)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			t.logger.Warnf("Potential BOLA vulnerability: %s endpoint accessible without authentication", endpoint)
		}

		// Try with invalid tokens
		invalidTokens := []string{
			"invalid-token",
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			"",
		}

		for _, token := range invalidTokens {
			headers := map[string]string{
				"Authorization": fmt.Sprintf("Bearer %s", token),
			}

			resp, err := t.makeRequest(ctx, test.method, endpoint, headers, nil)
			if err != nil {
				continue
			}
			resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				t.logger.Warnf("Potential BOLA vulnerability: %s endpoint accessible with invalid token", endpoint)
			}
		}
	}

	return nil
}

// makeRequest makes an HTTP request with the specified parameters
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
