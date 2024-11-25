package security

import (
	"crypto/tls"
	"net/http"
	"strings"
	"time"

	"github.com/gregcmartin/casper/internal/security/bola"
	"github.com/gregcmartin/casper/internal/security/core"
	"github.com/gregcmartin/casper/internal/security/export"
	"github.com/gregcmartin/casper/internal/security/graphql"
	"github.com/gregcmartin/casper/internal/security/parameter"
	"github.com/gregcmartin/casper/internal/security/static"
	"github.com/gregcmartin/casper/internal/security/vuln"
	"github.com/sirupsen/logrus"
)

// Tester is the main security testing orchestrator
type Tester struct {
	logger        *logrus.Logger
	coreTester    *core.Tester
	paramTester   *parameter.Tester
	graphqlTester *graphql.Tester
	staticTester  *static.Tester
	exportTester  *export.Tester
	bolaTester    *bola.Tester
	vulnTester    *vuln.Tester
}

// New creates a new security tester instance
func New(logger *logrus.Logger, baseURL string) *Tester {
	// Create a custom transport to check TLS configuration
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}

	baseURL = strings.TrimRight(baseURL, "/")

	return &Tester{
		logger:        logger,
		coreTester:    core.New(logger, client, baseURL),
		paramTester:   parameter.New(logger, client, baseURL),
		graphqlTester: graphql.New(logger, client, baseURL),
		staticTester:  static.New(logger, client, baseURL),
		exportTester:  export.New(logger, client, baseURL),
		bolaTester:    bola.New(logger, client, baseURL),
		vulnTester:    vuln.New(logger, client, baseURL),
	}
}

// RunTests performs all security tests against the API
func (t *Tester) RunTests(specPath string) error {
	t.logger.Info("Starting comprehensive security tests")

	// Extract paths from spec for specialized tests
	paths, err := t.extractPaths(specPath)
	if err != nil {
		return err
	}

	// Run core security tests
	if err := t.coreTester.RunTests(specPath); err != nil {
		return err
	}

	// Run parameter-based security tests
	if err := t.paramTester.RunTests(specPath); err != nil {
		return err
	}

	// Run comprehensive vulnerability tests
	if err := t.vulnTester.RunTests(paths); err != nil {
		t.logger.Warn("Vulnerability testing failed:", err)
	}

	// Run BOLA security tests
	if err := t.bolaTester.RunTests(paths); err != nil {
		t.logger.Warn("BOLA testing failed:", err)
	}

	// Run GraphQL security tests if GraphQL endpoints are detected
	for _, path := range paths {
		if strings.Contains(path, "graphql") {
			if err := t.graphqlTester.RunTests(path); err != nil {
				t.logger.Warnf("GraphQL testing failed for path %s: %v", path, err)
			}
		}
	}

	// Run static resource security tests
	staticPaths := t.filterStaticPaths(paths)
	if len(staticPaths) > 0 {
		if err := t.staticTester.RunTests(staticPaths); err != nil {
			t.logger.Warn("Static resource testing failed:", err)
		}
	}

	// Run export functionality security tests
	exportPaths := t.filterExportPaths(paths)
	if len(exportPaths) > 0 {
		if err := t.exportTester.RunTests(exportPaths); err != nil {
			t.logger.Warn("Export functionality testing failed:", err)
		}
	}

	return nil
}

// SetHeader sets a custom header for all requests
func (t *Tester) SetHeader(key, value string) {
	// Only set headers for testers that support it
	t.coreTester.SetHeader(key, value)
	t.bolaTester.SetHeader(key, value)
	t.vulnTester.SetHeader(key, value)
}

// SetUserToken sets a user token for BOLA testing
func (t *Tester) SetUserToken(userID, token string) {
	t.bolaTester.SetUserToken(userID, token)
}

// extractPaths extracts all paths from the OpenAPI spec
func (t *Tester) extractPaths(specPath string) ([]string, error) {
	// This would be implemented to parse the OpenAPI spec and extract paths
	// For now, return a placeholder implementation
	return []string{
		"/api/v1/users",
		"/api/v1/users/{id}",
		"/api/v1/auth/login",
		"/api/v1/auth/register",
		"/api/v1/password/reset",
		"/api/v1/graphql",
		"/api/v1/files",
		"/api/v1/export",
		"/api/v1/debug",
	}, nil
}

// filterStaticPaths filters paths that might serve static resources
func (t *Tester) filterStaticPaths(paths []string) []string {
	var staticPaths []string
	staticPatterns := []string{
		"files", "images", "documents",
		"download", "uploads", "media",
		"static", "assets", "resources",
	}

	for _, path := range paths {
		for _, pattern := range staticPatterns {
			if strings.Contains(strings.ToLower(path), pattern) {
				staticPaths = append(staticPaths, path)
				break
			}
		}
	}

	return staticPaths
}

// filterExportPaths filters paths that might have export functionality
func (t *Tester) filterExportPaths(paths []string) []string {
	var exportPaths []string
	exportPatterns := []string{
		"export", "download", "report",
		"pdf", "csv", "excel",
		"generate", "print",
	}

	for _, path := range paths {
		for _, pattern := range exportPatterns {
			if strings.Contains(strings.ToLower(path), pattern) {
				exportPaths = append(exportPaths, path)
				break
			}
		}
	}

	return exportPaths
}
