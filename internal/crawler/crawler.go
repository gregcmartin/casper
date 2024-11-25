package crawler

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/sirupsen/logrus"
)

// Options configures crawler behavior
type Options struct {
	SkipValidation bool
	SkipURLEncode  bool
	RawOutput      bool
}

// Crawler handles API discovery
type Crawler struct {
	logger  *logrus.Logger
	client  *http.Client
	options Options
}

// DiscoveryResult contains API discovery findings
type DiscoveryResult struct {
	BaseURL           string
	SpecURLs          []string
	APIEndpoints      []string
	SwaggerUI         []string
	DocumentationURLs []string
	Headers           map[string][]string
}

// New creates a new crawler instance
func New(logger *logrus.Logger) *Crawler {
	// Create HTTP client with TLS verification disabled
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	return &Crawler{
		logger: logger,
		client: client,
		options: Options{
			SkipValidation: false,
			SkipURLEncode:  false,
			RawOutput:      false,
		},
	}
}

// SetOptions configures crawler options
func (c *Crawler) SetOptions(opts Options) {
	c.options = opts
}

// DiscoverAPIs discovers API specifications and endpoints
func (c *Crawler) DiscoverAPIs(domain string) (*DiscoveryResult, error) {
	// Normalize domain to URL
	if !strings.HasPrefix(domain, "http://") && !strings.HasPrefix(domain, "https://") {
		domain = "https://" + domain
	}

	baseURL, err := url.Parse(domain)
	if err != nil {
		return nil, fmt.Errorf("invalid domain: %w", err)
	}

	c.logger.Infof("Starting API discovery for domain: %s", baseURL.Host)

	result := &DiscoveryResult{
		BaseURL: baseURL.String(),
		Headers: make(map[string][]string),
	}

	// Check server headers
	c.logger.Info("Checking server headers...")
	if err := c.checkHeaders(result); err != nil {
		c.logger.Warnf("Header check failed: %v", err)
	}

	// Check for API documentation interfaces
	c.logger.Info("Checking for API documentation interfaces...")
	if err := c.checkDocInterfaces(result); err != nil {
		c.logger.Warnf("Documentation interface check failed: %v", err)
	}

	// Check common API specification locations
	c.logger.Info("Checking common API specification locations...")
	if err := c.checkSpecLocations(result); err != nil {
		c.logger.Warnf("Specification location check failed: %v", err)
	}

	// Discover API endpoints
	c.logger.Info("Discovering API endpoints...")
	if err := c.discoverEndpoints(result); err != nil {
		c.logger.Warnf("Endpoint discovery failed: %v", err)
	}

	c.logger.Infof("Discovery completed. Found %d spec(s) %d API endpoint(s) %d Swagger UI(s) and %d documentation URL(s)",
		len(result.SpecURLs), len(result.APIEndpoints), len(result.SwaggerUI), len(result.DocumentationURLs))

	if len(result.SpecURLs) > 0 {
		c.logger.Info("Found API specifications:")
		for _, url := range result.SpecURLs {
			c.logger.Info("- " + url)
		}
	}

	return result, nil
}

// checkHeaders checks server headers for API information
func (c *Crawler) checkHeaders(result *DiscoveryResult) error {
	resp, err := c.client.Get(result.BaseURL)
	if err != nil {
		return fmt.Errorf("failed to get headers: %w", err)
	}
	defer resp.Body.Close()

	// Store interesting headers
	for _, header := range []string{
		"Server",
		"X-Powered-By",
		"Access-Control-Allow-Origin",
		"Access-Control-Allow-Methods",
		"Access-Control-Allow-Headers",
		"API-Version",
		"X-API-Version",
	} {
		if values := resp.Header[header]; len(values) > 0 {
			result.Headers[header] = values
		}
	}

	return nil
}

// checkDocInterfaces checks for common API documentation interfaces
func (c *Crawler) checkDocInterfaces(result *DiscoveryResult) error {
	paths := []string{
		"/swagger",
		"/swagger-ui",
		"/swagger-ui.html",
		"/api-docs",
		"/docs",
		"/redoc",
		"/graphql",
		"/graphiql",
	}

	for _, path := range paths {
		url := result.BaseURL + path
		resp, err := c.client.Get(url)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			result.SwaggerUI = append(result.SwaggerUI, url)
		}
	}

	return nil
}

// checkSpecLocations checks common locations for API specifications
func (c *Crawler) checkSpecLocations(result *DiscoveryResult) error {
	paths := []string{
		"/swagger.json",
		"/swagger.yaml",
		"/swagger.yml",
		"/api-docs.json",
		"/openapi.json",
		"/openapi.yaml",
		"/openapi.yml",
		"/v1/swagger.json",
		"/v2/swagger.json",
		"/v3/swagger.json",
	}

	for _, path := range paths {
		url := result.BaseURL + path
		resp, err := c.client.Get(url)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			result.SpecURLs = append(result.SpecURLs, url)
		}
	}

	return nil
}

// discoverEndpoints attempts to discover API endpoints
func (c *Crawler) discoverEndpoints(result *DiscoveryResult) error {
	commonPaths := []string{
		"/api",
		"/api/v1",
		"/api/v2",
		"/api/v3",
		"/rest",
		"/graphql",
		"/users",
		"/auth",
		"/login",
		"/register",
	}

	for _, path := range commonPaths {
		url := result.BaseURL + path
		resp, err := c.client.Get(url)
		if err != nil {
			continue
		}
		resp.Body.Close()

		// Consider any 2xx or 401/403 as potential API endpoints
		if resp.StatusCode >= 200 && resp.StatusCode < 300 ||
			resp.StatusCode == http.StatusUnauthorized ||
			resp.StatusCode == http.StatusForbidden {
			result.APIEndpoints = append(result.APIEndpoints, url)
		}
	}

	return nil
}
