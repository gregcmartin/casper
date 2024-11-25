package crawler

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// Common paths where API specs might be found
var commonSpecPaths = []string{
	// Swagger UI paths
	"/swagger",
	"/swagger/",
	"/swagger-ui",
	"/swagger-ui/",
	"/swagger-ui.html",
	"/swagger-ui/index.html",
	"/api/swagger-ui",
	"/api/swagger-ui/",
	"/api/swagger-ui.html",
	"/docs/swagger-ui",
	"/docs/swagger-ui/",
	"/docs/swagger-ui.html",

	// Swagger/OpenAPI spec paths
	"/swagger.json",
	"/swagger.yaml",
	"/swagger.yml",
	"/swagger/v1/swagger.json",
	"/swagger/v2/swagger.json",
	"/swagger/v3/swagger.json",
	"/api/swagger.json",
	"/api/swagger.yaml",
	"/api/v1/swagger.json",
	"/api/v2/swagger.json",
	"/api/v3/swagger.json",
	"/docs/swagger.json",
	"/docs/swagger.yaml",

	// OpenAPI paths
	"/openapi",
	"/openapi.json",
	"/openapi.yaml",
	"/openapi.yml",
	"/api/openapi",
	"/api/openapi.json",
	"/api/openapi.yaml",
	"/v1/openapi.json",
	"/v2/openapi.json",
	"/v3/openapi.json",

	// API documentation paths
	"/api-docs",
	"/api-docs/",
	"/api/docs",
	"/api/docs/",
	"/docs/api",
	"/docs/api/",
	"/documentation",
	"/documentation/",
	"/api/documentation",
	"/api/documentation/",

	// ReDoc paths
	"/redoc",
	"/redoc/",
	"/api/redoc",
	"/api/redoc/",
	"/docs/redoc",
	"/docs/redoc/",

	// GraphQL paths
	"/graphql",
	"/graphiql",
	"/playground",
	"/graphql/playground",
	"/api/graphql",
	"/api/graphiql",

	// Additional common paths
	"/api/spec",
	"/api/schema",
	"/api/definition",
	"/api/reference",
}

// Common API endpoint patterns
var commonAPIPatterns = []string{
	// Core API paths
	"/api",
	"/api/",
	"/api/v1",
	"/api/v2",
	"/api/v3",
	"/rest",
	"/rest/",
	"/rest/v1",
	"/rest/v2",
	"/graphql",

	// Common resource paths
	"/api/users",
	"/api/auth",
	"/api/login",
	"/api/register",
	"/api/products",
	"/api/orders",
	"/api/items",
	"/api/data",
	"/api/search",
	"/api/upload",
	"/api/download",

	// Common service paths
	"/service",
	"/services",
	"/api/service",
	"/api/services",
	"/api/public",
	"/api/private",
	"/api/internal",
	"/api/external",
	"/api/system",

	// Common version paths
	"/v1",
	"/v2",
	"/v3",
	"/api/v1",
	"/api/v2",
	"/api/v3",

	// Common function paths
	"/api/status",
	"/api/health",
	"/api/ping",
	"/api/test",
	"/api/version",
	"/api/config",
	"/api/settings",
}

// Crawler handles domain crawling and API discovery
type Crawler struct {
	logger     *logrus.Logger
	client     *http.Client
	visited    map[string]bool
	visitedMux sync.Mutex
}

// DiscoveryResult represents the result of API discovery
type DiscoveryResult struct {
	BaseURL           string            `json:"base_url"`
	SpecURLs          []string          `json:"spec_urls"`
	APIEndpoints      []string          `json:"api_endpoints"`
	SwaggerUI         []string          `json:"swagger_ui"`
	DocumentationURLs []string          `json:"documentation_urls"`
	Headers           map[string]string `json:"headers,omitempty"`
}

// New creates a new Crawler instance
func New(logger *logrus.Logger) *Crawler {
	// Create custom transport with relaxed TLS verification for testing
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
	}

	return &Crawler{
		logger:  logger,
		client:  client,
		visited: make(map[string]bool),
	}
}

// DiscoverAPIs crawls a domain to discover APIs and API specifications
func (c *Crawler) DiscoverAPIs(baseURL string) (*DiscoveryResult, error) {
	c.logger.Infof("Starting API discovery for domain: %s", baseURL)

	// Ensure baseURL has a protocol
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		baseURL = "https://" + baseURL
	}

	// Parse and normalize the base URL
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}
	baseURL = parsedURL.Scheme + "://" + parsedURL.Host

	result := &DiscoveryResult{
		BaseURL:           baseURL,
		SpecURLs:          make([]string, 0),
		APIEndpoints:      make([]string, 0),
		SwaggerUI:         make([]string, 0),
		DocumentationURLs: make([]string, 0),
		Headers:           make(map[string]string),
	}

	// Check server headers
	c.logger.Info("Checking server headers...")
	if headers, err := c.checkServerHeaders(baseURL); err == nil {
		result.Headers = headers
	}

	// First, check for Swagger UI and documentation
	c.logger.Info("Checking for API documentation interfaces...")
	swaggerUI, docURLs := c.findDocumentationInterfaces(baseURL)
	result.SwaggerUI = append(result.SwaggerUI, swaggerUI...)
	result.DocumentationURLs = append(result.DocumentationURLs, docURLs...)

	// Then, check common spec locations
	c.logger.Info("Checking common API specification locations...")
	specURLs := c.findSpecifications(baseURL)
	result.SpecURLs = append(result.SpecURLs, specURLs...)

	// Finally, discover potential API endpoints
	c.logger.Info("Discovering API endpoints...")
	apiEndpoints := c.findAPIEndpoints(baseURL)
	result.APIEndpoints = append(result.APIEndpoints, apiEndpoints...)

	// Remove duplicates
	result.SpecURLs = removeDuplicates(result.SpecURLs)
	result.APIEndpoints = removeDuplicates(result.APIEndpoints)
	result.SwaggerUI = removeDuplicates(result.SwaggerUI)
	result.DocumentationURLs = removeDuplicates(result.DocumentationURLs)

	c.logger.Infof("Discovery completed. Found %d spec(s), %d API endpoint(s), %d Swagger UI(s), and %d documentation URL(s)",
		len(result.SpecURLs), len(result.APIEndpoints), len(result.SwaggerUI), len(result.DocumentationURLs))

	return result, nil
}

// checkServerHeaders checks for API-related headers
func (c *Crawler) checkServerHeaders(baseURL string) (map[string]string, error) {
	headers := make(map[string]string)

	resp, err := c.client.Get(baseURL)
	if err != nil {
		return headers, err
	}
	defer resp.Body.Close()

	relevantHeaders := []string{
		"Server",
		"X-Powered-By",
		"X-API-Version",
		"X-API-Gateway",
		"Access-Control-Allow-Origin",
		"Access-Control-Allow-Methods",
		"Access-Control-Allow-Headers",
	}

	for _, header := range relevantHeaders {
		if value := resp.Header.Get(header); value != "" {
			headers[header] = value
		}
	}

	return headers, nil
}

// findDocumentationInterfaces looks for Swagger UI and other API documentation interfaces
func (c *Crawler) findDocumentationInterfaces(baseURL string) ([]string, []string) {
	var swaggerUI []string
	var docURLs []string
	var wg sync.WaitGroup
	var mutex sync.Mutex

	// Common documentation interface paths
	docPaths := []string{
		"/swagger-ui.html",
		"/swagger-ui/index.html",
		"/swagger",
		"/api-docs",
		"/redoc",
		"/graphiql",
		"/playground",
	}

	for _, path := range docPaths {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			url := baseURL + p
			resp, err := c.client.Get(url)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				mutex.Lock()
				if strings.Contains(p, "swagger") {
					swaggerUI = append(swaggerUI, url)
					c.logger.Infof("Found Swagger UI at: %s", url)
				} else {
					docURLs = append(docURLs, url)
					c.logger.Infof("Found API documentation at: %s", url)
				}
				mutex.Unlock()
			}
		}(path)
	}

	wg.Wait()
	return swaggerUI, docURLs
}

// findSpecifications checks common locations for API specifications
func (c *Crawler) findSpecifications(baseURL string) []string {
	var specs []string
	var wg sync.WaitGroup
	var mutex sync.Mutex

	for _, path := range commonSpecPaths {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			specURL := baseURL + p
			if c.isValidSpec(specURL) {
				mutex.Lock()
				specs = append(specs, specURL)
				mutex.Unlock()
				c.logger.Infof("Found API specification at: %s", specURL)
			}
		}(path)
	}

	wg.Wait()
	return specs
}

// findAPIEndpoints discovers potential API endpoints
func (c *Crawler) findAPIEndpoints(baseURL string) []string {
	var endpoints []string
	var wg sync.WaitGroup
	var mutex sync.Mutex

	for _, pattern := range commonAPIPatterns {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			endpoint := baseURL + p
			if c.isValidEndpoint(endpoint) {
				mutex.Lock()
				endpoints = append(endpoints, endpoint)
				mutex.Unlock()
				c.logger.Infof("Found API endpoint at: %s", endpoint)
			}
		}(pattern)
	}

	wg.Wait()
	return endpoints
}

// isValidSpec checks if a URL points to a valid API specification
func (c *Crawler) isValidSpec(url string) bool {
	resp, err := c.client.Get(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false
	}

	// Read the first 1024 bytes to check content
	content := make([]byte, 1024)
	n, err := resp.Body.Read(content)
	if err != nil && err != io.EOF {
		return false
	}
	content = content[:n]

	// Check if it looks like a valid spec
	contentStr := string(content)
	return c.looksLikeSpec(contentStr, resp.Header.Get("Content-Type"))
}

// isValidEndpoint checks if a URL points to a valid API endpoint
func (c *Crawler) isValidEndpoint(url string) bool {
	methods := []string{"GET", "OPTIONS", "HEAD"}

	for _, method := range methods {
		req, err := http.NewRequest(method, url, nil)
		if err != nil {
			continue
		}

		resp, err := c.client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if c.isAPIResponse(resp) {
			return true
		}
	}

	return false
}

// looksLikeSpec checks if content appears to be an API specification
func (c *Crawler) looksLikeSpec(content, contentType string) bool {
	// Check for common spec indicators
	indicators := []string{
		"\"swagger\":", "\"openapi\":",
		"swagger:", "openapi:",
		"\"info\":", "info:",
		"\"paths\":", "paths:",
		"\"components\":", "components:",
		"\"definitions\":", "definitions:",
		"type Query", "schema {",
		"FORMAT: 1A",
		"#%RAML",
	}

	for _, indicator := range indicators {
		if strings.Contains(content, indicator) {
			return true
		}
	}

	// Try parsing as JSON
	var jsonData map[string]interface{}
	if json.NewDecoder(strings.NewReader(content)).Decode(&jsonData) == nil {
		_, hasSwagger := jsonData["swagger"]
		_, hasOpenAPI := jsonData["openapi"]
		_, hasInfo := jsonData["info"]
		_, hasPaths := jsonData["paths"]

		if hasSwagger || hasOpenAPI || (hasInfo && hasPaths) {
			return true
		}
	}

	return false
}

// isAPIResponse checks if a response appears to be from an API
func (c *Crawler) isAPIResponse(resp *http.Response) bool {
	// Check status code
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
		return false
	}

	// Check content type
	contentType := resp.Header.Get("Content-Type")
	apiContentTypes := []string{
		"application/json",
		"application/xml",
		"application/graphql",
		"application/yaml",
		"application/x-yaml",
		"text/yaml",
		"application/hal+json",
		"application/vnd.api+json",
		"application/ld+json",
	}

	for _, ct := range apiContentTypes {
		if strings.Contains(contentType, ct) {
			return true
		}
	}

	// Check for API-related headers
	apiHeaders := []string{
		"X-RateLimit",
		"X-API-Key",
		"X-API-Version",
		"Access-Control-Allow-Origin",
		"Access-Control-Allow-Methods",
		"X-Powered-By",
		"X-Request-ID",
		"API-Version",
	}

	for _, header := range apiHeaders {
		if resp.Header.Get(header) != "" {
			return true
		}
	}

	return false
}

// removeDuplicates removes duplicate strings from a slice
func removeDuplicates(slice []string) []string {
	keys := make(map[string]bool)
	var list []string
	for _, entry := range slice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}
