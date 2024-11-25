package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/gregcmartin/casper/internal/business"
	"github.com/gregcmartin/casper/internal/crawler"
	"github.com/gregcmartin/casper/internal/reporter"
	"github.com/gregcmartin/casper/internal/security"
	"github.com/gregcmartin/casper/internal/validator"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	baseURL          string
	outputFile       string
	logger           *logrus.Logger
	debug            bool
	skipTests        []string
	skipValidation   bool
	skipURLEncode    bool
	mode             string
	noSpecValidation bool
	rawOutput        bool
)

var rootCmd = &cobra.Command{
	Use:   "casper",
	Short: "Casper - API Security Testing Tool",
	Long: `Casper is a CLI tool that helps prevent incorrect API implementations
by validating and testing your API using OpenAPI specifications.`,
}

var validateCmd = &cobra.Command{
	Use:   "validate [OpenAPI spec file]",
	Short: "Validate an OpenAPI specification file",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		specPath := args[0]

		if skipValidation {
			logger.Info("Skipping validation as requested")
			return
		}

		// Ensure the file exists
		if _, err := os.Stat(specPath); os.IsNotExist(err) {
			logger.Errorf("Specification file not found: %s", specPath)
			os.Exit(1)
		}

		v := validator.New(logger)

		if err := v.ValidateSpec(specPath); err != nil {
			logger.Errorf("Validation failed: %v", err)
			os.Exit(1)
		}

		logger.Info("OpenAPI specification is valid")
	},
}

var testCmd = &cobra.Command{
	Use:   "test [OpenAPI spec file]",
	Short: "Run security and business logic tests against an API",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if baseURL == "" {
			logger.Error("Base URL is required for testing")
			os.Exit(1)
		}

		// Initialize the reporter
		r := reporter.New(logger)

		// Initialize security tester
		tester := security.New(logger, baseURL)

		// Handle different test modes
		switch mode {
		case "core":
			logger.Info("Running core security tests...")
			if len(args) > 0 && !noSpecValidation {
				if err := tester.RunTests(args[0]); err != nil {
					logger.Errorf("Core security testing failed: %v", err)
					os.Exit(1)
				}
			} else {
				if err := tester.RunTestsWithoutSpec(); err != nil {
					logger.Errorf("Core security testing failed: %v", err)
					os.Exit(1)
				}
			}
		case "direct":
			logger.Info("Running direct API tests...")
			if err := tester.RunDirectTests(skipURLEncode); err != nil {
				logger.Errorf("Direct testing failed: %v", err)
				os.Exit(1)
			}
		case "raw":
			logger.Info("Running raw security tests...")
			if err := tester.RunRawTests(); err != nil {
				logger.Errorf("Raw testing failed: %v", err)
				os.Exit(1)
			}
		default:
			// Default full testing mode
			if len(args) == 0 {
				logger.Error("OpenAPI spec file is required for full testing mode")
				os.Exit(1)
			}

			specPath := args[0]

			// Ensure the file exists
			if _, err := os.Stat(specPath); os.IsNotExist(err) {
				logger.Errorf("Specification file not found: %s", specPath)
				os.Exit(1)
			}

			// Validate spec unless skipped
			if !skipValidation && !noSpecValidation {
				v := validator.New(logger)
				if err := v.ValidateSpec(specPath); err != nil {
					logger.Errorf("Specification validation failed: %v", err)
					os.Exit(1)
				}
			}

			// Run security tests if not skipped
			if !contains(skipTests, "security") {
				logger.Info("Running security tests...")
				if err := tester.RunTests(specPath); err != nil {
					logger.Errorf("Security testing failed: %v", err)
					os.Exit(1)
				}
			}

			// Run business logic tests if not skipped
			if !contains(skipTests, "business") {
				logger.Info("Running business logic tests...")
				bizTester := business.New(logger, baseURL)
				if err := bizTester.RunTests(specPath); err != nil {
					logger.Errorf("Business logic testing failed: %v", err)
					os.Exit(1)
				}
			}
		}

		// Generate report
		if outputFile == "" {
			outputFile = "casper-report.json"
			if len(args) > 0 {
				outputFile = fmt.Sprintf("casper-report-%s.json",
					filepath.Base(args[0]))
			}
		}

		if err := r.GenerateReport(outputFile); err != nil {
			logger.Errorf("Failed to generate report: %v", err)
			os.Exit(1)
		}

		logger.Infof("Testing completed. Report saved to: %s", outputFile)
	},
}

var discoverCmd = &cobra.Command{
	Use:   "discover [domain or base URL]",
	Short: "Discover APIs and API specifications in a domain",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		domain := args[0]

		// Initialize crawler with options
		c := crawler.New(logger)
		c.SetOptions(crawler.Options{
			SkipValidation: skipValidation || noSpecValidation,
			SkipURLEncode:  skipURLEncode,
			RawOutput:      rawOutput,
		})

		// Discover APIs
		result, err := c.DiscoverAPIs(domain)
		if err != nil {
			logger.Errorf("API discovery failed: %v", err)
			os.Exit(1)
		}

		// Create a directory for downloaded specs
		specsDir := "discovered_specs"
		if err := os.MkdirAll(specsDir, 0755); err != nil {
			logger.Errorf("Failed to create specs directory: %v", err)
			os.Exit(1)
		}

		// Download discovered specs
		var downloadedSpecs []string
		if len(result.SpecURLs) > 0 {
			logger.Info("Found API specifications:")
			for _, specURL := range result.SpecURLs {
				logger.Infof("- %s", specURL)

				// Create a filename for the spec
				parsedURL, err := url.Parse(specURL)
				if err != nil {
					logger.Warnf("Failed to parse spec URL: %v", err)
					continue
				}
				filename := filepath.Join(specsDir, filepath.Base(parsedURL.Path))

				// Download the spec
				if err := downloadSpec(specURL, filename); err != nil {
					logger.Warnf("Failed to download spec from %s: %v", specURL, err)
					continue
				}
				downloadedSpecs = append(downloadedSpecs, filename)
				logger.Infof("Downloaded spec to: %s", filename)
			}
		}

		// If API endpoints were found without specs, test them directly
		if len(result.APIEndpoints) > 0 {
			logger.Info("Found API endpoints:")
			for _, endpoint := range result.APIEndpoints {
				logger.Infof("- %s", endpoint)
			}
		}

		// Generate discovery report
		if outputFile == "" {
			// Parse the domain for a clean filename
			parsedURL, err := url.Parse(domain)
			if err != nil {
				logger.Errorf("Failed to parse domain: %v", err)
				os.Exit(1)
			}

			// Create a clean filename from the host
			cleanDomain := strings.ReplaceAll(parsedURL.Host, ".", "-")
			outputFile = fmt.Sprintf("casper-discovery-%s.json", cleanDomain)
		}

		// Create a map to store the full results
		fullResult := map[string]interface{}{
			"base_url":           result.BaseURL,
			"spec_urls":          result.SpecURLs,
			"api_endpoints":      result.APIEndpoints,
			"swagger_ui":         result.SwaggerUI,
			"documentation_urls": result.DocumentationURLs,
			"headers":            result.Headers,
			"downloaded_specs":   downloadedSpecs,
		}

		// Save discovery results
		file, err := os.Create(outputFile)
		if err != nil {
			logger.Errorf("Failed to create report file: %v", err)
			os.Exit(1)
		}
		defer file.Close()

		if err := json.NewEncoder(file).Encode(fullResult); err != nil {
			logger.Errorf("Failed to write discovery report: %v", err)
			os.Exit(1)
		}

		logger.Infof("Discovery completed. Report saved to: %s", outputFile)

		// If specs were found and downloaded, validate and test them
		if len(downloadedSpecs) > 0 && !skipValidation && !noSpecValidation {
			logger.Info("Starting validation and testing of discovered specs...")

			v := validator.New(logger)
			tester := security.New(logger, result.BaseURL)

			for _, specPath := range downloadedSpecs {
				logger.Infof("Validating and testing spec: %s", specPath)

				// Validate spec
				if err := v.ValidateSpec(specPath); err != nil {
					logger.Warnf("Validation failed for %s: %v", specPath, err)
					continue
				}

				// Run security tests
				if err := tester.RunTests(specPath); err != nil {
					logger.Warnf("Security testing failed for %s: %v", specPath, err)
					continue
				}
			}
		}
	},
}

// downloadSpec downloads an API specification from a URL
func downloadSpec(specURL, filename string) error {
	// Create HTTP client with TLS verification disabled
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	// Download the spec
	resp, err := client.Get(specURL)
	if err != nil {
		return fmt.Errorf("failed to download spec: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download spec: status code %d", resp.StatusCode)
	}

	// Create the file
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	// Copy the content
	_, err = io.Copy(file, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

func init() {
	// Setup logging
	logger = logrus.New()
	logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})

	// Add global flags
	rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false,
		"Enable debug logging")

	// Add command flags
	testCmd.Flags().StringVarP(&baseURL, "base-url", "u", "",
		"Base URL of the API to test (required)")
	testCmd.Flags().StringVarP(&outputFile, "output", "o", "",
		"Output file for the security report (default: casper-report-<spec>.json)")
	testCmd.Flags().StringSliceVarP(&skipTests, "skip", "s", []string{},
		"Skip specific test categories (security, business)")
	testCmd.Flags().BoolVar(&skipValidation, "skip-validation", false,
		"Skip OpenAPI specification validation")
	testCmd.Flags().BoolVar(&skipURLEncode, "no-url-encode", false,
		"Disable automatic URL encoding")
	testCmd.Flags().StringVarP(&mode, "mode", "m", "",
		"Test mode (core, direct, raw)")
	testCmd.Flags().BoolVar(&noSpecValidation, "skip-spec-validation", false,
		"Skip all specification validation")
	testCmd.Flags().BoolVar(&rawOutput, "raw-output", false,
		"Output raw test results")

	// Add discover command flags
	discoverCmd.Flags().StringVarP(&outputFile, "output", "o", "",
		"Output file for the discovery report (default: casper-discovery-<domain>.json)")
	discoverCmd.Flags().BoolVar(&skipValidation, "skip-validation", false,
		"Skip OpenAPI specification validation")
	discoverCmd.Flags().BoolVar(&skipURLEncode, "no-url-encode", false,
		"Disable automatic URL encoding")
	discoverCmd.Flags().BoolVar(&noSpecValidation, "skip-spec-validation", false,
		"Skip all specification validation")
	discoverCmd.Flags().BoolVar(&rawOutput, "raw-output", false,
		"Output raw discovery results")

	// Add commands
	rootCmd.AddCommand(validateCmd)
	rootCmd.AddCommand(testCmd)
	rootCmd.AddCommand(discoverCmd)

	// Set log level based on debug flag
	cobra.OnInitialize(func() {
		if debug {
			logger.SetLevel(logrus.DebugLevel)
		}
	})
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

// contains checks if a string is present in a slice
func contains(slice []string, str string) bool {
	for _, s := range slice {
		if s == str {
			return true
		}
	}
	return false
}
