package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/gregcmartin/casper/internal/business"
	"github.com/gregcmartin/casper/internal/reporter"
	"github.com/gregcmartin/casper/internal/security"
	"github.com/gregcmartin/casper/internal/validator"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	baseURL    string
	outputFile string
	logger     *logrus.Logger
	debug      bool
	skipTests  []string
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
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if baseURL == "" {
			logger.Error("Base URL is required for testing")
			os.Exit(1)
		}

		specPath := args[0]

		// Ensure the file exists
		if _, err := os.Stat(specPath); os.IsNotExist(err) {
			logger.Errorf("Specification file not found: %s", specPath)
			os.Exit(1)
		}

		// First validate the spec
		v := validator.New(logger)
		if err := v.ValidateSpec(specPath); err != nil {
			logger.Errorf("Specification validation failed: %v", err)
			os.Exit(1)
		}

		// Initialize the reporter
		r := reporter.New(logger)

		// Run security tests if not skipped
		if !contains(skipTests, "security") {
			logger.Info("Running security tests...")
			tester := security.New(logger, baseURL)
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

		// Generate report
		if outputFile == "" {
			outputFile = fmt.Sprintf("casper-report-%s.json",
				filepath.Base(specPath))
		}

		if err := r.GenerateReport(outputFile); err != nil {
			logger.Errorf("Failed to generate report: %v", err)
			os.Exit(1)
		}

		logger.Infof("Testing completed. Report saved to: %s", outputFile)
	},
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

	// Add commands
	rootCmd.AddCommand(validateCmd)
	rootCmd.AddCommand(testCmd)

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
