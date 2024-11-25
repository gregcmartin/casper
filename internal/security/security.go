package security

import (
	"crypto/tls"
	"net/http"
	"strings"
	"time"

	"github.com/gregcmartin/casper/internal/security/core"
	"github.com/gregcmartin/casper/internal/security/parameter"
	"github.com/sirupsen/logrus"
)

// Tester is the main security testing orchestrator
type Tester struct {
	logger      *logrus.Logger
	coreTester  *core.Tester
	paramTester *parameter.Tester
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
		logger:      logger,
		coreTester:  core.New(logger, client, baseURL),
		paramTester: parameter.New(logger, client, baseURL),
	}
}

// RunTests performs all security tests against the API
func (t *Tester) RunTests(specPath string) error {
	t.logger.Info("Starting comprehensive security tests")

	// Run core security tests
	if err := t.coreTester.RunTests(specPath); err != nil {
		return err
	}

	// Run parameter-based security tests
	if err := t.paramTester.RunTests(specPath); err != nil {
		return err
	}

	return nil
}

// SetHeader sets a custom header for all requests
func (t *Tester) SetHeader(key, value string) {
	t.coreTester.SetHeader(key, value)
}
