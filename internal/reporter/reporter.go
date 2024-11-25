package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/sirupsen/logrus"
)

// Severity represents the severity level of an issue
type Severity string

const (
	Critical Severity = "CRITICAL"
	High     Severity = "HIGH"
	Medium   Severity = "MEDIUM"
	Low      Severity = "LOW"
	Info     Severity = "INFO"
)

// Category represents the type of test that found the issue
type Category string

const (
	SecurityTest Category = "SECURITY"
	BusinessTest Category = "BUSINESS_LOGIC"
)

// SubCategory provides more specific categorization of issues
type SubCategory string

const (
	// Security subcategories
	Authentication SubCategory = "AUTHENTICATION"
	Authorization  SubCategory = "AUTHORIZATION"
	Injection      SubCategory = "INJECTION"
	XSS            SubCategory = "XSS"
	CSRF           SubCategory = "CSRF"
	CORS           SubCategory = "CORS"
	InfoDisclosure SubCategory = "INFORMATION_DISCLOSURE"
	RateLimit      SubCategory = "RATE_LIMITING"
	SSRF           SubCategory = "SSRF"
	JWT            SubCategory = "JWT_SECURITY"
	MassAssignment SubCategory = "MASS_ASSIGNMENT"

	// Business logic subcategories
	ResourceDependency SubCategory = "RESOURCE_DEPENDENCY"
	StateTransition    SubCategory = "STATE_TRANSITION"
	DataConsistency    SubCategory = "DATA_CONSISTENCY"
	AccessControl      SubCategory = "ACCESS_CONTROL"
)

// Issue represents a security or business logic issue found during testing
type Issue struct {
	ID          string      `json:"id"`
	Title       string      `json:"title"`
	Description string      `json:"description"`
	Category    Category    `json:"category"`
	SubCategory SubCategory `json:"sub_category"`
	Severity    Severity    `json:"severity"`
	Path        string      `json:"path"`
	Method      string      `json:"method"`
	Evidence    string      `json:"evidence,omitempty"`
	Mitigation  string      `json:"mitigation,omitempty"`
	References  []string    `json:"references,omitempty"`
	Timestamp   time.Time   `json:"timestamp"`
}

// Report represents a complete test report
type Report struct {
	Summary struct {
		TotalIssues      int                       `json:"total_issues"`
		IssuesBySeverity map[Severity]int          `json:"issues_by_severity"`
		IssuesByCategory map[Category]int          `json:"issues_by_category"`
		StartTime        time.Time                 `json:"start_time"`
		EndTime          time.Time                 `json:"end_time"`
		TestCoverage     map[SubCategory]TestStats `json:"test_coverage"`
	} `json:"summary"`
	Issues []Issue `json:"issues"`
}

// TestStats represents statistics for a specific test category
type TestStats struct {
	TestsRun    int `json:"tests_run"`
	TestsPassed int `json:"tests_passed"`
	TestsFailed int `json:"tests_failed"`
}

// Reporter handles the generation of test reports
type Reporter struct {
	logger *logrus.Logger
	report Report
}

// New creates a new Reporter instance
func New(logger *logrus.Logger) *Reporter {
	r := &Reporter{
		logger: logger,
		report: Report{},
	}
	r.report.Summary.IssuesBySeverity = make(map[Severity]int)
	r.report.Summary.IssuesByCategory = make(map[Category]int)
	r.report.Summary.TestCoverage = make(map[SubCategory]TestStats)
	r.report.Summary.StartTime = time.Now()
	return r
}

// AddIssue adds a new issue to the report
func (r *Reporter) AddIssue(issue Issue) {
	r.report.Issues = append(r.report.Issues, issue)
	r.report.Summary.TotalIssues++
	r.report.Summary.IssuesBySeverity[issue.Severity]++
	r.report.Summary.IssuesByCategory[issue.Category]++
}

// UpdateTestStats updates the test statistics for a subcategory
func (r *Reporter) UpdateTestStats(subCategory SubCategory, passed bool) {
	stats := r.report.Summary.TestCoverage[subCategory]
	stats.TestsRun++
	if passed {
		stats.TestsPassed++
	} else {
		stats.TestsFailed++
	}
	r.report.Summary.TestCoverage[subCategory] = stats
}

// GenerateReport finalizes and saves the report to a file
func (r *Reporter) GenerateReport(outputPath string) error {
	r.report.Summary.EndTime = time.Now()

	// Calculate test coverage percentages
	for subCategory, stats := range r.report.Summary.TestCoverage {
		r.logger.WithFields(logrus.Fields{
			"subCategory": subCategory,
			"passed":      stats.TestsPassed,
			"failed":      stats.TestsFailed,
			"total":       stats.TestsRun,
		}).Debug("Test coverage stats")
	}

	// Create the report file
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create report file: %w", err)
	}
	defer file.Close()

	// Write report as JSON
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(r.report); err != nil {
		return fmt.Errorf("failed to encode report: %w", err)
	}

	r.logger.Infof("Report generated successfully: %s", outputPath)
	r.logSummary()

	return nil
}

// logSummary prints a summary of the findings
func (r *Reporter) logSummary() {
	r.logger.Info("=== Test Summary ===")
	r.logger.Infof("Total Issues: %d", r.report.Summary.TotalIssues)

	r.logger.Info("Issues by Severity:")
	for severity, count := range r.report.Summary.IssuesBySeverity {
		r.logger.Infof("  %s: %d", severity, count)
	}

	r.logger.Info("Issues by Category:")
	for category, count := range r.report.Summary.IssuesByCategory {
		r.logger.Infof("  %s: %d", category, count)
	}

	r.logger.Info("Test Coverage:")
	for subCategory, stats := range r.report.Summary.TestCoverage {
		passRate := float64(stats.TestsPassed) / float64(stats.TestsRun) * 100
		r.logger.Infof("  %s: %.1f%% (%d/%d passed)",
			subCategory, passRate, stats.TestsPassed, stats.TestsRun)
	}

	duration := r.report.Summary.EndTime.Sub(r.report.Summary.StartTime)
	r.logger.Infof("Duration: %v", duration)
}

// GetReport returns the current report
func (r *Reporter) GetReport() Report {
	return r.report
}
