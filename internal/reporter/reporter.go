package reporter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/sirupsen/logrus"
)

// Reporter handles test result reporting
type Reporter struct {
	logger *logrus.Logger
	issues []Issue
}

// Issue represents a security issue found during testing
type Issue struct {
	Type        string    `json:"type"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
	Endpoint    string    `json:"endpoint,omitempty"`
	Evidence    string    `json:"evidence,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
}

// New creates a new reporter instance
func New(logger *logrus.Logger) *Reporter {
	return &Reporter{
		logger: logger,
		issues: make([]Issue, 0),
	}
}

// AddIssue adds a security issue to the report
func (r *Reporter) AddIssue(issueType, severity, description string, endpoint, evidence string) {
	issue := Issue{
		Type:        issueType,
		Severity:    severity,
		Description: description,
		Endpoint:    endpoint,
		Evidence:    evidence,
		Timestamp:   time.Now(),
	}
	r.issues = append(r.issues, issue)
}

// GenerateReport creates the final security report
func (r *Reporter) GenerateReport(outputPath string) error {
	// Clean up the output path
	outputPath = filepath.Clean(outputPath)
	if filepath.Ext(outputPath) == "" {
		outputPath += ".json"
	}

	// Create report structure
	report := struct {
		Summary struct {
			TotalIssues      int            `json:"total_issues"`
			IssuesBySeverity map[string]int `json:"issues_by_severity"`
			IssuesByType     map[string]int `json:"issues_by_type"`
			Duration         string         `json:"duration"`
			Timestamp        time.Time      `json:"timestamp"`
		} `json:"summary"`
		Issues []Issue `json:"issues"`
	}{
		Issues: r.issues,
	}

	// Calculate summary statistics
	report.Summary.TotalIssues = len(r.issues)
	report.Summary.IssuesBySeverity = make(map[string]int)
	report.Summary.IssuesByType = make(map[string]int)
	report.Summary.Timestamp = time.Now()

	for _, issue := range r.issues {
		report.Summary.IssuesBySeverity[issue.Severity]++
		report.Summary.IssuesByType[issue.Type]++
	}

	// Create output file
	file, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Write report
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return err
	}

	// Log summary
	r.logger.Info("Report generated successfully:", outputPath)
	r.logger.Info("=== Test Summary ===")
	r.logger.Infof("Total Issues: %d", report.Summary.TotalIssues)
	r.logger.Info("Issues by Severity:")
	for severity, count := range report.Summary.IssuesBySeverity {
		r.logger.Infof("  %s: %d", severity, count)
	}
	r.logger.Info("Issues by Type:")
	for issueType, count := range report.Summary.IssuesByType {
		r.logger.Infof("  %s: %d", issueType, count)
	}

	return nil
}

// LogIssue logs an issue and adds it to the report
func (r *Reporter) LogIssue(issueType, severity, description string, endpoint, evidence string) {
	r.logger.Warnf("[%s] %s: %s", severity, issueType, description)
	if endpoint != "" {
		r.logger.Warnf("Endpoint: %s", endpoint)
	}
	if evidence != "" {
		r.logger.Warnf("Evidence: %s", evidence)
	}
	r.AddIssue(issueType, severity, description, endpoint, evidence)
}

// GetIssueCount returns the total number of issues found
func (r *Reporter) GetIssueCount() int {
	return len(r.issues)
}

// Clear removes all issues from the reporter
func (r *Reporter) Clear() {
	r.issues = make([]Issue, 0)
}
