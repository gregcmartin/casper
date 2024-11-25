# Casper

Casper is a comprehensive API security testing tool written in Go. It helps prevent incorrect API implementations by validating and testing APIs using OpenAPI specifications.

## Features

- **OpenAPI Validation**: Comprehensive validation of OpenAPI/Swagger specifications
- **Security Testing**:
  - Authentication bypass detection
  - SQL injection testing
  - XSS vulnerability scanning
  - CORS misconfiguration checks
  - Information disclosure detection
  - Mass assignment vulnerability testing
  - SSRF vulnerability detection
  - JWT security testing
  - Rate limiting checks
- **Business Logic Testing**:
  - Resource dependency validation
  - State transition checks
  - Data consistency verification
  - Access control testing
- **Detailed Reporting**:
  - Severity-based categorization
  - Test coverage statistics
  - Category-based issue tracking
  - Comprehensive test summaries

## Installation

```bash
# Clone the repository
git clone https://github.com/gregcmartin/casper.git

# Build the project
cd casper
go build -o casper ./cmd/casper
```

## Usage

### Validate an OpenAPI Specification

```bash
./casper validate [spec-file]
```

### Run Security and Business Logic Tests

```bash
./casper test [spec-file] --base-url [api-url]
```

### Additional Options

```bash
# Run with debug logging
./casper test [spec-file] --base-url [api-url] --debug

# Skip specific test categories
./casper test [spec-file] --base-url [api-url] --skip security,business

# Specify output report file
./casper test [spec-file] --base-url [api-url] --output report.json
```

## Example

```bash
# Validate a spec file
./casper validate examples/petstore.yaml

# Run full test suite
./casper test examples/petstore.yaml --base-url http://api.example.com

# Run only security tests
./casper test examples/petstore.yaml --base-url http://api.example.com --skip business
```

## Report Format

Casper generates detailed JSON reports containing:
- Overall test summary
- Issues by severity
- Issues by category
- Test coverage statistics
- Detailed findings for each issue

Example report structure:
```json
{
  "summary": {
    "total_issues": 5,
    "issues_by_severity": {
      "HIGH": 2,
      "MEDIUM": 3
    },
    "issues_by_category": {
      "SECURITY": 3,
      "BUSINESS_LOGIC": 2
    },
    "test_coverage": {
      "AUTHENTICATION": {
        "tests_run": 10,
        "tests_passed": 8,
        "tests_failed": 2
      }
    }
  },
  "issues": [
    {
      "id": "SEC001",
      "title": "SQL Injection Vulnerability",
      "description": "Endpoint vulnerable to SQL injection",
      "severity": "HIGH",
      "category": "SECURITY",
      "path": "/users",
      "method": "GET"
    }
  ]
}
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
