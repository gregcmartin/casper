# Casper

Casper is a comprehensive API security testing tool written in Go. It helps prevent incorrect API implementations by validating and testing APIs using OpenAPI specifications.

## Features

### Authentication & Authorization
- Authentication bypass detection
- JWT security testing
- OAuth implementation validation
- Brute force protection testing
- Session management security
- Password policy validation

### Injection & XSS Protection
- SQL injection testing
- Cross-Site Scripting (XSS) detection
- Server-Side Request Forgery (SSRF) testing
- Mass assignment vulnerability checks
- Input validation testing

### Security Headers & Configuration
- CORS misconfiguration detection
- HTTP security headers validation
- Content security testing
- TLS configuration validation
- HSTS implementation checks

### API Design Security
- Rate limiting validation
- API versioning checks
- Information disclosure detection
- Error handling security
- File upload security

### Data Protection
- Data encryption validation
- Content type security
- SSL/TLS stripping protection
- DDOS protection testing

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

## Security Tests

### Authentication Tests
- Token-based authentication validation
- OAuth 2.0 implementation security
- JWT implementation security
- Session management security
- Password policy enforcement
- Brute force protection

### Injection Prevention Tests
- SQL injection vectors
- NoSQL injection vectors
- Command injection
- XSS payloads
- SSRF vulnerabilities
- Mass assignment vulnerabilities

### Security Configuration Tests
- CORS policy validation
- Security headers verification
- TLS configuration
- HSTS implementation
- Content security policy
- X-Frame-Options

### API Security Tests
- Rate limiting implementation
- API versioning security
- Information disclosure
- Error handling security
- File upload restrictions
- HTTP method restrictions

### Data Protection Tests
- Data encryption validation
- Sensitive data exposure
- SSL/TLS implementation
- DDOS protection
- Content type security

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
