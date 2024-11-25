# Casper

Casper is a comprehensive API security testing tool written in Go. It helps prevent incorrect API implementations by validating and testing APIs using OpenAPI specifications.

## Features

### Core Security Tests
- Authentication & Authorization
  * Multiple authentication endpoint testing
  * Token-based authentication validation
  * Authorization bypass detection
  * Function level authorization testing
- Input Validation & Injection
  * SQL injection testing
  * XSS vulnerability detection
  * Command injection testing
  * Input validation bypass attempts
- Security Headers & Configuration
  * CORS misconfiguration detection
  * Security headers validation
  * TLS configuration testing
  * HSTS implementation checks

### Parameter-Based Tests
- ID and Reference Testing
  * GUID/UUID bypass attempts
  * Numeric ID substitution
  * Array wrapping vulnerabilities
  * JSON object wrapping
- Parameter Manipulation
  * Parameter pollution
  * JSON parameter pollution
  * Wildcard testing
  * Content type manipulation
- Version Testing
  * API version testing
  * Version parameter manipulation
  * Environment detection
  * Non-production environment testing

### GraphQL Security Tests
- Schema Analysis
  * Introspection testing
  * Field suggestion detection
  * Query depth analysis
  * Query complexity testing
- GraphQL-Specific
  * Batch query testing
  * Field level authorization
  * Query validation
  * Mutation testing

### Static Resource Tests
- Resource Access
  * Direct resource access testing
  * Path traversal detection
  * Resource authorization testing
  * Cross-user access attempts
- File Handling
  * File type validation
  * Upload restrictions
  * Resource enumeration
  * Access control verification

### Export Functionality Tests
- Export Injection
  * PDF export injection
  * CSV export injection
  * HTML export injection
  * Template injection
- Format Testing
  * Export parameter manipulation
  * Format validation
  * Path traversal in exports
  * File inclusion testing

## Installation

```bash
# Clone the repository
git clone https://github.com/gregcmartin/casper.git

# Build the project
cd casper
go build -o casper ./cmd/casper
```

## Usage

### Basic Usage

```bash
# Validate an OpenAPI specification
./casper validate [spec-file]

# Run all security tests
./casper test [spec-file] --base-url [api-url]
```

### Advanced Options

```bash
# Run with debug logging
./casper test [spec-file] --base-url [api-url] --debug

# Skip specific test categories
./casper test [spec-file] --base-url [api-url] --skip security,business

# Specify output report file
./casper test [spec-file] --base-url [api-url] --output report.json
```

### Example

```bash
# Test a local API
./casper test examples/petstore.yaml --base-url http://localhost:8080

# Test with debug output
./casper test examples/petstore.yaml --base-url http://api.example.com --debug
```

## Security Test Categories

### Authentication Tests
- Multiple authentication endpoint testing
- Token manipulation and validation
- Session management security
- OAuth implementation testing
- JWT security validation
- Authentication bypass attempts

### Authorization Tests
- Role-based access control
- Function level authorization
- Resource-level permissions
- Cross-user access attempts
- Privilege escalation tests
- Authorization bypass detection

### Injection Prevention Tests
- SQL injection vectors
- NoSQL injection
- Command injection
- XSS payloads
- SSRF vulnerabilities
- Template injection

### API Security Tests
- Rate limiting implementation
- API versioning security
- Information disclosure
- Error handling security
- Input validation
- Output encoding

### Data Protection Tests
- Data encryption validation
- Sensitive data exposure
- SSL/TLS implementation
- DDOS protection
- Content security
- File upload security

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
