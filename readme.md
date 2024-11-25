# Casper

Casper is a comprehensive API security testing tool written in Go. It helps prevent incorrect API implementations by validating and testing APIs using OpenAPI specifications.

## Features

- OpenAPI/Swagger specification validation
- Comprehensive security testing suite
- Business logic validation
- Detailed security reporting
- GraphQL security testing
- Static resource security
- Export functionality testing

For detailed information about security tests, see [TESTS.md](TESTS.md).

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

## Project Structure

```
casper/
├── cmd/casper/         # CLI implementation
├── internal/
│   ├── validator/      # OpenAPI validation
│   ├── security/       # Security testing
│   │   ├── core/      # Core security tests
│   │   ├── parameter/ # Parameter-based tests
│   │   ├── graphql/   # GraphQL-specific tests
│   │   ├── static/    # Static resource tests
│   │   ├── export/    # Export functionality tests
│   │   └── security.go # Main orchestrator
│   ├── business/      # Business logic testing
│   └── reporter/      # Report generation
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
