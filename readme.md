# Casper 👻 v1.0

Casper is a comprehensive API security testing tool written in Go. It helps prevent incorrect API implementations by validating and testing APIs using OpenAPI specifications, domain crawling, or direct base URL testing.

## Features

- OpenAPI/Swagger specification validation
- Domain-based API discovery and testing
- Direct base URL testing support
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

### Spec-Based Testing

```bash
# Test using OpenAPI specification
./casper -input api-spec.yaml -base-url http://api.example.com

# Run with debug logging
./casper -input api-spec.yaml -base-url http://api.example.com -debug
```

### Domain-Based Testing

```bash
# Test entire domain with automatic API discovery
./casper -input example.com

# Test with authentication
./casper -input example.com -auth your-token
```

### Direct Base URL Testing

```bash
# Test specific API endpoint or base path
./casper -base-url http://api.example.com/v1

# Test with custom output file
./casper -base-url http://api.example.com/v1 -output custom-report.json
```

## Project Structure

```
casper/
├── cmd/casper/         # CLI implementation
├── internal/
│   ├── crawler/        # API discovery
│   ├── validator/      # OpenAPI validation
│   ├── security/       # Security testing
│   │   ├── core/      # Core security tests
│   │   ├── parameter/ # Parameter-based tests
│   │   ├── graphql/   # GraphQL-specific tests
│   │   ├── static/    # Static resource tests
│   │   ├── export/    # Export functionality tests
│   │   ├── specless/  # Spec-less testing
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
