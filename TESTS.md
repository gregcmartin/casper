# Casper Security Tests

This document details all security tests implemented in Casper.

## Core Security Tests

### Authentication & Authorization
- Multiple authentication endpoint testing
  * Tests all authentication endpoints (`/api/mobile/login`, `/api/v3/login`, etc.)
  * Checks for inconsistencies between different auth methods
  * Tests for authentication bypass vulnerabilities
- Token-based authentication validation
  * JWT security testing
  * OAuth implementation validation
  * Token manipulation detection
- Authorization testing
  * Function level authorization (BFLA)
  * Role-based access control
  * Resource-level permissions
  * Cross-user access attempts

### Input Validation & Injection
- SQL Injection Testing
  * Classic SQL injection patterns
  * Error-based SQL injection
  * Time-based SQL injection
  * Union-based SQL injection
- Command Injection
  * Shell command injection
  * Ruby command injection via URLs
  * System command execution
- XSS Protection
  * Reflected XSS testing
  * Stored XSS testing
  * DOM-based XSS testing
- SSRF Protection
  * Internal port scanning attempts
  * Cloud metadata access
  * Internal service discovery
  * Large file download attempts

### Security Configuration
- CORS Testing
  * Origin validation
  * Credential handling
  * Header restrictions
  * Preflight requests
- Security Headers
  * HSTS implementation
  * X-Frame-Options
  * Content Security Policy
  * X-Content-Type-Options
- TLS Configuration
  * Protocol version testing
  * Cipher suite validation
  * Certificate validation
  * SSL/TLS stripping protection

## Parameter-Based Tests

### ID and Reference Testing
- GUID/UUID Testing
  * Numeric ID substitution
  * GUID format validation
  * UUID version testing
- Array Manipulation
  * Array wrapping exploits
  * Array parameter pollution
  * Array type confusion
- JSON Object Testing
  * Object wrapping vulnerabilities
  * Nested object injection
  * Object parameter pollution

### Parameter Manipulation
- HTTP Parameter Pollution
  * Multiple parameter submissions
  * Parameter priority testing
  * Parameter interpretation
- Content Type Testing
  * Content-Type header manipulation
  * MIME type confusion
  * Charset manipulation
- Version Testing
  * API version manipulation
  * Version parameter pollution
  * Version-specific vulnerabilities

## GraphQL Security Tests

### Schema Analysis
- Introspection Testing
  * Schema exposure testing
  * Type system analysis
  * Field accessibility
- Query Validation
  * Query depth limits
  * Query complexity analysis
  * Circular query detection
- Mutation Testing
  * Input validation
  * Authorization checks
  * Data manipulation limits

### GraphQL-Specific
- Batch Query Testing
  * Query batching limits
  * Resource consumption
  * Rate limiting effectiveness
- Field Level Security
  * Field authorization
  * Nested field access
  * Field level filtering

## Static Resource Tests

### Resource Access
- Direct Access Testing
  * Path traversal attempts
  * Directory listing
  * File permission validation
- Authorization Testing
  * Resource-level permissions
  * Cross-user access
  * Role-based access
- File Type Testing
  * MIME type validation
  * Extension validation
  * Content validation

### Resource Enumeration
- Directory Testing
  * Directory traversal
  * Hidden file discovery
  * Backup file detection
- Access Control
  * Resource isolation
  * User separation
  * Permission boundaries

## Export Functionality Tests

### Export Injection
- PDF Export Testing
  * HTML injection in PDF
  * JavaScript execution
  * External resource inclusion
- CSV Export Testing
  * Formula injection
  * Macro execution
  * Data exfiltration
- HTML Export Testing
  * Script injection
  * Template manipulation
  * Style injection

### Format Testing
- Parameter Testing
  * Format parameter manipulation
  * Path traversal in exports
  * Template selection
- Content Validation
  * Content-Type verification
  * File format validation
  * Size limitations

## Environment-Specific Tests

### Non-Production Testing
- Environment Detection
  * Development environment discovery
  * Staging environment access
  * Test environment identification
- Security Mechanism Testing
  * Disabled security controls
  * Relaxed validation rules
  * Debug mode detection

### Version Testing
- API Version Analysis
  * Old version discovery
  * Version-specific vulnerabilities
  * Version compatibility issues
- Endpoint Testing
  * Version-specific endpoints
  * Deprecated endpoint access
  * Version bypass attempts

## Best Practices

### Test Execution
1. Always start with specification validation
2. Run core security tests first
3. Follow with specialized tests (GraphQL, Static, Export)
4. End with environment-specific tests

### Test Categories
1. Critical Security Tests
   - Authentication & Authorization
   - Injection Prevention
   - Security Configuration
2. Functional Security Tests
   - Parameter Manipulation
   - Resource Access
   - Export Functionality
3. Environmental Tests
   - Version Testing
   - Environment Detection
   - Configuration Analysis

### Common Vulnerabilities
1. Authentication Bypass
   - Multiple auth endpoint testing
   - Version-specific vulnerabilities
   - Environment-specific bypasses
2. Authorization Issues
   - BOLA (IDOR)
   - Function level authorization
   - Resource access control
3. Injection Vulnerabilities
   - SQL injection
   - Command injection
   - Export injection
4. Configuration Problems
   - CORS misconfigurations
   - Security header issues
   - TLS configuration
