package validator

import (
	"fmt"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/sirupsen/logrus"
)

// OpenAPI3Validator handles OpenAPI 3.0 specification validation
type OpenAPI3Validator struct {
	logger *logrus.Logger
}

// NewOpenAPI3Validator creates a new OpenAPI 3.0 validator instance
func NewOpenAPI3Validator(logger *logrus.Logger) *OpenAPI3Validator {
	return &OpenAPI3Validator{
		logger: logger,
	}
}

// Validate validates an OpenAPI 3.0 specification
func (v *OpenAPI3Validator) Validate(specPath string) (*ValidationResult, error) {
	v.logger.Debug("Validating OpenAPI 3.0 specification")

	// Load and parse the spec
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromFile(specPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load OpenAPI 3.0 spec: %w", err)
	}

	// Initialize validation result
	result := &ValidationResult{
		Valid:   true,
		Errors:  []ValidationError{},
		Methods: []string{},
		Paths:   []string{},
		Info: SpecInfo{
			Title:       doc.Info.Title,
			Version:     doc.Info.Version,
			Description: doc.Info.Description,
			Format:      FormatOpenAPI3,
		},
	}

	// Validate the specification
	if err := doc.Validate(loader.Context); err != nil {
		v.addError(result, ValidationError{
			Message:    fmt.Sprintf("OpenAPI 3.0 validation failed: %v", err),
			Severity:   "error",
			Suggestion: "Fix the validation errors according to OpenAPI 3.0 specification",
		})
	}

	// Extract paths and methods
	if doc.Paths != nil {
		for path, pathItem := range doc.Paths.Map() {
			result.Paths = append(result.Paths, path)
			v.extractMethods(pathItem, result)
		}
	}

	// Validate security schemes
	if doc.Components != nil && doc.Components.SecuritySchemes != nil {
		v.validateSecuritySchemes(doc.Components.SecuritySchemes, result)
	}

	return result, nil
}

// extractMethods extracts HTTP methods from a path item
func (v *OpenAPI3Validator) extractMethods(pathItem *openapi3.PathItem, result *ValidationResult) {
	if pathItem.Get != nil {
		result.Methods = append(result.Methods, "GET")
	}
	if pathItem.Post != nil {
		result.Methods = append(result.Methods, "POST")
	}
	if pathItem.Put != nil {
		result.Methods = append(result.Methods, "PUT")
	}
	if pathItem.Delete != nil {
		result.Methods = append(result.Methods, "DELETE")
	}
	if pathItem.Options != nil {
		result.Methods = append(result.Methods, "OPTIONS")
	}
	if pathItem.Head != nil {
		result.Methods = append(result.Methods, "HEAD")
	}
	if pathItem.Patch != nil {
		result.Methods = append(result.Methods, "PATCH")
	}
	if pathItem.Trace != nil {
		result.Methods = append(result.Methods, "TRACE")
	}
}

// validateSecuritySchemes validates security schemes
func (v *OpenAPI3Validator) validateSecuritySchemes(schemes openapi3.SecuritySchemes, result *ValidationResult) {
	for name, schemeRef := range schemes {
		scheme := schemeRef.Value
		if scheme.Type == "" {
			v.addError(result, ValidationError{
				Path:       fmt.Sprintf("components.securitySchemes.%s", name),
				Message:    "Security scheme missing type",
				Severity:   "error",
				Suggestion: "Add a type field to the security scheme",
			})
			continue
		}

		switch scheme.Type {
		case "oauth2":
			if scheme.Flows == nil {
				v.addError(result, ValidationError{
					Path:       fmt.Sprintf("components.securitySchemes.%s", name),
					Message:    "OAuth2 security scheme missing flows",
					Severity:   "error",
					Suggestion: "Add flows configuration to the OAuth2 security scheme",
				})
			}
		case "apiKey":
			if scheme.Name == "" || scheme.In == "" {
				v.addError(result, ValidationError{
					Path:       fmt.Sprintf("components.securitySchemes.%s", name),
					Message:    "API key security scheme missing name or location",
					Severity:   "error",
					Suggestion: "Add name and in fields to the API key security scheme",
				})
			}
		case "http":
			if scheme.Scheme == "" {
				v.addError(result, ValidationError{
					Path:       fmt.Sprintf("components.securitySchemes.%s", name),
					Message:    "HTTP security scheme missing scheme",
					Severity:   "error",
					Suggestion: "Add scheme field to the HTTP security scheme",
				})
			}
		}
	}
}

// addError adds a validation error to the result
func (v *OpenAPI3Validator) addError(result *ValidationResult, err ValidationError) {
	result.Valid = false
	result.Errors = append(result.Errors, err)
}
