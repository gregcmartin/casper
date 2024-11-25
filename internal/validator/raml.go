package validator

import (
	"fmt"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

// RAMLValidator handles RAML specification validation
type RAMLValidator struct {
	logger *logrus.Logger
}

// NewRAMLValidator creates a new RAML validator instance
func NewRAMLValidator(logger *logrus.Logger) *RAMLValidator {
	return &RAMLValidator{
		logger: logger,
	}
}

// RAMLDocument represents a RAML specification
type RAMLDocument struct {
	Title           string                    `yaml:"title"`
	Version         string                    `yaml:"version"`
	BaseURI         string                    `yaml:"baseUri"`
	MediaType       string                    `yaml:"mediaType"`
	SecuritySchemes map[string]SecurityScheme `yaml:"securitySchemes"`
	Types           map[string]interface{}    `yaml:"types"`
	Resources       map[string]RAMLResource   `yaml:"resources"`
}

// RAMLResource represents a RAML resource
type RAMLResource struct {
	Description string                  `yaml:"description"`
	Methods     map[string]RAMLMethod   `yaml:"methods"`
	Resources   map[string]RAMLResource `yaml:"resources"`
}

// RAMLMethod represents a RAML method
type RAMLMethod struct {
	Description string                  `yaml:"description"`
	Headers     map[string]interface{}  `yaml:"headers"`
	QueryParams map[string]interface{}  `yaml:"queryParameters"`
	Body        map[string]interface{}  `yaml:"body"`
	Responses   map[string]RAMLResponse `yaml:"responses"`
}

// RAMLResponse represents a RAML response
type RAMLResponse struct {
	Description string                 `yaml:"description"`
	Headers     map[string]interface{} `yaml:"headers"`
	Body        map[string]interface{} `yaml:"body"`
}

// Validate validates a RAML specification
func (v *RAMLValidator) Validate(specPath string) (*ValidationResult, error) {
	v.logger.Debug("Validating RAML specification")

	// Read RAML file
	content, err := os.ReadFile(specPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read RAML file: %w", err)
	}

	// Parse RAML document
	var doc RAMLDocument
	if err := yaml.Unmarshal(content, &doc); err != nil {
		return nil, fmt.Errorf("failed to parse RAML document: %w", err)
	}

	// Initialize validation result
	result := &ValidationResult{
		Valid:   true,
		Errors:  []ValidationError{},
		Methods: []string{},
		Paths:   []string{},
		Info: SpecInfo{
			Title:       doc.Title,
			Version:     doc.Version,
			Description: "", // RAML doesn't have a top-level description
			Format:      FormatRAML,
		},
	}

	// Validate basic structure
	if err := v.validateBasicStructure(&doc, result); err != nil {
		return nil, err
	}

	// Validate resources
	v.validateResources(doc.Resources, "", result)

	// Validate security schemes
	v.validateSecuritySchemes(doc.SecuritySchemes, result)

	// Validate types
	v.validateTypes(doc.Types, result)

	return result, nil
}

// validateBasicStructure validates the basic RAML structure
func (v *RAMLValidator) validateBasicStructure(doc *RAMLDocument, result *ValidationResult) error {
	if doc.Title == "" {
		v.addError(result, ValidationError{
			Message:    "Missing API title",
			Severity:   "error",
			Suggestion: "Add a title field to the RAML specification",
		})
	}

	if doc.Version == "" {
		v.addError(result, ValidationError{
			Message:    "Missing API version",
			Severity:   "warning",
			Suggestion: "Add a version field to the RAML specification",
		})
	}

	if doc.BaseURI == "" {
		v.addError(result, ValidationError{
			Message:    "Missing baseUri",
			Severity:   "warning",
			Suggestion: "Add a baseUri field to the RAML specification",
		})
	}

	return nil
}

// validateResources validates RAML resources recursively
func (v *RAMLValidator) validateResources(resources map[string]RAMLResource, parentPath string, result *ValidationResult) {
	for path, resource := range resources {
		fullPath := parentPath + path
		result.Paths = append(result.Paths, fullPath)

		// Validate methods
		for method, methodDef := range resource.Methods {
			result.Methods = append(result.Methods, strings.ToUpper(method))
			v.validateMethod(method, methodDef, fullPath, result)
		}

		// Recursively validate nested resources
		if resource.Resources != nil {
			v.validateResources(resource.Resources, fullPath, result)
		}
	}
}

// validateMethod validates a RAML method
func (v *RAMLValidator) validateMethod(method string, methodDef RAMLMethod, path string, result *ValidationResult) {
	// Validate method description
	if methodDef.Description == "" {
		v.addError(result, ValidationError{
			Path:       path,
			Message:    fmt.Sprintf("Missing description for method %s", method),
			Severity:   "warning",
			Suggestion: "Add a description to the method",
		})
	}

	// Validate responses
	if len(methodDef.Responses) == 0 {
		v.addError(result, ValidationError{
			Path:       path,
			Message:    fmt.Sprintf("No responses defined for method %s", method),
			Severity:   "error",
			Suggestion: "Add at least one response definition",
		})
	}

	// Validate request body if it's a POST or PUT method
	if (method == "post" || method == "put") && len(methodDef.Body) == 0 {
		v.addError(result, ValidationError{
			Path:       path,
			Message:    fmt.Sprintf("No request body defined for %s method", method),
			Severity:   "warning",
			Suggestion: "Add a request body definition",
		})
	}
}

// validateSecuritySchemes validates RAML security schemes
func (v *RAMLValidator) validateSecuritySchemes(schemes map[string]SecurityScheme, result *ValidationResult) {
	for name, scheme := range schemes {
		if scheme.Type == "" {
			v.addError(result, ValidationError{
				Path:       fmt.Sprintf("securitySchemes.%s", name),
				Message:    "Missing security scheme type",
				Severity:   "error",
				Suggestion: "Add a type field to the security scheme",
			})
		}
	}
}

// validateTypes validates RAML type definitions
func (v *RAMLValidator) validateTypes(types map[string]interface{}, result *ValidationResult) {
	for name, typeDef := range types {
		if typeDef == nil {
			v.addError(result, ValidationError{
				Path:       fmt.Sprintf("types.%s", name),
				Message:    "Empty type definition",
				Severity:   "error",
				Suggestion: "Add properties to the type definition",
			})
		}
	}
}

// addError adds a validation error to the result
func (v *RAMLValidator) addError(result *ValidationResult, err ValidationError) {
	result.Valid = false
	result.Errors = append(result.Errors, err)
}
