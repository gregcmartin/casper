package validator

import (
	"fmt"

	"github.com/go-openapi/loads"
	"github.com/go-openapi/spec"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/validate"
	"github.com/sirupsen/logrus"
)

// Swagger2Validator handles Swagger 2.0 specification validation
type Swagger2Validator struct {
	logger *logrus.Logger
}

// NewSwagger2Validator creates a new Swagger 2.0 validator instance
func NewSwagger2Validator(logger *logrus.Logger) *Swagger2Validator {
	return &Swagger2Validator{
		logger: logger,
	}
}

// Validate validates a Swagger 2.0 specification
func (v *Swagger2Validator) Validate(specPath string) (*ValidationResult, error) {
	v.logger.Debug("Validating Swagger 2.0 specification")

	// Load the specification
	doc, err := loads.Spec(specPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load Swagger 2.0 spec: %w", err)
	}

	// Expand spec with full validation
	if err := spec.ExpandSpec(doc.Spec(), &spec.ExpandOptions{RelativeBase: specPath}); err != nil {
		return nil, fmt.Errorf("failed to expand spec: %w", err)
	}

	// Create validator
	validator := validate.NewSpecValidator(doc.Schema(), strfmt.Default)

	// Initialize validation result
	result := &ValidationResult{
		Valid:   true,
		Errors:  []ValidationError{},
		Methods: []string{},
		Paths:   []string{},
		Info: SpecInfo{
			Title:       doc.Spec().Info.Title,
			Version:     doc.Spec().Info.Version,
			Description: doc.Spec().Info.Description,
			Format:      FormatSwagger2,
		},
	}

	// Validate the specification
	validationResult, _ := validator.Validate(doc)
	if validationResult != nil && validationResult.HasErrors() {
		for _, validationError := range validationResult.Errors {
			v.addError(result, ValidationError{
				Path:       fmt.Sprintf("spec.%s", validationError),
				Message:    validationError.Error(),
				Severity:   "error",
				Suggestion: "Fix the validation error according to Swagger 2.0 specification",
			})
		}
	}

	// Extract paths and methods
	for path, pathItem := range doc.Spec().Paths.Paths {
		result.Paths = append(result.Paths, path)
		v.extractMethods(pathItem, result)
	}

	// Validate security definitions
	v.validateSecurityDefinitions(doc.Spec().SecurityDefinitions, result)

	return result, nil
}

// extractMethods extracts HTTP methods from a path item
func (v *Swagger2Validator) extractMethods(pathItem spec.PathItem, result *ValidationResult) {
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
}

// validateSecurityDefinitions validates security definitions
func (v *Swagger2Validator) validateSecurityDefinitions(secDefs spec.SecurityDefinitions, result *ValidationResult) {
	if secDefs != nil {
		for name, scheme := range secDefs {
			if scheme.Type == "" {
				v.addError(result, ValidationError{
					Path:       fmt.Sprintf("securityDefinitions.%s", name),
					Message:    "Security scheme missing type",
					Severity:   "error",
					Suggestion: "Add a type field to the security scheme",
				})
				continue
			}

			switch scheme.Type {
			case "oauth2":
				if scheme.Flow == "" {
					v.addError(result, ValidationError{
						Path:       fmt.Sprintf("securityDefinitions.%s", name),
						Message:    "OAuth2 security scheme missing flow",
						Severity:   "error",
						Suggestion: "Add a flow field to the OAuth2 security scheme",
					})
				}
			case "apiKey":
				if scheme.Name == "" || scheme.In == "" {
					v.addError(result, ValidationError{
						Path:       fmt.Sprintf("securityDefinitions.%s", name),
						Message:    "API key security scheme missing name or location",
						Severity:   "error",
						Suggestion: "Add name and in fields to the API key security scheme",
					})
				}
			}
		}
	}
}

// addError adds a validation error to the result
func (v *Swagger2Validator) addError(result *ValidationResult, err ValidationError) {
	result.Valid = false
	result.Errors = append(result.Errors, err)
}
