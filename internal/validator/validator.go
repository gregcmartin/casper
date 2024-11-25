package validator

import (
	"fmt"

	"github.com/go-openapi/loads"
	"github.com/go-openapi/spec"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/validate"
	"github.com/sirupsen/logrus"
)

// Validator handles OpenAPI specification validation
type Validator struct {
	logger *logrus.Logger
}

// New creates a new Validator instance
func New(logger *logrus.Logger) *Validator {
	return &Validator{
		logger: logger,
	}
}

// ValidateSpec validates an OpenAPI specification file
func (v *Validator) ValidateSpec(specPath string) error {
	v.logger.Infof("Starting validation of OpenAPI spec: %s", specPath)

	// Load the specification
	doc, err := loads.Spec(specPath)
	if err != nil {
		return fmt.Errorf("failed to load spec file: %w", err)
	}
	v.logger.Debug("Successfully loaded spec file")

	// Expand spec with full validation
	if err := spec.ExpandSpec(doc.Spec(), &spec.ExpandOptions{RelativeBase: specPath}); err != nil {
		return fmt.Errorf("failed to expand spec: %w", err)
	}

	// Create validator
	validator := validate.NewSpecValidator(doc.Schema(), strfmt.Default)

	// Validate the specification
	result, _ := validator.Validate(doc)
	if result != nil && result.HasErrors() {
		return fmt.Errorf("specification validation failed: %v", result.Errors)
	}

	// Validate basic structure
	v.logger.Debug("Validating basic structure")
	if err := v.validateBasicStructure(doc); err != nil {
		return fmt.Errorf("structure validation failed: %w", err)
	}
	v.logger.Debug("Basic structure validation passed")

	// Validate security definitions
	v.logger.Debug("Validating security definitions")
	if err := v.validateSecurityDefinitions(doc); err != nil {
		return fmt.Errorf("security validation failed: %w", err)
	}
	v.logger.Debug("Security definitions validation passed")

	v.logger.WithFields(logrus.Fields{
		"title":   doc.Spec().Info.Title,
		"version": doc.Spec().Info.Version,
		"paths":   len(doc.Spec().Paths.Paths),
	}).Info("OpenAPI specification is valid")

	return nil
}

// validateBasicStructure checks the basic required fields of the OpenAPI spec
func (v *Validator) validateBasicStructure(doc *loads.Document) error {
	spec := doc.Spec()

	if spec.Info == nil {
		return fmt.Errorf("missing info section")
	}

	if spec.Info.Title == "" {
		return fmt.Errorf("missing API title")
	}

	if spec.Info.Version == "" {
		return fmt.Errorf("missing API version")
	}

	if len(spec.Paths.Paths) == 0 {
		return fmt.Errorf("no paths defined in the specification")
	}

	v.logger.WithFields(logrus.Fields{
		"title":   spec.Info.Title,
		"version": spec.Info.Version,
		"paths":   len(spec.Paths.Paths),
	}).Debug("Structure details")

	return nil
}

// validateSecurityDefinitions checks the security definitions in the spec
func (v *Validator) validateSecurityDefinitions(doc *loads.Document) error {
	spec := doc.Spec()

	// Check if security schemes are properly defined
	if spec.SecurityDefinitions != nil {
		for name, scheme := range spec.SecurityDefinitions {
			v.logger.WithFields(logrus.Fields{
				"name": name,
				"type": scheme.Type,
			}).Debug("Validating security scheme")

			if scheme.Type == "" {
				return fmt.Errorf("security scheme %s missing type", name)
			}

			// Validate based on security type
			switch scheme.Type {
			case "oauth2":
				if scheme.Flow == "" {
					return fmt.Errorf("oauth2 security scheme %s missing flow", name)
				}
			case "apiKey":
				if scheme.Name == "" || scheme.In == "" {
					return fmt.Errorf("apiKey security scheme %s missing name or location", name)
				}
			}
		}
	}

	return nil
}
