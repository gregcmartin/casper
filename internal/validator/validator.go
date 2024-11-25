package validator

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

// Validator handles API specification validation
type Validator struct {
	logger             *logrus.Logger
	swagger2Validator  *Swagger2Validator
	openapi3Validator  *OpenAPI3Validator
	asyncValidator     *AsyncAPIValidator
	graphqlValidator   *GraphQLValidator
	ramlValidator      *RAMLValidator
	blueprintValidator *BlueprintValidator
}

// New creates a new Validator instance
func New(logger *logrus.Logger) *Validator {
	return &Validator{
		logger:             logger,
		swagger2Validator:  NewSwagger2Validator(logger),
		openapi3Validator:  NewOpenAPI3Validator(logger),
		asyncValidator:     NewAsyncAPIValidator(logger),
		graphqlValidator:   NewGraphQLValidator(logger),
		ramlValidator:      NewRAMLValidator(logger),
		blueprintValidator: NewBlueprintValidator(logger),
	}
}

// ValidateSpec validates an API specification file
func (v *Validator) ValidateSpec(specPath string) error {
	v.logger.Infof("Starting validation of API spec: %s", specPath)

	// Detect format
	format, err := v.detectFormat(specPath)
	if err != nil {
		return fmt.Errorf("format detection failed: %w", err)
	}
	v.logger.Infof("Detected specification format: %s", format)

	var result *ValidationResult
	switch format {
	case FormatSwagger2:
		result, err = v.swagger2Validator.Validate(specPath)
	case FormatOpenAPI3:
		result, err = v.openapi3Validator.Validate(specPath)
	case FormatAsyncAPI:
		result, err = v.asyncValidator.Validate(specPath)
	case FormatGraphQL:
		result, err = v.graphqlValidator.Validate(specPath)
	case FormatRAML:
		result, err = v.ramlValidator.Validate(specPath)
	case FormatBlueprint:
		result, err = v.blueprintValidator.Validate(specPath)
	default:
		return fmt.Errorf("unsupported specification format")
	}

	if err != nil {
		return err
	}

	// Log validation results
	v.logValidationResult(result)

	return nil
}

// detectFormat determines the API specification format
func (v *Validator) detectFormat(specPath string) (SpecFormat, error) {
	data, err := os.ReadFile(specPath)
	if err != nil {
		return "", fmt.Errorf("failed to read spec file: %w", err)
	}

	content := string(data)

	// Check file extension first
	switch {
	case strings.HasSuffix(specPath, ".graphql"):
		return FormatGraphQL, nil
	case strings.HasSuffix(specPath, ".apib"):
		return FormatBlueprint, nil
	}

	// Check for RAML header
	if strings.HasPrefix(strings.TrimSpace(content), "#%RAML") {
		return FormatRAML, nil
	}

	// Check for API Blueprint format header
	if strings.HasPrefix(strings.TrimSpace(content), "FORMAT: 1A") {
		return FormatBlueprint, nil
	}

	// Try to parse as JSON/YAML
	var spec struct {
		Swagger  string `json:"swagger" yaml:"swagger"`
		OpenAPI  string `json:"openapi" yaml:"openapi"`
		AsyncAPI string `json:"asyncapi" yaml:"asyncapi"`
	}

	// Try JSON first
	if err := json.Unmarshal(data, &spec); err != nil {
		// If JSON fails, try YAML
		if err := yaml.Unmarshal(data, &spec); err != nil {
			// If both fail, check for GraphQL schema
			if strings.Contains(content, "type Query") || strings.Contains(content, "schema {") {
				return FormatGraphQL, nil
			}
			return "", fmt.Errorf("failed to parse spec file")
		}
	}

	switch {
	case spec.Swagger == "2.0":
		return FormatSwagger2, nil
	case strings.HasPrefix(spec.OpenAPI, "3."):
		return FormatOpenAPI3, nil
	case spec.AsyncAPI != "":
		return FormatAsyncAPI, nil
	}

	return "", fmt.Errorf("unable to determine specification format")
}

// logValidationResult logs the validation results
func (v *Validator) logValidationResult(result *ValidationResult) {
	if !result.Valid {
		v.logger.Warn("Validation failed with errors:")
		for _, err := range result.Errors {
			v.logger.WithFields(logrus.Fields{
				"path":       err.Path,
				"severity":   err.Severity,
				"suggestion": err.Suggestion,
			}).Warn(err.Message)
		}
		return
	}

	v.logger.WithFields(logrus.Fields{
		"title":   result.Info.Title,
		"version": result.Info.Version,
		"format":  result.Info.Format,
		"paths":   len(result.Paths),
		"methods": len(result.Methods),
	}).Info("API specification is valid")
}
