package validator

import (
	"fmt"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
)

// BlueprintValidator handles API Blueprint specification validation
type BlueprintValidator struct {
	logger *logrus.Logger
}

// NewBlueprintValidator creates a new API Blueprint validator instance
func NewBlueprintValidator(logger *logrus.Logger) *BlueprintValidator {
	return &BlueprintValidator{
		logger: logger,
	}
}

// BlueprintDocument represents an API Blueprint document
type BlueprintDocument struct {
	Format      string
	Version     string
	Host        string
	Title       string
	Description string
	Groups      []BlueprintResourceGroup
}

// BlueprintResourceGroup represents a group of resources in API Blueprint
type BlueprintResourceGroup struct {
	Name        string
	Description string
	Resources   []BlueprintResource
}

// BlueprintResource represents an API Blueprint resource
type BlueprintResource struct {
	Name        string
	Description string
	URITemplate string
	Actions     []BlueprintAction
}

// BlueprintAction represents an API Blueprint action (HTTP method)
type BlueprintAction struct {
	Name        string
	Method      string
	Description string
	Parameters  []BlueprintParameter
	Headers     map[string]string
	Examples    []BlueprintExample
}

// BlueprintParameter represents an API Blueprint parameter
type BlueprintParameter struct {
	Name        string
	Type        string
	Required    bool
	Description string
}

// BlueprintExample represents an API Blueprint request/response example
type BlueprintExample struct {
	Name        string
	Description string
	Request     BlueprintMessage
	Response    BlueprintMessage
}

// BlueprintMessage represents an API Blueprint request or response
type BlueprintMessage struct {
	Headers map[string]string
	Body    string
}

// Validate validates an API Blueprint specification
func (v *BlueprintValidator) Validate(specPath string) (*ValidationResult, error) {
	v.logger.Debug("Validating API Blueprint specification")

	// Read API Blueprint file
	content, err := os.ReadFile(specPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read API Blueprint file: %w", err)
	}

	// Parse API Blueprint document
	doc, err := v.parseBlueprint(string(content))
	if err != nil {
		return nil, fmt.Errorf("failed to parse API Blueprint: %w", err)
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
			Description: doc.Description,
			Format:      FormatBlueprint,
		},
	}

	// Validate basic structure
	if err := v.validateBasicStructure(doc, result); err != nil {
		return nil, err
	}

	// Validate resource groups
	v.validateResourceGroups(doc.Groups, result)

	return result, nil
}

// parseBlueprint parses an API Blueprint document
func (v *BlueprintValidator) parseBlueprint(content string) (*BlueprintDocument, error) {
	// Parse the content using API Blueprint parser
	// For now, return a mock document for structure demonstration
	doc := &BlueprintDocument{
		Format:  "1A",
		Version: "1.0",
		Title:   "Example API",
		Groups:  []BlueprintResourceGroup{},
	}

	// TODO: Implement actual parsing using API Blueprint parser
	return doc, nil
}

// validateBasicStructure validates the basic API Blueprint structure
func (v *BlueprintValidator) validateBasicStructure(doc *BlueprintDocument, result *ValidationResult) error {
	if doc.Title == "" {
		v.addError(result, ValidationError{
			Message:    "Missing API title",
			Severity:   "error",
			Suggestion: "Add a title to the API Blueprint specification",
		})
	}

	if doc.Format == "" {
		v.addError(result, ValidationError{
			Message:    "Missing FORMAT section",
			Severity:   "error",
			Suggestion: "Add FORMAT: 1A at the beginning of the document",
		})
	}

	return nil
}

// validateResourceGroups validates API Blueprint resource groups
func (v *BlueprintValidator) validateResourceGroups(groups []BlueprintResourceGroup, result *ValidationResult) {
	for _, group := range groups {
		if group.Name == "" {
			v.addError(result, ValidationError{
				Message:    "Resource group missing name",
				Severity:   "warning",
				Suggestion: "Add a name to the resource group",
			})
		}

		// Validate resources in the group
		v.validateResources(group.Resources, result)
	}
}

// validateResources validates API Blueprint resources
func (v *BlueprintValidator) validateResources(resources []BlueprintResource, result *ValidationResult) {
	for _, resource := range resources {
		if resource.URITemplate == "" {
			v.addError(result, ValidationError{
				Path:       resource.Name,
				Message:    "Resource missing URI template",
				Severity:   "error",
				Suggestion: "Add a URI template to the resource",
			})
		}

		result.Paths = append(result.Paths, resource.URITemplate)

		// Validate actions
		v.validateActions(resource.Actions, resource.URITemplate, result)
	}
}

// validateActions validates API Blueprint actions
func (v *BlueprintValidator) validateActions(actions []BlueprintAction, path string, result *ValidationResult) {
	for _, action := range actions {
		if action.Method == "" {
			v.addError(result, ValidationError{
				Path:       path,
				Message:    "Action missing HTTP method",
				Severity:   "error",
				Suggestion: "Add an HTTP method to the action",
			})
		}

		result.Methods = append(result.Methods, strings.ToUpper(action.Method))

		// Validate parameters
		v.validateParameters(action.Parameters, path, result)

		// Validate examples
		v.validateExamples(action.Examples, path, result)
	}
}

// validateParameters validates API Blueprint parameters
func (v *BlueprintValidator) validateParameters(params []BlueprintParameter, path string, result *ValidationResult) {
	for _, param := range params {
		if param.Name == "" {
			v.addError(result, ValidationError{
				Path:       path,
				Message:    "Parameter missing name",
				Severity:   "error",
				Suggestion: "Add a name to the parameter",
			})
		}

		if param.Type == "" {
			v.addError(result, ValidationError{
				Path:       fmt.Sprintf("%s.%s", path, param.Name),
				Message:    "Parameter missing type",
				Severity:   "warning",
				Suggestion: "Add a type to the parameter",
			})
		}
	}
}

// validateExamples validates API Blueprint examples
func (v *BlueprintValidator) validateExamples(examples []BlueprintExample, path string, result *ValidationResult) {
	for _, example := range examples {
		// Validate request
		if example.Request.Body != "" && len(example.Request.Headers) == 0 {
			v.addError(result, ValidationError{
				Path:       path,
				Message:    "Request example missing headers",
				Severity:   "warning",
				Suggestion: "Add Content-Type header to the request example",
			})
		}

		// Validate response
		if example.Response.Body != "" && len(example.Response.Headers) == 0 {
			v.addError(result, ValidationError{
				Path:       path,
				Message:    "Response example missing headers",
				Severity:   "warning",
				Suggestion: "Add Content-Type header to the response example",
			})
		}
	}
}

// addError adds a validation error to the result
func (v *BlueprintValidator) addError(result *ValidationResult, err ValidationError) {
	result.Valid = false
	result.Errors = append(result.Errors, err)
}
