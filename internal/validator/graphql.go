package validator

import (
	"fmt"
	"os"

	"github.com/graphql-go/graphql/language/ast"
	"github.com/graphql-go/graphql/language/parser"
	"github.com/graphql-go/graphql/language/source"
	"github.com/sirupsen/logrus"
)

// GraphQLValidator handles GraphQL schema validation
type GraphQLValidator struct {
	logger *logrus.Logger
}

// NewGraphQLValidator creates a new GraphQL validator instance
func NewGraphQLValidator(logger *logrus.Logger) *GraphQLValidator {
	return &GraphQLValidator{
		logger: logger,
	}
}

// Validate validates a GraphQL schema
func (v *GraphQLValidator) Validate(schemaPath string) (*ValidationResult, error) {
	v.logger.Debug("Validating GraphQL schema")

	// Read schema file
	content, err := os.ReadFile(schemaPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read schema file: %w", err)
	}

	// Parse schema
	src := source.NewSource(&source.Source{
		Body: content,
		Name: schemaPath,
	})
	doc, err := parser.Parse(parser.ParseParams{Source: src})
	if err != nil {
		return nil, fmt.Errorf("failed to parse GraphQL schema: %w", err)
	}

	// Initialize validation result
	result := &ValidationResult{
		Valid:   true,
		Errors:  []ValidationError{},
		Methods: []string{},
		Paths:   []string{},
	}

	// Extract schema information and validate
	v.validateDocument(doc, result)

	return result, nil
}

// validateDocument validates the entire GraphQL document
func (v *GraphQLValidator) validateDocument(doc *ast.Document, result *ValidationResult) {
	for _, def := range doc.Definitions {
		switch def := def.(type) {
		case *ast.SchemaDefinition:
			v.validateSchemaDefinition(def, result)
		case *ast.ObjectDefinition:
			v.validateObject(def, result)
		case *ast.InterfaceDefinition:
			v.validateInterface(def, result)
		case *ast.UnionDefinition:
			v.validateUnion(def, result)
		case *ast.EnumDefinition:
			v.validateEnum(def, result)
		case *ast.InputObjectDefinition:
			v.validateInputObject(def, result)
		case *ast.DirectiveDefinition:
			v.validateDirective(def, result)
		}
	}
}

// validateSchemaDefinition validates the schema definition
func (v *GraphQLValidator) validateSchemaDefinition(schema *ast.SchemaDefinition, result *ValidationResult) {
	for _, op := range schema.OperationTypes {
		result.Methods = append(result.Methods, string(op.Operation))
	}
}

// validateObject validates an object type definition
func (v *GraphQLValidator) validateObject(obj *ast.ObjectDefinition, result *ValidationResult) {
	// Add type name to paths
	result.Paths = append(result.Paths, obj.Name.Value)

	// Check for empty objects
	if len(obj.Fields) == 0 {
		v.addError(result, ValidationError{
			Path:       obj.Name.Value,
			Message:    fmt.Sprintf("Object type '%s' has no fields", obj.Name.Value),
			Severity:   "error",
			Suggestion: "Add at least one field to the object type",
		})
	}

	// Check for proper naming convention
	if !isValidName(obj.Name.Value) {
		v.addError(result, ValidationError{
			Path:       obj.Name.Value,
			Message:    fmt.Sprintf("Invalid object type name '%s'", obj.Name.Value),
			Severity:   "warning",
			Suggestion: "Use PascalCase for type names",
		})
	}

	// Validate fields
	for _, field := range obj.Fields {
		v.validateField(field, obj.Name.Value, result)
	}
}

// validateField validates a field definition
func (v *GraphQLValidator) validateField(field *ast.FieldDefinition, parentName string, result *ValidationResult) {
	// Check for proper naming convention
	if !isValidFieldName(field.Name.Value) {
		v.addError(result, ValidationError{
			Path:       fmt.Sprintf("%s.%s", parentName, field.Name.Value),
			Message:    fmt.Sprintf("Invalid field name '%s'", field.Name.Value),
			Severity:   "warning",
			Suggestion: "Use camelCase for field names",
		})
	}

	// Add field path for root types
	if parentName == "Query" || parentName == "Mutation" || parentName == "Subscription" {
		result.Paths = append(result.Paths, field.Name.Value)
	}
}

// validateDirective validates a directive definition
func (v *GraphQLValidator) validateDirective(dir *ast.DirectiveDefinition, result *ValidationResult) {
	// Check for proper naming convention
	if !isValidDirectiveName(dir.Name.Value) {
		v.addError(result, ValidationError{
			Path:       dir.Name.Value,
			Message:    fmt.Sprintf("Invalid directive name '@%s'", dir.Name.Value),
			Severity:   "warning",
			Suggestion: "Use camelCase for directive names",
		})
	}
}

// validateInputObject validates an input object definition
func (v *GraphQLValidator) validateInputObject(input *ast.InputObjectDefinition, result *ValidationResult) {
	// Check for empty input objects
	if len(input.Fields) == 0 {
		v.addError(result, ValidationError{
			Path:       input.Name.Value,
			Message:    fmt.Sprintf("Input object '%s' has no fields", input.Name.Value),
			Severity:   "error",
			Suggestion: "Add at least one field to the input object",
		})
	}
}

// validateInterface validates an interface definition
func (v *GraphQLValidator) validateInterface(iface *ast.InterfaceDefinition, result *ValidationResult) {
	// Check for empty interfaces
	if len(iface.Fields) == 0 {
		v.addError(result, ValidationError{
			Path:       iface.Name.Value,
			Message:    fmt.Sprintf("Interface '%s' has no fields", iface.Name.Value),
			Severity:   "error",
			Suggestion: "Add at least one field to the interface",
		})
	}
}

// validateUnion validates a union definition
func (v *GraphQLValidator) validateUnion(union *ast.UnionDefinition, result *ValidationResult) {
	// Check for empty unions
	if len(union.Types) == 0 {
		v.addError(result, ValidationError{
			Path:       union.Name.Value,
			Message:    fmt.Sprintf("Union '%s' has no member types", union.Name.Value),
			Severity:   "error",
			Suggestion: "Add at least one member type to the union",
		})
	}
}

// validateEnum validates an enum definition
func (v *GraphQLValidator) validateEnum(enum *ast.EnumDefinition, result *ValidationResult) {
	// Check for empty enums
	if len(enum.Values) == 0 {
		v.addError(result, ValidationError{
			Path:       enum.Name.Value,
			Message:    fmt.Sprintf("Enum '%s' has no values", enum.Name.Value),
			Severity:   "error",
			Suggestion: "Add at least one value to the enum",
		})
	}
}

// Helper functions

func (v *GraphQLValidator) addError(result *ValidationResult, err ValidationError) {
	result.Valid = false
	result.Errors = append(result.Errors, err)
}

func isValidName(name string) bool {
	return len(name) > 0 && name[0] >= 'A' && name[0] <= 'Z'
}

func isValidFieldName(name string) bool {
	return len(name) > 0 && name[0] >= 'a' && name[0] <= 'z'
}

func isValidDirectiveName(name string) bool {
	return len(name) > 0 && name[0] >= 'a' && name[0] <= 'z'
}
