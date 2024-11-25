package validator

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

// AsyncAPIValidator handles AsyncAPI specification validation
type AsyncAPIValidator struct {
	logger *logrus.Logger
}

// NewAsyncAPIValidator creates a new AsyncAPI validator instance
func NewAsyncAPIValidator(logger *logrus.Logger) *AsyncAPIValidator {
	return &AsyncAPIValidator{
		logger: logger,
	}
}

// AsyncAPIDocument represents an AsyncAPI specification
type AsyncAPIDocument struct {
	AsyncAPI   string             `json:"asyncapi" yaml:"asyncapi"`
	Info       AsyncAPIInfo       `json:"info" yaml:"info"`
	Channels   map[string]Channel `json:"channels" yaml:"channels"`
	Components *Components        `json:"components,omitempty" yaml:"components,omitempty"`
	Servers    map[string]Server  `json:"servers,omitempty" yaml:"servers,omitempty"`
}

type AsyncAPIInfo struct {
	Title       string `json:"title" yaml:"title"`
	Version     string `json:"version" yaml:"version"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
}

type Channel struct {
	Description string     `json:"description,omitempty" yaml:"description,omitempty"`
	Subscribe   *Operation `json:"subscribe,omitempty" yaml:"subscribe,omitempty"`
	Publish     *Operation `json:"publish,omitempty" yaml:"publish,omitempty"`
}

type Operation struct {
	Summary     string                `json:"summary,omitempty" yaml:"summary,omitempty"`
	Description string                `json:"description,omitempty" yaml:"description,omitempty"`
	Message     *Message              `json:"message,omitempty" yaml:"message,omitempty"`
	Security    []map[string][]string `json:"security,omitempty" yaml:"security,omitempty"`
}

type Message struct {
	Name        string                 `json:"name,omitempty" yaml:"name,omitempty"`
	Title       string                 `json:"title,omitempty" yaml:"title,omitempty"`
	Summary     string                 `json:"summary,omitempty" yaml:"summary,omitempty"`
	Description string                 `json:"description,omitempty" yaml:"description,omitempty"`
	Payload     map[string]interface{} `json:"payload,omitempty" yaml:"payload,omitempty"`
}

type Components struct {
	Messages        map[string]Message        `json:"messages,omitempty" yaml:"messages,omitempty"`
	SecuritySchemes map[string]SecurityScheme `json:"securitySchemes,omitempty" yaml:"securitySchemes,omitempty"`
}

type Server struct {
	URL         string                `json:"url" yaml:"url"`
	Protocol    string                `json:"protocol" yaml:"protocol"`
	Description string                `json:"description,omitempty" yaml:"description,omitempty"`
	Security    []map[string][]string `json:"security,omitempty" yaml:"security,omitempty"`
}

// Validate validates an AsyncAPI specification
func (v *AsyncAPIValidator) Validate(specPath string) (*ValidationResult, error) {
	v.logger.Debug("Validating AsyncAPI specification")

	// Read the file content
	content, err := os.ReadFile(specPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read AsyncAPI spec: %w", err)
	}

	// Parse the AsyncAPI document
	var doc AsyncAPIDocument
	if strings.HasSuffix(specPath, ".json") {
		if err := json.Unmarshal(content, &doc); err != nil {
			return nil, fmt.Errorf("failed to parse AsyncAPI JSON: %w", err)
		}
	} else {
		if err := yaml.Unmarshal(content, &doc); err != nil {
			return nil, fmt.Errorf("failed to parse AsyncAPI YAML: %w", err)
		}
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
			Format:      FormatAsyncAPI,
		},
	}

	// Validate basic structure
	if err := v.validateBasicStructure(&doc, result); err != nil {
		return result, err
	}

	// Validate channels
	v.validateChannels(doc.Channels, result)

	// Validate servers
	v.validateServers(doc.Servers, result)

	// Validate components
	if doc.Components != nil {
		v.validateComponents(doc.Components, result)
	}

	return result, nil
}

func (v *AsyncAPIValidator) validateBasicStructure(doc *AsyncAPIDocument, result *ValidationResult) error {
	if !strings.HasPrefix(doc.AsyncAPI, "2.") {
		v.addError(result, ValidationError{
			Message:    fmt.Sprintf("Unsupported AsyncAPI version: %s", doc.AsyncAPI),
			Severity:   "error",
			Suggestion: "Use AsyncAPI version 2.x",
		})
	}

	if doc.Info.Title == "" {
		v.addError(result, ValidationError{
			Message:    "Missing API title",
			Severity:   "error",
			Suggestion: "Add a title in the info section",
		})
	}

	if doc.Info.Version == "" {
		v.addError(result, ValidationError{
			Message:    "Missing API version",
			Severity:   "error",
			Suggestion: "Add a version in the info section",
		})
	}

	return nil
}

func (v *AsyncAPIValidator) validateChannels(channels map[string]Channel, result *ValidationResult) {
	for channelName, channel := range channels {
		result.Paths = append(result.Paths, channelName)

		if channel.Subscribe != nil {
			result.Methods = append(result.Methods, "subscribe")
			v.validateOperation(channel.Subscribe, channelName, "subscribe", result)
		}

		if channel.Publish != nil {
			result.Methods = append(result.Methods, "publish")
			v.validateOperation(channel.Publish, channelName, "publish", result)
		}
	}
}

func (v *AsyncAPIValidator) validateOperation(op *Operation, channelName, opType string, result *ValidationResult) {
	if op.Message == nil {
		v.addError(result, ValidationError{
			Path:       fmt.Sprintf("%s.%s", channelName, opType),
			Message:    fmt.Sprintf("Missing message definition in %s operation", opType),
			Severity:   "error",
			Suggestion: "Add a message definition to the operation",
		})
	}
}

func (v *AsyncAPIValidator) validateServers(servers map[string]Server, result *ValidationResult) {
	for serverName, server := range servers {
		if server.URL == "" {
			v.addError(result, ValidationError{
				Path:       fmt.Sprintf("servers.%s", serverName),
				Message:    "Missing server URL",
				Severity:   "error",
				Suggestion: "Add a URL to the server definition",
			})
		}

		if server.Protocol == "" {
			v.addError(result, ValidationError{
				Path:       fmt.Sprintf("servers.%s", serverName),
				Message:    "Missing server protocol",
				Severity:   "error",
				Suggestion: "Add a protocol to the server definition",
			})
		}
	}
}

func (v *AsyncAPIValidator) validateComponents(components *Components, result *ValidationResult) {
	if components.SecuritySchemes != nil {
		for name, scheme := range components.SecuritySchemes {
			if scheme.Type == "" {
				v.addError(result, ValidationError{
					Path:       fmt.Sprintf("components.securitySchemes.%s", name),
					Message:    "Missing security scheme type",
					Severity:   "error",
					Suggestion: "Add a type to the security scheme",
				})
			}
		}
	}
}

func (v *AsyncAPIValidator) addError(result *ValidationResult, err ValidationError) {
	result.Valid = false
	result.Errors = append(result.Errors, err)
}
