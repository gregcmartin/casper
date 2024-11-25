package validator

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sirupsen/logrus"
)

func TestValidateSpec(t *testing.T) {
	logger := newTestLogger()
	v := New(logger)

	tests := []struct {
		name        string
		specPath    string
		wantFormat  SpecFormat
		wantErr     bool
		description string
	}{
		{
			name:        "Swagger 2.0",
			specPath:    filepath.Join("..", "..", "examples", "petstore.yaml"),
			wantFormat:  FormatSwagger2,
			wantErr:     false,
			description: "Should successfully validate Swagger 2.0 spec",
		},
		{
			name:        "OpenAPI 3.0",
			specPath:    filepath.Join("..", "..", "examples", "petstore-v3.yaml"),
			wantFormat:  FormatOpenAPI3,
			wantErr:     false,
			description: "Should successfully validate OpenAPI 3.0 spec",
		},
		{
			name:        "AsyncAPI",
			specPath:    filepath.Join("..", "..", "examples", "chat-service-async.yaml"),
			wantFormat:  FormatAsyncAPI,
			wantErr:     false,
			description: "Should successfully validate AsyncAPI spec",
		},
		{
			name:        "GraphQL",
			specPath:    filepath.Join("..", "..", "examples", "social-network.graphql"),
			wantFormat:  FormatGraphQL,
			wantErr:     false,
			description: "Should successfully validate GraphQL schema",
		},
		{
			name:        "RAML",
			specPath:    filepath.Join("..", "..", "examples", "music-service.raml"),
			wantFormat:  FormatRAML,
			wantErr:     false,
			description: "Should successfully validate RAML spec",
		},
		{
			name:        "API Blueprint",
			specPath:    filepath.Join("..", "..", "examples", "todo-service.apib"),
			wantFormat:  FormatBlueprint,
			wantErr:     false,
			description: "Should successfully validate API Blueprint spec",
		},
		{
			name:        "Invalid File",
			specPath:    filepath.Join("..", "..", "examples", "nonexistent.yaml"),
			wantFormat:  "",
			wantErr:     true,
			description: "Should fail for nonexistent file",
		},
		{
			name:        "Invalid Format",
			specPath:    filepath.Join("..", "..", "examples", "invalid.txt"),
			wantFormat:  "",
			wantErr:     true,
			description: "Should fail for unsupported format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// First detect format
			format, err := v.detectFormat(tt.specPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("detectFormat() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && format != tt.wantFormat {
				t.Errorf("detectFormat() got = %v, want %v", format, tt.wantFormat)
				return
			}

			// Then validate if format was detected successfully
			if !tt.wantErr {
				err = v.ValidateSpec(tt.specPath)
				if err != nil {
					t.Errorf("ValidateSpec() error = %v", err)
				}
			}
		})
	}
}

func TestDetectFormat(t *testing.T) {
	logger := newTestLogger()
	v := New(logger)

	tests := []struct {
		name       string
		content    string
		wantFormat SpecFormat
		wantErr    bool
	}{
		{
			name: "Swagger 2.0",
			content: `swagger: "2.0"
info:
  title: Test API
  version: 1.0.0`,
			wantFormat: FormatSwagger2,
			wantErr:    false,
		},
		{
			name: "OpenAPI 3.0",
			content: `openapi: "3.0.0"
info:
  title: Test API
  version: 1.0.0`,
			wantFormat: FormatOpenAPI3,
			wantErr:    false,
		},
		{
			name: "AsyncAPI",
			content: `asyncapi: "2.0.0"
info:
  title: Test API
  version: 1.0.0`,
			wantFormat: FormatAsyncAPI,
			wantErr:    false,
		},
		{
			name: "GraphQL",
			content: `type Query {
  test: String
}`,
			wantFormat: FormatGraphQL,
			wantErr:    false,
		},
		{
			name: "RAML",
			content: `#%RAML 1.0
title: Test API
version: 1.0`,
			wantFormat: FormatRAML,
			wantErr:    false,
		},
		{
			name: "API Blueprint",
			content: `FORMAT: 1A
HOST: http://api.example.com

# Test API`,
			wantFormat: FormatBlueprint,
			wantErr:    false,
		},
		{
			name:       "Invalid Format",
			content:    "Invalid content",
			wantFormat: "",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpFile := createTempFile(t, tt.content)
			defer removeTempFile(t, tmpFile)

			format, err := v.detectFormat(tmpFile)
			if (err != nil) != tt.wantErr {
				t.Errorf("detectFormat() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && format != tt.wantFormat {
				t.Errorf("detectFormat() got = %v, want %v", format, tt.wantFormat)
			}
		})
	}
}

// Helper functions

func newTestLogger() *logrus.Logger {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	return logger
}

func createTempFile(t *testing.T, content string) string {
	t.Helper()
	tmpfile, err := os.CreateTemp("", "test-*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	if _, err := tmpfile.Write([]byte(content)); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatalf("Failed to close temp file: %v", err)
	}
	return tmpfile.Name()
}

func removeTempFile(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Errorf("Failed to remove temp file: %v", err)
	}
}
