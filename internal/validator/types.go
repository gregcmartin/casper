package validator

// SpecFormat represents the API specification format
type SpecFormat string

const (
	FormatSwagger2  SpecFormat = "swagger2"
	FormatOpenAPI3  SpecFormat = "openapi3"
	FormatAsyncAPI  SpecFormat = "asyncapi"
	FormatGraphQL   SpecFormat = "graphql"
	FormatRAML      SpecFormat = "raml"
	FormatBlueprint SpecFormat = "blueprint"
)

// SpecInfo contains basic information about an API specification
type SpecInfo struct {
	Title       string
	Version     string
	Description string
	Format      SpecFormat
}

// ValidationResult contains the results of specification validation
type ValidationResult struct {
	Valid   bool
	Errors  []ValidationError
	Info    SpecInfo
	Paths   []string
	Methods []string
}

// ValidationError represents a validation error
type ValidationError struct {
	Path        string
	Message     string
	Severity    string
	Suggestion  string
	LineNumber  int
	ColumnStart int
	ColumnEnd   int
}

// SecurityScheme represents a generic security scheme
type SecurityScheme struct {
	Type        string
	Name        string
	Description string
	Location    string
	Flows       []OAuthFlow
}

// OAuthFlow represents OAuth flow configuration
type OAuthFlow struct {
	Type             string
	AuthorizationURL string
	TokenURL         string
	RefreshURL       string
	Scopes           map[string]string
}
