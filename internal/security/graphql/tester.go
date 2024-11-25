package graphql

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/sirupsen/logrus"
)

// Tester handles GraphQL-specific security testing
type Tester struct {
	logger  *logrus.Logger
	client  *http.Client
	baseURL string
}

// New creates a new GraphQL tester instance
func New(logger *logrus.Logger, client *http.Client, baseURL string) *Tester {
	return &Tester{
		logger:  logger,
		client:  client,
		baseURL: baseURL,
	}
}

// RunTests performs GraphQL security tests
func (t *Tester) RunTests(path string) error {
	t.logger.Info("Starting GraphQL security tests")

	tests := []struct {
		name string
		fn   func(string) error
	}{
		{"Schema Introspection", t.testSchemaIntrospection},
		{"Field Suggestions", t.testFieldSuggestions},
		{"Query Depth", t.testQueryDepth},
		{"Query Complexity", t.testQueryComplexity},
		{"Batch Queries", t.testBatchQueries},
	}

	for _, test := range tests {
		if err := test.fn(path); err != nil {
			t.logger.Warnf("%s test failed: %v", test.name, err)
		}
	}

	return nil
}

// testSchemaIntrospection tests for exposed schema information
func (t *Tester) testSchemaIntrospection(path string) error {
	query := `{__schema{types{name,kind,description,fields{name,type{name}}}}}`

	resp, err := t.makeGraphQLRequest(path, query)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		t.logger.Warn("GraphQL schema introspection is enabled")
	}

	return nil
}

// testFieldSuggestions tests for field suggestion vulnerabilities
func (t *Tester) testFieldSuggestions(path string) error {
	queries := []string{
		`{__type(name:"User"){fields{name}}}`,
		`{__type(name:"Admin"){fields{name}}}`,
		`{__type(name:"Internal"){fields{name}}}`,
	}

	for _, query := range queries {
		resp, err := t.makeGraphQLRequest(path, query)
		if err != nil {
			return err
		}
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			t.logger.Warnf("GraphQL field suggestions available for query: %s", query)
		}
	}

	return nil
}

// testQueryDepth tests for deep query vulnerabilities
func (t *Tester) testQueryDepth(path string) error {
	// Create a deeply nested query
	depth := 10
	var query strings.Builder
	query.WriteString("{user{")
	for i := 0; i < depth; i++ {
		query.WriteString("friends{")
	}
	query.WriteString("id")
	for i := 0; i < depth; i++ {
		query.WriteString("}")
	}
	query.WriteString("}")

	resp, err := t.makeGraphQLRequest(path, query.String())
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		t.logger.Warn("Deep GraphQL queries are allowed")
	}

	return nil
}

// testQueryComplexity tests for query complexity limits
func (t *Tester) testQueryComplexity(path string) error {
	// Create a query with high complexity
	query := `{
		users(first: 100) {
			edges {
				node {
					posts(first: 100) {
						edges {
							node {
								comments(first: 100) {
									edges {
										node {
											id
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}`

	resp, err := t.makeGraphQLRequest(path, query)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		t.logger.Warn("High complexity GraphQL queries are allowed")
	}

	return nil
}

// testBatchQueries tests for batch query vulnerabilities
func (t *Tester) testBatchQueries(path string) error {
	// Create a batch of queries
	queries := []string{
		`query { user(id: 1) { id } }`,
		`query { user(id: 2) { id } }`,
		`query { user(id: 3) { id } }`,
	}

	batchQuery := fmt.Sprintf("[%s]", strings.Join(queries, ","))

	resp, err := t.makeGraphQLRequest(path, batchQuery)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		t.logger.Warn("GraphQL batch queries are allowed")
	}

	return nil
}

// makeGraphQLRequest performs a GraphQL request
func (t *Tester) makeGraphQLRequest(path, query string) (*http.Response, error) {
	payload := fmt.Sprintf(`{"query": "%s"}`, query)
	req, err := http.NewRequest("POST", t.baseURL+path, strings.NewReader(payload))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")

	return t.client.Do(req)
}
