package graphql

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

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
	// Set reasonable timeouts
	client.Timeout = 10 * time.Second

	return &Tester{
		logger:  logger,
		client:  client,
		baseURL: baseURL,
	}
}

// RunTests performs GraphQL security tests
func (t *Tester) RunTests(path string) error {
	t.logger.Info("Starting GraphQL security tests")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	tests := []struct {
		name string
		fn   func(context.Context, string) error
	}{
		{"Schema Introspection", t.testSchemaIntrospection},
		{"Field Suggestions", t.testFieldSuggestions},
		{"Query Depth", t.testQueryDepth},
		{"Query Complexity", t.testQueryComplexity},
		{"Batch Queries", t.testBatchQueries},
	}

	var wg sync.WaitGroup
	errChan := make(chan error, len(tests))

	for _, test := range tests {
		wg.Add(1)
		go func(tt struct {
			name string
			fn   func(context.Context, string) error
		}) {
			defer wg.Done()
			if err := tt.fn(ctx, path); err != nil {
				if !strings.Contains(err.Error(), "no such host") {
					t.logger.Warnf("%s test failed: %v", tt.name, err)
					select {
					case errChan <- err:
					default:
					}
				}
			}
		}(test)
	}

	wg.Wait()
	close(errChan)

	// Collect any errors
	var errs []error
	for err := range errChan {
		if err != nil && !strings.Contains(err.Error(), "no such host") {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("multiple test failures: %v", errs)
	}
	return nil
}

// testSchemaIntrospection tests for exposed schema information
func (t *Tester) testSchemaIntrospection(ctx context.Context, path string) error {
	query := `{__schema{types{name,kind,description,fields{name,type{name}}}}}`

	resp, err := t.makeGraphQLRequest(ctx, path, query)
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
func (t *Tester) testFieldSuggestions(ctx context.Context, path string) error {
	queries := []string{
		`{__type(name:"User"){fields{name}}}`,
		`{__type(name:"Admin"){fields{name}}}`,
		`{__type(name:"Internal"){fields{name}}}`,
	}

	var wg sync.WaitGroup
	errChan := make(chan error, len(queries))

	for _, query := range queries {
		wg.Add(1)
		go func(q string) {
			defer wg.Done()

			select {
			case <-ctx.Done():
				errChan <- ctx.Err()
				return
			default:
				resp, err := t.makeGraphQLRequest(ctx, path, q)
				if err != nil {
					if !strings.Contains(err.Error(), "no such host") {
						errChan <- err
					}
					return
				}
				resp.Body.Close()

				if resp.StatusCode == http.StatusOK {
					t.logger.Warnf("GraphQL field suggestions available for query: %s", q)
				}
			}
		}(query)
	}

	wg.Wait()
	close(errChan)

	// Collect any errors
	var errs []error
	for err := range errChan {
		if err != nil && !strings.Contains(err.Error(), "no such host") {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("multiple field suggestion test failures: %v", errs)
	}
	return nil
}

// testQueryDepth tests for deep query vulnerabilities
func (t *Tester) testQueryDepth(ctx context.Context, path string) error {
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

	resp, err := t.makeGraphQLRequest(ctx, path, query.String())
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
func (t *Tester) testQueryComplexity(ctx context.Context, path string) error {
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

	resp, err := t.makeGraphQLRequest(ctx, path, query)
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
func (t *Tester) testBatchQueries(ctx context.Context, path string) error {
	// Create a batch of queries
	queries := []string{
		`query { user(id: 1) { id } }`,
		`query { user(id: 2) { id } }`,
		`query { user(id: 3) { id } }`,
	}

	var wg sync.WaitGroup
	errChan := make(chan error, len(queries))

	for _, query := range queries {
		wg.Add(1)
		go func(q string) {
			defer wg.Done()

			select {
			case <-ctx.Done():
				errChan <- ctx.Err()
				return
			default:
				batchQuery := fmt.Sprintf("[%s]", q)
				resp, err := t.makeGraphQLRequest(ctx, path, batchQuery)
				if err != nil {
					if !strings.Contains(err.Error(), "no such host") {
						errChan <- err
					}
					return
				}
				defer resp.Body.Close()

				if resp.StatusCode == http.StatusOK {
					t.logger.Warn("GraphQL batch queries are allowed")
				}
			}
		}(query)
	}

	wg.Wait()
	close(errChan)

	// Collect any errors
	var errs []error
	for err := range errChan {
		if err != nil && !strings.Contains(err.Error(), "no such host") {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("multiple batch query test failures: %v", errs)
	}
	return nil
}

// makeGraphQLRequest performs a GraphQL request
func (t *Tester) makeGraphQLRequest(ctx context.Context, path, query string) (*http.Response, error) {
	payload := fmt.Sprintf(`{"query": "%s"}`, query)
	req, err := http.NewRequestWithContext(ctx, "POST", t.baseURL+path, strings.NewReader(payload))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := t.client.Do(req)
	if err != nil {
		// Skip DNS resolution errors
		if strings.Contains(err.Error(), "no such host") {
			return nil, err
		}
		return nil, fmt.Errorf("request failed: %w", err)
	}

	return resp, nil
}
