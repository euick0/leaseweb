// A tiny library-shaped module for the repository-audit tests. The tests only
// read it (no network): it is never built there.
package lhfixture

import (
	"strings"

	"golang.org/x/net/html"
)

// Parse reads an HTML page.
func Parse(page string) (*html.Node, error) {
	return html.Parse(strings.NewReader(page))
}
