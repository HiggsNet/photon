package zone

import (
	"fmt"
	"path"
	"strings"
)

// HasPatternMeta distinguishes exact selectors from path.Match patterns,
// including its backslash escape syntax. Dots are ordinary literal characters.
func HasPatternMeta(pattern string) bool { return strings.ContainsAny(pattern, "*?[\\") }

// ValidatePattern checks the existing zone-selector glob grammar, not a regular
// expression or a fully-qualified zone name. Platform callers may constrain
// exact selectors further without changing glob semantics.
func ValidatePattern(pattern string) error {
	if pattern == "" {
		return fmt.Errorf("zone pattern is required")
	}
	if strings.Contains(pattern, "://") {
		return fmt.Errorf("invalid zone pattern %q", pattern)
	}
	if _, err := path.Match(pattern, "node.example."); err != nil {
		return fmt.Errorf("invalid zone glob %q: %w", pattern, err)
	}
	return nil
}

// MatchesPattern preserves the mesh policy exact-equality shortcut, then uses
// path.Match for globs. In particular '*' selects any zone string while '.*'
// requires a literal leading dot. ValidatePattern checks selector syntax.
func MatchesPattern(pattern string, peer ZonePath) bool {
	if pattern == "" {
		return false
	}
	if pattern == string(peer) {
		return true
	}
	matched, err := path.Match(pattern, string(peer))
	return err == nil && matched
}
