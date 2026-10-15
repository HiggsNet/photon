package zone

import "testing"

func TestMatchesPatternUsesGlobNotRegularExpression(t *testing.T) {
	for _, tc := range []struct {
		pattern string
		peer    ZonePath
		want    bool
	}{
		{"gateway.catofes.", "gateway.catofes.", true},
		{"gateway.catofes.", "other.catofes.", false},
		{"*", "gateway.catofes.", true},
		{"*.catofes.", "gateway.catofes.", true},
		{"*.catofes.", "nested.gateway.catofes.", true},
		{"*.catofes.", "gateway.other.", false},
		{"gateway-?.catofes.", "gateway-a.catofes.", true},
		{"gateway-?.catofes.", "gateway-ab.catofes.", false},
		{"gateway-[ab].catofes.", "gateway-b.catofes.", true},
		{"gateway-[^ab].catofes.", "gateway-c.catofes.", true},
		{"gateway-[ab].catofes.", "gateway-c.catofes.", false},
		{".*", "gateway.catofes.", false},
		{".*", ".gateway.catofes.", true},
		{`gateway\?.catofes.`, "gateway?.catofes.", true},
		{"[", "gateway.catofes.", false},
		{"", "gateway.catofes.", false},
	} {
		if got := MatchesPattern(tc.pattern, tc.peer); got != tc.want {
			t.Errorf("MatchesPattern(%q, %q) = %v, want %v", tc.pattern, tc.peer, got, tc.want)
		}
	}
}

func TestValidatePatternRetainsMeshPolicyGrammar(t *testing.T) {
	for _, pattern := range []string{"*", "*.catofes.", ".*", "gateway-?.catofes.", "gateway-[ab].catofes.", `gateway\?.catofes.`, "node.example.", "mesh-target-without-dot"} {
		if err := ValidatePattern(pattern); err != nil {
			t.Errorf("valid pattern %q rejected: %v", pattern, err)
		}
	}
	for _, pattern := range []string{"", "[", "gateway-[ab.catofes.", "gateway\\", "strongswan://*"} {
		if err := ValidatePattern(pattern); err == nil {
			t.Errorf("invalid pattern %q accepted", pattern)
		}
	}
}

func TestHasPatternMetaIncludesEscapes(t *testing.T) {
	for _, pattern := range []string{"*", ".*", "gateway?.", "gateway[ab].", `gateway\?.`} {
		if !HasPatternMeta(pattern) {
			t.Errorf("pattern %q classified exact", pattern)
		}
	}
	for _, exact := range []string{"gateway.catofes.", "gateway].catofes.", "."} {
		if HasPatternMeta(exact) {
			t.Errorf("literal %q classified glob", exact)
		}
	}
}
