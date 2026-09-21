package inspect

import (
	"slices"
	"testing"
)

func TestComparePrefixStrings(t *testing.T) {
	// Mixing lexical fallback with numeric ordering can create a cycle:
	// 2.0.0.0/8 < 10.0.0.0/8 < 15-invalid < 2.0.0.0/8.
	want := []string{"", "15-invalid", "2.0.0.0/8", "10.0.0.0/8", "10.0.0.0/16", "2001:db8::/32"}
	for i, a := range want {
		for j, b := range want {
			got := ComparePrefixStrings(a, b)
			if (i < j && got >= 0) || (i == j && got != 0) || (i > j && got <= 0) {
				t.Fatalf("ComparePrefixStrings(%q, %q) = %d", a, b, got)
			}
		}
	}
	got := slices.Clone(want)
	slices.Reverse(got)
	slices.SortFunc(got, ComparePrefixStrings)
	if !slices.Equal(got, want) {
		t.Fatalf("sorted prefixes = %v, want %v", got, want)
	}
	if ComparePrefixStrings("10.1.2.3/8", "10.0.0.0/8") != 0 {
		t.Fatal("host bits must not affect network ordering")
	}
}
