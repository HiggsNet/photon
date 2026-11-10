package inspect

import "testing"

func TestSortZoneStringsGroupsDotAndHyphenSuffixes(t *testing.T) {
	got := []string{
		"a-sha.catofes.",
		"b-pek.catofes.",
		"alpha.catofes.",
		"foo.pek.catofes.",
		"deep.a-pek.catofes.",
		"catofes.",
		"a-pek.catofes.",
		".",
	}
	SortZoneStrings(got)
	want := []string{
		".",
		"catofes.",
		"alpha.catofes.",
		"a-pek.catofes.",
		"deep.a-pek.catofes.",
		"b-pek.catofes.",
		"foo.pek.catofes.",
		"a-sha.catofes.",
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d] = %q, want %q; all=%+v", i, got[i], want[i], got)
		}
	}
}
