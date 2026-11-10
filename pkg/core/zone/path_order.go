package zone

import "strings"

// ComparePaths groups Zone paths by suffix, including hyphen-separated labels.
func ComparePaths(a, b string) int {
	aLabels, aOK := zonePathLabels(a)
	bLabels, bOK := zonePathLabels(b)
	if !aOK || !bOK {
		return strings.Compare(a, b)
	}
	for i := 0; i < len(aLabels) && i < len(bLabels); i++ {
		if aLabels[i] != bLabels[i] {
			return strings.Compare(aLabels[i], bLabels[i])
		}
	}
	if len(aLabels) != len(bLabels) {
		return len(aLabels) - len(bLabels)
	}
	return strings.Compare(a, b)
}

func zonePathLabels(path string) ([]string, bool) {
	zp := ZonePath(path)
	if !zp.Valid() {
		return nil, false
	}
	if zp.IsRoot() {
		return nil, true
	}
	labels := strings.FieldsFunc(strings.TrimSuffix(path, "."), func(r rune) bool {
		return r == '.' || r == '-'
	})
	for i, j := 0, len(labels)-1; i < j; i, j = i+1, j-1 {
		labels[i], labels[j] = labels[j], labels[i]
	}
	return labels, true
}
