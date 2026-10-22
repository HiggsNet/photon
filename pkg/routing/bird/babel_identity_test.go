package bird

import (
	"net/netip"
	"strings"
	"testing"
)

func TestLocalBabelIdentityRequiresExactLocalEvidence(t *testing.T) {
	const header = "photon_babel_mesh:\nPrefix Router ID Metric Seqno Routes Sources\n"
	const local = "192.0.2.0/24 ab:cd:ef:01:0a:00:00:02 0 7 0 0\n"
	prefixes := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("2001:db8::/64")}
	got, err := LocalBabelIdentity(header+local, "photon_babel_mesh", prefixes)
	if err != nil || got != "abcdef010a000002" {
		t.Fatal(got, err)
	}
	for name, line := range map[string]string{
		"learned exact prefix":   "192.0.2.0/24 ab:cd:ef:01:0a:00:00:02 100 7 1 1\n",
		"remote zero metric":     "198.51.100.0/24 ab:cd:ef:01:0a:00:00:02 0 7 0 0\n",
		"local competing remote": "192.0.2.0/24 ab:cd:ef:01:0a:00:00:02 0 7 1 1\n",
		"withdrawn":              "192.0.2.0/24 ab:cd:ef:01:0a:00:00:02 65535 7 0 0\n",
	} {
		t.Run(name, func(t *testing.T) {
			got, err := LocalBabelIdentity(header+line, "photon_babel_mesh", prefixes)
			if err != nil || got != "" {
				t.Fatal(got, err)
			}
		})
	}
	for name, output := range map[string]string{
		"wrong instance": strings.Replace(header, "mesh", "elsewhere", 1) + local,
		"missing header": local,
		"low32":          header + strings.Replace(local, "ab:cd:ef:01:0a:00:00:02", "0a:00:00:02", 1),
		"zero":           header + strings.Replace(local, "ab:cd:ef:01:0a:00:00:02", "00:00:00:00:00:00:00:00", 1),
		"conflict":       header + local + "2001:db8::/64 ff:cd:ef:01:0a:00:00:02 0 7 0 0\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := LocalBabelIdentity(output, "photon_babel_mesh", prefixes); err == nil {
				t.Fatal("accepted untrusted identity evidence")
			}
		})
	}
}
