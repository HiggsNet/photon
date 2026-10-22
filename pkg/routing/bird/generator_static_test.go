package bird

import (
	"bytes"
	"context"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStaticProtocolsKeepFamiliesSeparate(t *testing.T) {
	routes := StaticRouteBlock{Name: "owned", IPv4Routes: []StaticRoute{{Prefix: netip.MustParsePrefix("192.0.2.0/24"), Blackhole: true}}, IPv6Routes: []StaticRoute{{Prefix: netip.MustParsePrefix("2001:db8::/32"), Via: "test0"}}}
	for _, tc := range []struct {
		name, v4, v6 string
		count        int
	}{
		{"dual", "table4", "table6", 2}, {"ipv4", "table4", "", 1}, {"ipv6", "", "table6", 1}, {"disabled", "", "", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var text bytes.Buffer
			renderStaticRouteBlock(&text, routes, tc.v4, tc.v6)
			output := text.String()
			if strings.Count(output, "protocol static ") != tc.count {
				t.Fatalf("wrong protocol count: %s", output)
			}
			for _, block := range strings.Split(output, "protocol static ")[1:] {
				switch {
				case strings.HasPrefix(block, "owned_v4 {"):
					if strings.Contains(block, "ipv6") || !strings.Contains(block, "route 192.0.2.0/24 blackhole;") || strings.Contains(block, "2001:db8") {
						t.Fatalf("mixed IPv4 block: %s", block)
					}
				case strings.HasPrefix(block, "owned_v6 {"):
					if strings.Contains(block, "ipv4") || !strings.Contains(block, `route 2001:db8::/32 via "test0";`) || strings.Contains(block, "192.0.2") {
						t.Fatalf("mixed IPv6 block: %s", block)
					}
				default:
					t.Fatalf("unexpected protocol name: %s", block)
				}
			}
		})
	}
	var empty bytes.Buffer
	renderStaticRouteBlock(&empty, StaticRouteBlock{Name: "empty"}, "table4", "table6")
	if empty.Len() != 0 {
		t.Fatal("generated empty static protocols")
	}
}

// Parse the complete production output without starting a daemon or modifying
// networking. The explicit binary lets CI and native rigs pin their BIRD build.
func TestGeneratedDualStackStaticConfigWithRealBird(t *testing.T) {
	binary := os.Getenv("PHOTON_BIRD_PARSE_BINARY")
	if binary == "" {
		t.Skip("set PHOTON_BIRD_PARSE_BINARY to a pinned BIRD binary")
	}
	spec := testBirdInstanceSpec()
	spec.LogTarget = "log stderr all"
	spec.StaticRoutes = []StaticRouteSpec{
		{Prefix: netip.MustParsePrefix("192.0.2.0/24"), Blackhole: true},
		{Prefix: netip.MustParsePrefix("2001:db8::/32"), Blackhole: true},
	}
	generated, err := (DefaultConfigGenerator{}).Generate(spec, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "bird.conf")
	if err := os.WriteFile(path, generated, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, binary, "-p", "-c", path).CombinedOutput()
	if err != nil {
		t.Fatalf("BIRD rejected generated dual-stack config: %v\n%s\n%s", err, output, generated)
	}
	t.Log("complete generated IPv4/IPv6 static configuration accepted by BIRD -p")
}
