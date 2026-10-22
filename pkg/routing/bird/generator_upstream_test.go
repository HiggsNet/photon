package bird

import (
	"net/netip"
	"strings"
	"testing"
)

func TestGenerateWithUpstreamInterface(t *testing.T) {
	spec := testBirdInstanceSpec()
	spec.NetNSName = "photontesth2"
	spec.Upstream = &UpstreamSpec{
		Interface: "phv2host",
	}

	gen := DefaultConfigGenerator{}
	cfg, err := gen.Generate(spec, nil, nil)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	s := string(cfg)

	// The primary XFRM mesh interface uses wireless ETX costing plus RTT.
	if !strings.Contains(s, `interface "phx*" {`) {
		t.Errorf("missing primary interface block with phx*\n%s", s)
	}
	if !strings.Contains(s, "type wireless;") {
		t.Errorf("missing type wireless in primary interface block\n%s", s)
	}

	// The upstream veth interface block must not use wireless ETX costing.
	if !strings.Contains(s, `interface "phv2host" {`) {
		t.Errorf("missing upstream interface block\n%s", s)
	}
	// Count wireless occurrences: exactly one, in the primary mesh block.
	if cnt := strings.Count(s, "type wireless;"); cnt != 1 {
		t.Errorf("expected exactly 1 'type wireless;' but got %d in:\n%s", cnt, s)
	}
}

func TestGenerateWithoutUpstreamNoExtraInterface(t *testing.T) {
	spec := testBirdInstanceSpec()
	spec.NetNSName = "photontesth2"

	gen := DefaultConfigGenerator{}
	cfg, err := gen.Generate(spec, nil, nil)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	s := string(cfg)

	// Should NOT have any upstream interface block.
	if strings.Contains(s, "phv2host") {
		t.Errorf("upstream interface block present when not configured\n%s", s)
	}
	// Must still have the primary interface block.
	if !strings.Contains(s, `interface "phx*" {`) {
		t.Errorf("missing primary interface block\n%s", s)
	}
}

func TestGenerateWithStaticRoutes(t *testing.T) {
	spec := testBirdInstanceSpec()
	spec.NetNSName = "photontesth2"
	spec.StaticRoutes = []StaticRouteSpec{
		{
			Prefix: netip.MustParsePrefix("10.0.0.0/24"),
			Via:    "phv2host",
		},
		{
			Prefix: netip.MustParsePrefix("2001:db8:1::/48"),
			Via:    "phv2host",
		},
	}

	gen := DefaultConfigGenerator{}
	cfg, err := gen.Generate(spec, nil, nil)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	s := string(cfg)

	// BIRD permits only one address-family channel per static protocol.
	if !strings.Contains(s, "protocol static photon_static_photontesth2_v4 {") ||
		!strings.Contains(s, "protocol static photon_static_photontesth2_v6 {") || strings.Count(s, "protocol static ") != 2 {
		t.Errorf("missing separate family static protocols\n%s", s)
	}
	// Must have the IPv4 route via the upstream interface.
	if !strings.Contains(s, `route 10.0.0.0/24 via "phv2host";`) {
		t.Errorf("missing IPv4 static route via interface\n%s", s)
	}
	// Must have the IPv6 route via the upstream interface.
	if !strings.Contains(s, `route 2001:db8:1::/48 via "phv2host";`) {
		t.Errorf("missing IPv6 static route via interface\n%s", s)
	}
}

func TestGenerateWithStaticRouteGatewayAndInterface(t *testing.T) {
	spec := testBirdInstanceSpec()
	spec.NetNSName = "photontesth2"
	spec.StaticRoutes = []StaticRouteSpec{
		{
			Prefix:  netip.MustParsePrefix("2001:db8:1::/48"),
			Via:     "phv2-host",
			NextHop: netip.MustParseAddr("fe80::a1:2"),
		},
	}

	cfg, err := (DefaultConfigGenerator{}).Generate(spec, nil, nil)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	if got := string(cfg); !strings.Contains(got, `route 2001:db8:1::/48 via fe80::a1:2%'phv2-host';`) {
		t.Errorf("missing IPv6 gateway route pinned to interface\n%s", got)
	}
}

func TestGenerateRejectsUnrepresentableScopedInterface(t *testing.T) {
	spec := testBirdInstanceSpec()
	spec.StaticRoutes = []StaticRouteSpec{
		{
			Prefix:  netip.MustParsePrefix("2001:db8:1::/48"),
			Via:     "phv2'host",
			NextHop: netip.MustParseAddr("fe80::a1:2"),
		},
	}

	_, err := (DefaultConfigGenerator{}).Generate(spec, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "cannot be represented as a BIRD scoped next-hop") {
		t.Fatalf("Generate error = %v, want scoped next-hop interface validation error", err)
	}
}

func TestGenerateWithBlackholeStaticRoute(t *testing.T) {
	spec := testBirdInstanceSpec()
	spec.NetNSName = "photontesth2"
	spec.StaticRoutes = []StaticRouteSpec{
		{
			Prefix:    netip.MustParsePrefix("10.0.0.0/24"),
			Blackhole: true,
		},
	}

	gen := DefaultConfigGenerator{}
	cfg, err := gen.Generate(spec, nil, nil)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	s := string(cfg)

	if !strings.Contains(s, "route 10.0.0.0/24 blackhole;") {
		t.Errorf("missing blackhole static route\n%s", s)
	}
}

func TestGenerateWithStaticRouteNoVia(t *testing.T) {
	spec := testBirdInstanceSpec()
	spec.NetNSName = "photontesth2"
	spec.StaticRoutes = []StaticRouteSpec{
		{
			Prefix: netip.MustParsePrefix("10.0.0.0/24"),
		},
	}

	gen := DefaultConfigGenerator{}
	cfg, err := gen.Generate(spec, nil, nil)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	s := string(cfg)

	// Without Via, should default to blackhole for safety.
	if !strings.Contains(s, "route 10.0.0.0/24 blackhole;") {
		t.Errorf("static route without via should default to blackhole\n%s", s)
	}
}

func TestGenerateWithoutStaticRoutesNoStaticBlock(t *testing.T) {
	spec := testBirdInstanceSpec()

	gen := DefaultConfigGenerator{}
	cfg, err := gen.Generate(spec, nil, nil)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	s := string(cfg)

	if strings.Contains(s, "protocol static") {
		t.Errorf("static protocol block present when no static routes\n%s", s)
	}
}

func TestGenerateWithUpstreamAndStaticRoutes(t *testing.T) {
	spec := testBirdInstanceSpec()
	spec.NetNSName = "photontesth2"
	spec.Upstream = &UpstreamSpec{
		Interface: "phv2host",
	}
	spec.StaticRoutes = []StaticRouteSpec{
		{
			Prefix: netip.MustParsePrefix("10.0.0.0/24"),
			Via:    "phv2host",
		},
	}

	gen := DefaultConfigGenerator{}
	cfg, err := gen.Generate(spec, nil, nil)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	s := string(cfg)

	// Both upstream interface block and static routes.
	if !strings.Contains(s, `interface "phv2host" {`) {
		t.Errorf("missing upstream interface block\n%s", s)
	}
	if !strings.Contains(s, "protocol static") {
		t.Errorf("missing protocol static block\n%s", s)
	}
	if !strings.Contains(s, `route 10.0.0.0/24 via "phv2host";`) {
		t.Errorf("missing static route via upstream interface\n%s", s)
	}
}
