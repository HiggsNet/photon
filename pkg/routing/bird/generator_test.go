package bird

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

func testBirdInstanceSpec() BirdInstanceSpec {
	return BirdInstanceSpec{
		RouterID:          0x01020304,
		NetNSName:         "ipsec-main",
		ControlSocketPath: "/run/photon/bird-ipsec-main.ctl",
		PIDFilePath:       "/run/photon/bird-ipsec-main.pid",
		ConfigPath:        "/etc/photon/bird-ipsec-main.conf",
		Mode:              BirdModeManaged,
		InterfacePattern:  "phx*",
	}
}

func TestGenerateManagedConfig(t *testing.T) {
	spec := testBirdInstanceSpec()
	importSet := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("2001:db8::/32"),
	}
	exportSet := []netip.Prefix{
		netip.MustParsePrefix("192.168.0.0/16"),
	}

	gen := DefaultConfigGenerator{}
	cfg, err := gen.Generate(spec, importSet, exportSet)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	s := string(cfg)

	if !strings.Contains(s, "Photon-generated BIRD config") {
		t.Error("missing Photon-generated header comment")
	}
	if !strings.Contains(s, "Do not edit manually") {
		t.Error("missing manual-edit warning")
	}
	if !strings.Contains(s, "router id 1.2.3.4;") {
		t.Error("missing router id directive")
	}
	if !strings.Contains(s, "log syslog all;") {
		t.Error("missing default log directive")
	}
	if !strings.Contains(s, "protocol device") {
		t.Error("missing protocol device block")
	}
	if !strings.Contains(s, "scan time 5;") {
		t.Error("missing default device scan time")
	}
	if !strings.Contains(s, "ipv4 table photon_ipsec_main4;") {
		t.Error("missing ipv4 table declaration")
	}
	if !strings.Contains(s, "ipv6 table photon_ipsec_main6;") {
		t.Error("missing ipv6 table declaration")
	}
	if !strings.Contains(s, "protocol kernel photon_kern_ipsec_main") {
		t.Error("missing kernel protocol block")
	}
	if !strings.Contains(s, "protocol babel photon_babel_ipsec_main") {
		t.Error("missing babel protocol block")
	}
	if !strings.Contains(s, "    randomize router id;") {
		t.Error("missing Babel router ID randomization for restart-safe sequence numbers")
	}
	if cnt := strings.Count(s, "randomize router id;"); cnt != 1 {
		t.Errorf("expected exactly one Babel router ID randomization directive, got %d", cnt)
	}
	if strings.Contains(s, "etx loss scale") || strings.Contains(s, "hysteresis margin") {
		t.Error("default config must remain compatible with stock BIRD")
	}
	if !strings.Contains(s, "interface \"phx*\"") {
		t.Error("missing interface pattern")
	}
	if !strings.Contains(s, "type wireless;") {
		t.Error("missing type wireless directive")
	}
	if strings.Contains(s, "type tunnel;") {
		t.Error("mesh interfaces must not use binary tunnel reachability")
	}
	if !strings.Contains(s, "rxcost 100;") {
		t.Error("missing default rxcost")
	}
	for _, want := range []string{
		"rtt cost 1024;",
		"rtt min 10 ms;",
		"rtt max 500 ms;",
		"rtt decay 12;",
		"hello interval 4 s;",
		"update interval 16 s;",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing default Babel tuning %q", want)
		}
	}
	if !strings.Contains(s, "filter photon_import_ipsec_main") {
		t.Error("missing import filter")
	}
	if !strings.Contains(s, "filter photon_export_ipsec_main") {
		t.Error("missing export filter")
	}
}

func TestGenerateKernelMultipath(t *testing.T) {
	gen := DefaultConfigGenerator{}
	for _, tc := range []struct {
		name  string
		limit uint
		want  string
	}{
		{name: "without limit", want: "merge paths on;"},
		{name: "with limit", limit: 16, want: "merge paths on limit 16;"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := testBirdInstanceSpec()
			spec.ECMP = true
			spec.ECMPLimit = tc.limit
			cfg, err := gen.Generate(spec, nil, nil)
			if err != nil {
				t.Fatalf("Generate failed: %v", err)
			}
			if !strings.Contains(string(cfg), tc.want) {
				t.Fatalf("generated config missing %q:\n%s", tc.want, cfg)
			}
		})
	}
}

func TestRenderFilter(t *testing.T) {
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("2001:db8::/32"),
	}
	bogons := []netip.Prefix{
		netip.MustParsePrefix("192.168.0.0/16"),
	}

	filter := RenderFilter("test_filter", prefixes, bogons)

	if !strings.Contains(filter, "filter test_filter {") {
		t.Error("missing filter declaration")
	}
	if !strings.Contains(filter, "if net ~ [ 0.0.0.0/0 ] then reject;") {
		t.Error("missing IPv4 default route rejection")
	}
	if !strings.Contains(filter, "if net ~ [ ::/0 ] then reject;") {
		t.Error("missing IPv6 default route rejection")
	}
	if !strings.Contains(filter, "192.168.0.0/16+") {
		t.Error("missing bogon rejection with more-specific")
	}
	if !strings.Contains(filter, "10.0.0.0/8{18,28}") {
		t.Error("missing bounded authorized IPv4 prefix acceptance")
	}
	if !strings.Contains(filter, "2001:db8::/32{48,96}") {
		t.Error("missing bounded authorized IPv6 prefix acceptance")
	}
	if !strings.HasSuffix(filter, "    reject;\n}") {
		t.Error("missing final reject")
	}
}

func TestAcceptedPrefixPatternBoundsIPv6Specifics(t *testing.T) {
	tests := []struct {
		raw  string
		want string
	}{
		{raw: "2001:db8::/32", want: "2001:db8::/32{48,96}"},
		{raw: "2001:db8:1:2::/64", want: "2001:db8:1:2::/64{64,96}"},
		{raw: "2001:db8:1:2:3::/80", want: "2001:db8:1:2:3::/80{80,96}"},
		{raw: "2001:db8:1:2:3:4::/112", want: "2001:db8:1:2:3:4::/112"},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			if got := acceptedPrefixPattern(netip.MustParsePrefix(tt.raw)); got != tt.want {
				t.Fatalf("acceptedPrefixPattern(%s) = %s, want %s", tt.raw, got, tt.want)
			}
		})
	}
}

func TestAcceptedPrefixPatternBoundsIPv4Specifics(t *testing.T) {
	tests := []struct {
		raw  string
		want string
	}{
		{raw: "10.0.0.0/8", want: "10.0.0.0/8{18,28}"},
		{raw: "10.0.0.0/24", want: "10.0.0.0/24{24,28}"},
		{raw: "10.0.0.0/28", want: "10.0.0.0/28{28,28}"},
		{raw: "10.0.0.1/32", want: "10.0.0.1/32"},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			if got := acceptedPrefixPattern(netip.MustParsePrefix(tt.raw)); got != tt.want {
				t.Fatalf("acceptedPrefixPattern(%s) = %s, want %s", tt.raw, got, tt.want)
			}
		})
	}
}

func TestStableRouterIDDeterministic(t *testing.T) {
	z := zone.ZonePath("test.example.")
	root := []byte("root-trust")
	overlay := "overlay-1"

	id1 := StableRouterID(z, root, overlay)
	id2 := StableRouterID(z, root, overlay)

	if id1 == 0 {
		t.Error("router id is zero")
	}
	if id1 != id2 {
		t.Errorf("router id not deterministic: %d vs %d", id1, id2)
	}
}

func TestDefaultsApplied(t *testing.T) {
	spec := BirdInstanceSpec{
		RouterID:          0x01020304,
		NetNSName:         "ipsec-main",
		ControlSocketPath: "/run/photon/bird-ipsec-main.ctl",
		PIDFilePath:       "/run/photon/bird-ipsec-main.pid",
		ConfigPath:        "/etc/photon/bird-ipsec-main.conf",
		Mode:              BirdModeManaged,
		InterfacePattern:  "phx*",
	}

	gen := DefaultConfigGenerator{}
	cfg, err := gen.Generate(spec, nil, nil)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	s := string(cfg)

	if !strings.Contains(s, "rxcost 100;") {
		t.Error("default metric base not applied")
	}
	if !strings.Contains(s, "scan time 5;") {
		t.Error("default device scan time not applied")
	}
	if !strings.Contains(s, "log syslog all;") {
		t.Error("default log target not applied")
	}
}

func TestRenderMultipleInterfacePatterns(t *testing.T) {
	spec := testBirdInstanceSpec()
	spec.InterfacePattern = ""
	spec.InterfacePatterns = []string{"phx-live0", "phx-live1"}

	gen := DefaultConfigGenerator{}
	cfg, err := gen.Generate(spec, nil, nil)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	s := string(cfg)
	if !strings.Contains(s, `interface "phx-live0", "phx-live1" {`) {
		t.Fatalf("interface pattern list not comma-separated:\n%s", s)
	}
}

func TestRenderConcreteInterfacePoliciesBeforeCatchAll(t *testing.T) {
	spec := testBirdInstanceSpec()
	spec.InterfacePolicies = []BabelInterfacePolicy{
		{InterfaceName: "phx-new", Metric: 100},
		{InterfaceName: "phx-old", Metric: 500},
	}

	cfg, err := (DefaultConfigGenerator{}).Generate(spec, nil, nil)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	s := string(cfg)
	oldBlock := "interface \"phx-old\" {\n        type wireless;\n        rxcost 500;"
	newBlock := "interface \"phx-new\" {\n        type wireless;\n        rxcost 100;"
	catchAll := `interface "phx*" {`
	if !strings.Contains(s, oldBlock) || !strings.Contains(s, newBlock) {
		t.Fatalf("missing concrete interface policies:\n%s", s)
	}
	if strings.Index(s, oldBlock) > strings.Index(s, catchAll) || strings.Index(s, newBlock) > strings.Index(s, catchAll) {
		t.Fatalf("concrete policies must precede catch-all first match:\n%s", s)
	}
}

func TestRenderCustomBabelTuningOnWirelessMeshInterfaces(t *testing.T) {
	spec := testBirdInstanceSpec()
	etxLossScale, hysteresisMargin := uint(192), uint(0)
	spec.BabelETXLossScale = &etxLossScale
	spec.BabelHysteresisMargin = &hysteresisMargin
	spec.BabelRTTCost = 80
	spec.BabelRTTMin = 5 * time.Millisecond
	spec.BabelRTTMax = 450 * time.Millisecond
	spec.BabelRTTDecay = 9
	spec.BabelHelloInterval = 2 * time.Second
	spec.BabelUpdateInterval = 20 * time.Second
	spec.InterfacePolicies = []BabelInterfacePolicy{{InterfaceName: "phx-live", Metric: 125}}

	cfg, err := (DefaultConfigGenerator{}).Generate(spec, nil, nil)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	s := string(cfg)
	if !strings.Contains(s, "\n    etx loss scale 192;\n    hysteresis margin 0;\n") {
		t.Fatalf("missing protocol-level patched Babel settings:\n%s", s)
	}
	for _, blockStart := range []string{`interface "phx-live" {`, `interface "phx*" {`} {
		start := strings.Index(s, blockStart)
		if start < 0 {
			t.Fatalf("missing interface block %q:\n%s", blockStart, s)
		}
		end := strings.Index(s[start:], "    };")
		if end < 0 {
			t.Fatalf("unterminated interface block %q:\n%s", blockStart, s)
		}
		block := s[start : start+end]
		if !strings.Contains(block, "type wireless;") {
			t.Errorf("interface block %q must use wireless ETX costing:\n%s", blockStart, block)
		}
		for _, want := range []string{
			"rtt cost 80;", "rtt min 5 ms;", "rtt max 450 ms;", "rtt decay 9;",
			"hello interval 2 s;", "update interval 20 s;",
		} {
			if !strings.Contains(block, want) {
				t.Errorf("interface block %q missing %q:\n%s", blockStart, want, block)
			}
		}
	}
}

func TestRenderUpstreamUsesIntervalsWithoutRTTTuning(t *testing.T) {
	spec := testBirdInstanceSpec()
	spec.BabelHelloInterval = 2 * time.Second
	spec.BabelUpdateInterval = 20 * time.Second
	spec.Upstream = &UpstreamSpec{Interface: "phv2host"}

	cfg, err := (DefaultConfigGenerator{}).Generate(spec, nil, nil)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	s := string(cfg)
	start := strings.Index(s, `interface "phv2host" {`)
	if start < 0 {
		t.Fatalf("missing upstream block:\n%s", s)
	}
	end := strings.Index(s[start:], "    };")
	block := s[start : start+end]
	if strings.Contains(block, "type wireless;") || strings.Contains(block, "rtt cost") {
		t.Fatalf("upstream block must not enable mesh ETX/RTT tuning:\n%s", block)
	}
	if !strings.Contains(block, "hello interval 2 s;") || !strings.Contains(block, "update interval 20 s;") {
		t.Fatalf("upstream block missing configured intervals:\n%s", block)
	}
}

func TestRejectInvalidBabelTuning(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*BirdInstanceSpec)
	}{
		{name: "RTT cost too large", mutate: func(spec *BirdInstanceSpec) { spec.BabelRTTCost = 65535 }},
		{name: "RTT max before min", mutate: func(spec *BirdInstanceSpec) {
			spec.BabelRTTMin = 20 * time.Millisecond
			spec.BabelRTTMax = 10 * time.Millisecond
		}},
		{name: "RTT decay too large", mutate: func(spec *BirdInstanceSpec) { spec.BabelRTTDecay = 257 }},
		{name: "sub-millisecond Hello", mutate: func(spec *BirdInstanceSpec) { spec.BabelHelloInterval = 500 * time.Microsecond }},
		{name: "negative Update", mutate: func(spec *BirdInstanceSpec) { spec.BabelUpdateInterval = -time.Second }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := testBirdInstanceSpec()
			tc.mutate(&spec)
			if _, err := (DefaultConfigGenerator{}).Generate(spec, nil, nil); err == nil {
				t.Fatal("Generate should reject invalid Babel tuning")
			}
		})
	}
}

func TestIPv4AndIPv6Prefixes(t *testing.T) {
	spec := testBirdInstanceSpec()
	importSet := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("2001:db8::/32"),
	}

	gen := DefaultConfigGenerator{}
	cfg, err := gen.Generate(spec, importSet, nil)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	s := string(cfg)

	if !strings.Contains(s, "10.0.0.0/8") {
		t.Error("missing IPv4 authorized prefix")
	}
	if !strings.Contains(s, "2001:db8::/32") {
		t.Error("missing IPv6 authorized prefix")
	}
}

func TestBabelAuthRendered(t *testing.T) {
	spec := testBirdInstanceSpec()
	spec.BabelAuth = &BabelAuthSpec{
		Enabled:   true,
		Algorithm: "hmac sha256",
		KeyID:     7,
		Password:  "secret-key",
	}

	gen := DefaultConfigGenerator{}
	cfg, err := gen.Generate(spec, nil, nil)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	s := string(cfg)

	want := "auth \"hmac sha256\" key id 7 password \"secret-key\";"
	if !strings.Contains(s, want) {
		t.Errorf("auth block not rendered correctly, want substring %q in:\n%s", want, s)
	}
}

func TestDisabledModeReturnsError(t *testing.T) {
	spec := testBirdInstanceSpec()
	spec.Mode = BirdModeDisabled

	gen := DefaultConfigGenerator{}
	_, err := gen.Generate(spec, nil, nil)
	if err == nil {
		t.Error("expected error for disabled mode")
	}
}
