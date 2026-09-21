package photonlinux

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/transport/ipsec"
	"gopkg.in/yaml.v3"
)

func TestTunnelAddressConfig(t *testing.T) {
	for _, tc := range []struct {
		name      string
		raw       tunnelAddressConfigYAML
		want      ipsec.TunnelAddressSpec
		wantError string
	}{
		{name: "derived pool", raw: tunnelAddressConfigYAML{Mode: "derived-pool", Family: "ipv4", Pool: "10.44.0.0/24"}, want: ipsec.TunnelAddressSpec{Mode: ipsec.TunnelAddressDerivedPool, Family: ipsec.FamilyIPv4, Pool: netip.MustParsePrefix("10.44.0.0/24")}},
		{name: "invalid mode", raw: tunnelAddressConfigYAML{Mode: "magic"}, wantError: "invalid tunnel_address.mode"},
		{name: "invalid family", raw: tunnelAddressConfigYAML{Family: "ipx"}, wantError: "invalid tunnel_address.family"},
		{name: "mismatched pool", raw: tunnelAddressConfigYAML{Mode: "derived-pool", Family: "ipv4", Pool: "fd00:1234::/64"}, wantError: "does not match pool"},
		{name: "missing pool", raw: tunnelAddressConfigYAML{Mode: "derived-pool"}, wantError: "requires a pool"},
		{name: "inferred family", raw: tunnelAddressConfigYAML{Mode: " DERIVED-POOL ", Pool: "10.44.0.0/24"}, want: ipsec.TunnelAddressSpec{Mode: ipsec.TunnelAddressDerivedPool, Family: ipsec.FamilyIPv4, Pool: netip.MustParsePrefix("10.44.0.0/24")}},
		{name: "ipv4 default", raw: tunnelAddressConfigYAML{Family: "ipv4"}, want: ipsec.TunnelAddressSpec{Mode: ipsec.TunnelAddressDisabled, Family: ipsec.FamilyIPv4}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.raw.parse()
			if tc.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantError) {
					t.Fatalf("Parse() = %v, want %q", err, tc.wantError)
				}
			} else if err != nil || got != tc.want {
				t.Fatalf("Parse() = %+v, %v; want %+v", got, err, tc.want)
			}
		})
	}
}

func TestIPsecConfigRejectsInvalidOptions(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  IPsecConfigYAML
		want string
	}{
		{"driver", IPsecConfigYAML{Driver: "magic"}, "invalid ipsec.driver"},
		{"role", IPsecConfigYAML{Role: "invalid"}, "invalid ipsec.role"},
		{"deprecated accept", IPsecConfigYAML{DeprecatedAccept: "inbound"}, "ipsec.accept is deprecated"},
		{"port mode", IPsecConfigYAML{PortMode: "dynamic"}, "invalid ipsec.port_mode"},
		{"port range", IPsecConfigYAML{PortMode: "range", PortRange: ipsec.PortRange{From: 40000, To: 30000}}, "invalid ipsec.port_range"},
		{"port pairs", IPsecConfigYAML{PortMode: "range", PortRange: ipsec.PortRange{From: 30000, To: 30002}}, "two IKE/NAT-T port pairs"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := DefaultIPsecConfig()
			if err := tc.raw.Apply(&config); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Apply() = %v, want %q", err, tc.want)
			}
		})
	}
}

func applyIPsecYAML(input string, config *IPsecConfig) error {
	if strings.TrimSpace(input) == "" {
		return nil
	}
	var file struct {
		IPsec IPsecConfigYAML `yaml:"ipsec"`
	}
	decoder := yaml.NewDecoder(strings.NewReader(input))
	decoder.KnownFields(true)
	if err := decoder.Decode(&file); err != nil {
		return err
	}
	return file.IPsec.Apply(config)
}

func TestIPsecConfigDriver(t *testing.T) {
	config := DefaultIPsecConfig()
	input := `
ipsec:
  driver: strongswan
  vici_socket: /tmp/charon.vici
`
	if err := applyIPsecYAML(input, &config); err != nil {
		t.Fatalf("applyIPsecYAML: %v", err)
	}
	config.Normalize()
	if config.Driver != IPsecDriverStrongSwan || config.VICISocket != "/tmp/charon.vici" {
		t.Fatalf("IPsec driver config = %+v", config)
	}
}

func TestIPsecConfigAnnouncements(t *testing.T) {
	config := DefaultIPsecConfig()
	input := `ipsec:
  announce_addrs:
    - 203.0.113.10
    - 2001:db8::10
  announce_dns:
    - vpn.example.com
    - vpn6.example.com
  announce_dns_reconnect_after: 2m
  announce_gossip_endpoints: false
`
	if err := applyIPsecYAML(input, &config); err != nil {
		t.Fatalf("applyIPsecYAML: %v", err)
	}
	config.Normalize()
	if len(config.AnnounceAddrs) != 2 || config.AnnounceAddrs[0] != "203.0.113.10" || config.AnnounceAddrs[1] != "2001:db8::10" {
		t.Fatalf("AnnounceAddrs = %v", config.AnnounceAddrs)
	}
	if len(config.AnnounceDNS) != 2 || config.AnnounceDNS[0] != "vpn.example.com" || config.AnnounceDNS[1] != "vpn6.example.com" {
		t.Fatalf("AnnounceDNS = %v", config.AnnounceDNS)
	}
	if config.AnnounceDNSReconnectAfter != 2*time.Minute {
		t.Fatalf("AnnounceDNSReconnectAfter = %s, want 2m", config.AnnounceDNSReconnectAfter)
	}
	if config.AnnounceGossipEndpoints {
		t.Fatalf("AnnounceGossipEndpoints = true, want false")
	}
}

func TestIPsecConfigAnnouncementsRejectPorts(t *testing.T) {
	for _, candidate := range []string{"203.0.113.10:4500", "[2001:db8::10]:4500"} {
		config := DefaultIPsecConfig()
		input := "ipsec:\n  announce_addrs:\n    - \"" + candidate + "\"\n"
		err := applyIPsecYAML(input, &config)
		if err == nil || !strings.Contains(err.Error(), "without a port") {
			t.Fatalf("applyIPsecYAML(%q) error = %v, want address-without-port error", candidate, err)
		}
	}
}

func TestIPsecConfigAnnounceGossipEndpointsDefaultsToTrue(t *testing.T) {
	config := DefaultIPsecConfig()
	if err := applyIPsecYAML("", &config); err != nil {
		t.Fatalf("applyIPsecYAML: %v", err)
	}
	config.Normalize()
	if !config.AnnounceGossipEndpoints {
		t.Fatalf("AnnounceGossipEndpoints = false, want true")
	}
	if err := applyIPsecYAML("ipsec:\n  announce_gossip_endpoints: false\n  announce_dns_reconnect_after: 0s\n", &config); err != nil {
		t.Fatal(err)
	}
	config.Normalize()
	if config.AnnounceGossipEndpoints || config.AnnounceDNSReconnectAfter != 0 {
		t.Fatalf("explicit false/zero lost during normalization: %+v", config)
	}
}

func TestIPsecConfigRole(t *testing.T) {
	config := DefaultIPsecConfig()
	if config.Role != ipsec.RoleBoth {
		t.Fatalf("default role = %q, want both", config.Role)
	}
	input := `
ipsec:
  role: in
`
	if err := applyIPsecYAML(input, &config); err != nil {
		t.Fatalf("applyIPsecYAML: %v", err)
	}
	config.Normalize()
	if config.Role != ipsec.RoleIn {
		t.Fatalf("IPsec.Role = %q, want in", config.Role)
	}
}

func TestIPsecConfigPortRotation(t *testing.T) {
	config := DefaultIPsecConfig()
	input := `
ipsec:
  port_mode: range
  port_range:
    from: 30000
    to: 30099
  port_rotate_interval: 24h
  port_previous_grace: 2h
`
	if err := applyIPsecYAML(input, &config); err != nil {
		t.Fatalf("applyIPsecYAML: %v", err)
	}
	config.Normalize()
	if config.PortMode != ipsec.PortModeRange {
		t.Fatalf("PortMode = %q, want range", config.PortMode)
	}
	if config.PortRange.From != 30000 || config.PortRange.To != 30099 {
		t.Fatalf("PortRange = %+v", config.PortRange)
	}
	if config.PortRotateInterval != 24*time.Hour {
		t.Fatalf("PortRotateInterval = %s", config.PortRotateInterval)
	}
	if config.PortPreviousGrace != 2*time.Hour {
		t.Fatalf("PortPreviousGrace = %s", config.PortPreviousGrace)
	}
}

func TestDefaultIPsecPortGraceExceedsOverlayRetention(t *testing.T) {
	config := DefaultIPsecConfig()
	retention := time.Duration((ipsec.LinkGroupSpec{}).Normalized().Reconcile.RotateRetentionSeconds) * time.Second
	if config.PortPreviousGrace <= retention {
		t.Fatalf("default port grace %s must exceed overlay retention %s", config.PortPreviousGrace, retention)
	}
}

func TestValidateIPsecRotateWindows(t *testing.T) {
	for _, tc := range []struct {
		name      string
		grace     time.Duration
		retention int
		wantError bool
	}{
		{"explicit retention too long", 10 * time.Minute, 3600, true},
		{"default retention too long", 10 * time.Minute, 0, true},
		{"equal to default retention", time.Hour, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			group := ipsec.LinkGroupSpec{}
			group.Reconcile.RotateRetentionSeconds = tc.retention
			err := ValidateIPsecRotateWindows([]ipsec.LinkGroupSpec{group}, tc.grace)
			if tc.wantError {
				if err == nil || !strings.Contains(err.Error(), "ipsec.port_previous_grace") {
					t.Fatalf("ValidateIPsecRotateWindows: %v, want port grace error", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}
