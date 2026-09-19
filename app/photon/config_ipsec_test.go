package main

import (
	"strings"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/photonlinux"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestParseConfigYAMLIPsecDriver(t *testing.T) {
	config := defaultAppConfig()
	input := `
ipsec:
  driver: strongswan
  vici_socket: /tmp/charon.vici
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	normalizeAppConfig(config)
	if config.IPsec.Driver != photonlinux.IPsecDriverStrongSwan || config.IPsec.VICISocket != "/tmp/charon.vici" {
		t.Fatalf("IPsec driver config = %+v", config.IPsec)
	}
}

func TestParseConfigYAMLIPsecAnnouncements(t *testing.T) {
	config := defaultAppConfig()
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
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	normalizeAppConfig(config)
	if len(config.IPsec.AnnounceAddrs) != 2 || config.IPsec.AnnounceAddrs[0] != "203.0.113.10" || config.IPsec.AnnounceAddrs[1] != "2001:db8::10" {
		t.Fatalf("AnnounceAddrs = %v", config.IPsec.AnnounceAddrs)
	}
	if len(config.IPsec.AnnounceDNS) != 2 || config.IPsec.AnnounceDNS[0] != "vpn.example.com" || config.IPsec.AnnounceDNS[1] != "vpn6.example.com" {
		t.Fatalf("AnnounceDNS = %v", config.IPsec.AnnounceDNS)
	}
	if config.IPsec.AnnounceDNSReconnectAfter != 2*time.Minute {
		t.Fatalf("AnnounceDNSReconnectAfter = %s, want 2m", config.IPsec.AnnounceDNSReconnectAfter)
	}
	if config.IPsec.AnnounceGossipEndpoints {
		t.Fatalf("AnnounceGossipEndpoints = true, want false")
	}
}

func TestParseConfigYAMLIPsecAnnouncementsRejectPorts(t *testing.T) {
	for _, candidate := range []string{"203.0.113.10:4500", "[2001:db8::10]:4500"} {
		config := defaultAppConfig()
		input := "ipsec:\n  announce_addrs:\n    - \"" + candidate + "\"\n"
		err := parseConfigYAML(input, config)
		if err == nil || !strings.Contains(err.Error(), "without a port") {
			t.Fatalf("parseConfigYAML(%q) error = %v, want address-without-port error", candidate, err)
		}
	}
}

func TestParseConfigYAMLIPsecAnnounceGossipEndpointsDefaultsToTrue(t *testing.T) {
	config := defaultAppConfig()
	if err := parseConfigYAML("", config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	normalizeAppConfig(config)
	if !config.IPsec.AnnounceGossipEndpoints {
		t.Fatalf("AnnounceGossipEndpoints = false, want true")
	}
	if err := parseConfigYAML("ipsec:\n  announce_gossip_endpoints: false\n  announce_dns_reconnect_after: 0s\n", config); err != nil {
		t.Fatal(err)
	}
	normalizeAppConfig(config)
	if config.IPsec.AnnounceGossipEndpoints || config.IPsec.AnnounceDNSReconnectAfter != 0 {
		t.Fatalf("explicit false/zero lost during normalization: %+v", config.IPsec)
	}
}

func TestParseConfigYAMLIPsecRole(t *testing.T) {
	config := defaultAppConfig()
	input := `
ipsec:
  role: both
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	normalizeAppConfig(config)
	if config.IPsec.Role != ipsec.RoleBoth {
		t.Fatalf("IPsec.Role = %q, want both", config.IPsec.Role)
	}
}

func TestParseConfigYAMLIPsecPortRotation(t *testing.T) {
	config := defaultAppConfig()
	input := `
ipsec:
  port_mode: range
  port_range:
    from: 30000
    to: 30099
  port_rotate_interval: 24h
  port_previous_grace: 2h
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	normalizeAppConfig(config)
	if config.IPsec.PortMode != ipsec.PortModeRange {
		t.Fatalf("PortMode = %q, want range", config.IPsec.PortMode)
	}
	if config.IPsec.PortRange.From != 30000 || config.IPsec.PortRange.To != 30099 {
		t.Fatalf("PortRange = %+v", config.IPsec.PortRange)
	}
	if config.IPsec.PortRotateInterval != 24*time.Hour {
		t.Fatalf("PortRotateInterval = %s", config.IPsec.PortRotateInterval)
	}
	if config.IPsec.PortPreviousGrace != 2*time.Hour {
		t.Fatalf("PortPreviousGrace = %s", config.IPsec.PortPreviousGrace)
	}
}

func TestDefaultIPsecPortPreviousGraceIsLongerThanRotateRetention(t *testing.T) {
	config := defaultAppConfig()
	if config.IPsec.PortPreviousGrace != 2*time.Hour {
		t.Fatalf("default PortPreviousGrace = %s, want 2h", config.IPsec.PortPreviousGrace)
	}
}

func TestParseConfigYAMLPortGraceCoversRotateRetention(t *testing.T) {
	for _, tc := range []struct {
		name, grace, retention string
		wantError              bool
	}{
		{"explicit retention too long", "10m", "1h", true},
		{"default retention too long", "10m", "", true},
		{"equal to default retention", "1h", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := defaultAppConfig()
			input := "ipsec:\n  port_previous_grace: " + tc.grace + "\noverlays:\n  - name: ipsec-main\n"
			if tc.retention != "" {
				input += "    reconcile:\n      rotate_retention: " + tc.retention + "\n"
			}
			err := parseConfigYAML(input, config)
			if tc.wantError {
				if err == nil || !strings.Contains(err.Error(), "ipsec.port_previous_grace") {
					t.Fatalf("parseConfigYAML: %v, want port grace error", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}
