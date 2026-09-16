package photonlinux

import (
	"github.com/HiggsNet/photon/pkg/firewall"
	"testing"
)

func TestFirewallInstancesEnabled(t *testing.T) {
	config := FirewallConfig{
		Instances: []FirewallInstanceConfig{
			{ID: "a", Enabled: true, Mode: firewall.ModeManaged},
			{ID: "b", Enabled: false, Mode: firewall.ModeManaged},
			{ID: "c", Enabled: true, Mode: firewall.ModeDisabled},
			{ID: "d", Enabled: true, Mode: firewall.ModeExternal},
		},
	}
	enabled := config.ManagedInstances()
	if len(enabled) != 1 {
		t.Fatalf("expected 1 enabled, got %d", len(enabled))
	}
	if enabled[0].ID != "a" {
		t.Errorf("expected instance a, got %s", enabled[0].ID)
	}
}

func TestFirewallInstanceSpecFromConfig(t *testing.T) {
	inst := FirewallInstanceConfig{
		ID: "photontesth2", NetNS: "photontesth2", IsHost: false,
		Enabled: true, Mode: firewall.ModeManaged,
		Backend: firewall.BackendNFT, DefaultPolicy: firewall.DefaultPolicyDrop,
		OwnerPrefix: "photon", XFRMTunnelPattern: "phx*",
		LocalServices: []firewall.LocalService{{Proto: "tcp", Port: 443}},
	}
	spec := inst.Spec()
	if spec.ID != "photontesth2" {
		t.Errorf("ID = %s", spec.ID)
	}
	if spec.CharonIKEPort != 500 {
		t.Errorf("IKEPort = %d", spec.CharonIKEPort)
	}
	if len(spec.LocalServices) != 1 {
		t.Errorf("local services = %d", len(spec.LocalServices))
	}
}
