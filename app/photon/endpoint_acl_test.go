package main

import (
	"net/netip"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/photonlinux"
	photonstate "github.com/HiggsNet/photon/internal/state"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/firewall"
	"github.com/HiggsNet/photon/pkg/routing"
)

func TestResolveEndpointServicesTracksAuthorizedZoneRoutes(t *testing.T) {
	ars := &routing.AuthorizedRouteSet{Announced: map[zone.ZonePath]map[netip.Prefix]*routing.RouteEntry{
		"node-a.catofes.": {netip.MustParsePrefix("fd10:1::/64"): {}, netip.MustParsePrefix("10.1.0.0/24"): {}},
		"node-c.catofes.": {netip.MustParsePrefix("fd10:1::/64"): {}},
		"node-b.other.":   {netip.MustParsePrefix("10.2.0.0/24"): {}},
	}}
	services, err := resolveEndpointServices(map[string]photonstate.EndpointACL{
		"socks5": {Name: "socks5", Destination: "fd42::20", Protocol: "tcp", Port: 3128, Selectors: []string{"*.catofes."}},
	}, ars)
	if err != nil {
		t.Fatalf("resolveEndpointServices: %v", err)
	}
	if len(services) != 1 || len(services[0].Sources) != 1 || services[0].Sources[0].String() != "fd10:1::/64" {
		t.Fatalf("resolved services = %+v", services)
	}
}

func TestResolveEndpointServicesEmptyMatchIsFailClosedInput(t *testing.T) {
	services, err := resolveEndpointServices(map[string]photonstate.EndpointACL{
		"socks5": {Name: "socks5", Destination: "fd42::20", Protocol: "tcp", Port: 3128, Selectors: []string{"missing.catofes."}},
	}, &routing.AuthorizedRouteSet{Announced: map[zone.ZonePath]map[netip.Prefix]*routing.RouteEntry{}})
	if err != nil {
		t.Fatalf("resolveEndpointServices: %v", err)
	}
	if len(services) != 1 || len(services[0].Sources) != 0 {
		t.Fatalf("resolved services = %+v", services)
	}
}

func TestResolveEndpointServicesIPScope(t *testing.T) {
	services, err := resolveEndpointServices(map[string]photonstate.EndpointACL{
		"socks5": {
			Name: "socks5", Destination: "fd42::20", Scope: endpointACLScopeIP,
			Selectors: []string{"*.catofes."},
		},
	}, &routing.AuthorizedRouteSet{Announced: map[zone.ZonePath]map[netip.Prefix]*routing.RouteEntry{
		"node-a.catofes.": {netip.MustParsePrefix("fd10:1::/64"): {}},
	}})
	if err != nil {
		t.Fatalf("resolveEndpointServices: %v", err)
	}
	if len(services) != 1 || services[0].Proto != "" || services[0].Port != 0 {
		t.Fatalf("IP-scope services = %+v", services)
	}
}

func TestValidateEndpointACLScopes(t *testing.T) {
	legacy, err := validateEndpointACL(photonstate.EndpointACL{
		Name: "legacy", Destination: "fd42::20", Protocol: "tcp", Port: 3128,
		Selectors: []string{"*.catofes."},
	})
	if err != nil || legacy.Scope != endpointACLScopePort {
		t.Fatalf("legacy ACL = %+v, %v", legacy, err)
	}
	if _, err := validateEndpointACL(photonstate.EndpointACL{
		Name: "bad", Destination: "fd42::20", Scope: endpointACLScopeIP, Protocol: "udp",
		Selectors: []string{"*.catofes."},
	}); err == nil {
		t.Fatal("IP-scope ACL accepted a protocol")
	}
}

func TestEndpointACLApplyNoopDoesNotCommitOrNotify(t *testing.T) {
	acl := photonstate.EndpointACL{
		Name: "socks5-main", Destination: "fd42::20", Scope: endpointACLScopeIP,
		Selectors: []string{"*.catofes.", "node-a.catofes."},
	}
	verified := &corestate.VerifiedState{
		ManagedZone: "node-a.catofes.",
		Network:     zone.NewNetworkState(),
	}
	runtime := &photonlinux.LinuxState{
		EndpointACLs: map[string]photonstate.EndpointACL{
			acl.Name: acl,
		},
	}
	appConfig := defaultAppConfig()
	appConfig.Firewall.Instances = []firewall.FirewallInstanceSpec{{
		ID: "host", NetNS: "host", IsHost: true, Enabled: true,
		Mode: firewall.ModeManaged, Backend: firewall.BackendAuto,
	}}
	service := newTestDaemonFromOwners(
		&testApp{Config: appConfig}, verified, nil, runtime, appConfig, time.Second,
	)
	driver := &captureFirewallInstanceDriver{}
	driver.Backend = firewall.BackendNFT
	installTestFirewallDriver(service, driver)
	beforeRevision := uint64(service.State.Common.VerifiedRevision())
	notifications := 0
	service.Hooks.OnStateChanged = func() { notifications++ }

	// Validation canonicalizes selector order, so the differently ordered input
	// must still be recognized as the same committed ACL.
	incoming := acl
	incoming.Name = " SOCKS5-MAIN "
	incoming.Selectors = []string{"node-a.catofes.", "*.catofes."}
	result, _, _ := service.handleEvent(daemonEvent{Type: daemonEventEndpointACLApply, EndpointACL: &incoming})
	if result.Error != nil {
		t.Fatalf("no-op apply: %v", result.Error)
	}
	if result.StateCommitted {
		t.Fatal("no-op apply reported a committed state change")
	}
	if got := uint64(service.State.Common.VerifiedRevision()); got != beforeRevision {
		t.Fatalf("no-op apply revision = %d, want %d", got, beforeRevision)
	}
	if notifications != 0 || service.ipsecDirty || service.routingDirty || service.firewallDirty {
		t.Fatalf("no-op apply side effects: notifications=%d dirty=%v/%v/%v", notifications, service.ipsecDirty, service.routingDirty, service.firewallDirty)
	}
}

func TestEndpointACLRemoveMissingIsNoop(t *testing.T) {
	verified := &corestate.VerifiedState{ManagedZone: "node-a.catofes.", Network: zone.NewNetworkState()}
	runtime := &photonlinux.LinuxState{EndpointACLs: map[string]photonstate.EndpointACL{}}
	service := newTestDaemonFromOwners(
		&testApp{Config: defaultAppConfig()}, verified, nil, runtime, nil, time.Second,
	)
	beforeRevision := uint64(service.State.Common.VerifiedRevision())
	notifications := 0
	service.Hooks.OnStateChanged = func() { notifications++ }

	result, _, _ := service.handleEvent(daemonEvent{Type: daemonEventEndpointACLRemove, Key: "missing"})
	if result.Error != nil {
		t.Fatalf("no-op remove: %v", result.Error)
	}
	if result.StateCommitted {
		t.Fatal("no-op remove reported a committed state change")
	}
	if got := uint64(service.State.Common.VerifiedRevision()); got != beforeRevision {
		t.Fatalf("no-op remove revision = %d, want %d", got, beforeRevision)
	}
	if notifications != 0 || service.ipsecDirty || service.routingDirty || service.firewallDirty {
		t.Fatalf("no-op remove side effects: notifications=%d dirty=%v/%v/%v", notifications, service.ipsecDirty, service.routingDirty, service.firewallDirty)
	}
}

func TestEndpointACLNamesAndLocalMutation(t *testing.T) {
	acl, err := validateEndpointACL(photonstate.EndpointACL{
		Name: " API ", Destination: "fd42::20", Scope: endpointACLScopeIP,
		Selectors: []string{"*.catofes."},
	})
	if err != nil || acl.Name != "api" {
		t.Fatalf("normalized ACL = %+v, %v", acl, err)
	}
	for _, tc := range []struct {
		name      string
		keys      []string
		remove    string
		remaining string
	}{
		{"canonical", []string{"api"}, " API ", ""},
		{"legacy", []string{"API"}, " API ", ""},
		{"collision", []string{"API", "api"}, "API", "api"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			acls := map[string]photonstate.EndpointACL{}
			for _, key := range tc.keys {
				entry := acl
				entry.Name = key
				acls[key] = entry
			}
			config := defaultAppConfig()
			config.Firewall.Instances = []firewall.FirewallInstanceSpec{{
				ID: "host", NetNS: "host", IsHost: true, Enabled: true,
				Mode: firewall.ModeManaged, Backend: firewall.BackendAuto,
			}}
			service := newTestDaemonFromOwners(&testApp{Config: config},
				&corestate.VerifiedState{ManagedZone: "node-a.catofes.", Network: zone.NewNetworkState()},
				nil, &photonlinux.LinuxState{EndpointACLs: acls}, config, time.Second)
			driver := &captureFirewallInstanceDriver{}
			driver.Backend = firewall.BackendNFT
			installTestFirewallDriver(service, driver)
			notifications := 0
			service.Hooks.OnStateChanged = func() { notifications++ }
			if tc.name != "canonical" {
				committed, err := service.handleEndpointACLApplyEvent(acl)
				if err == nil || committed || notifications != 0 || service.firewallDirty {
					t.Fatalf("legacy collision was not rejected without side effects: %v, %v", committed, err)
				}
			}
			revision := service.State.Common.VerifiedRevision()
			committed, err := service.handleEndpointACLRemoveEvent(tc.remove)
			if err != nil || !committed {
				t.Fatalf("remove = %v, %v", committed, err)
			}
			remaining := service.State.ReadLinux().EndpointACLs
			wantCount := 0
			if tc.remaining != "" {
				wantCount = 1
				if _, ok := remaining[tc.remaining]; !ok {
					t.Fatalf("removed wrong entry: %+v", remaining)
				}
			}
			if len(remaining) != wantCount {
				t.Fatalf("remaining ACLs = %+v", remaining)
			}
			if notifications != 1 || !service.firewallDirty || service.ipsecDirty || service.routingDirty || service.State.Common.VerifiedRevision() != revision {
				t.Fatalf("unexpected local mutation side effects: notifications=%d dirty=%v/%v/%v", notifications, service.ipsecDirty, service.routingDirty, service.firewallDirty)
			}
		})
	}
}
