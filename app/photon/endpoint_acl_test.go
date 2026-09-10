package main

import (
	"net/netip"
	"testing"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/firewall"
	"github.com/HiggsNet/photon/pkg/routing"
)

func TestResolveEndpointServicesTracksAuthorizedZoneRoutes(t *testing.T) {
	ars := &routing.AuthorizedRouteSet{Announced: map[zone.ZonePath]map[netip.Prefix]*routing.RouteEntry{
		"node-a.catofes.": {netip.MustParsePrefix("fd10:1::/64"): {}},
		"node-b.other.":   {netip.MustParsePrefix("10.2.0.0/24"): {}},
	}}
	services, err := resolveEndpointServices(map[string]endpointACL{
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
	services, err := resolveEndpointServices(map[string]endpointACL{
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
	services, err := resolveEndpointServices(map[string]endpointACL{
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
	legacy, err := validateEndpointACL(endpointACL{
		Name: "legacy", Destination: "fd42::20", Protocol: "tcp", Port: 3128,
		Selectors: []string{"*.catofes."},
	})
	if err != nil || legacy.Scope != endpointACLScopePort {
		t.Fatalf("legacy ACL = %+v, %v", legacy, err)
	}
	if _, err := validateEndpointACL(endpointACL{
		Name: "bad", Destination: "fd42::20", Scope: endpointACLScopeIP, Protocol: "udp",
		Selectors: []string{"*.catofes."},
	}); err == nil {
		t.Fatal("IP-scope ACL accepted a protocol")
	}
}

func TestEndpointACLApplyNoopDoesNotCommitOrNotify(t *testing.T) {
	acl := endpointACL{
		Name: "socks5-main", Destination: "fd42::20", Scope: endpointACLScopeIP,
		Selectors: []string{"*.catofes.", "node-a.catofes."},
	}
	verified := &corestate.VerifiedState{
		ManagedZone: "node-a.catofes.",
		Network:     zone.NewNetworkState(),
	}
	runtime := &linuxRuntimeState{
		EndpointACLs: map[string]endpointACL{
			acl.Name: acl,
		},
	}
	appConfig := defaultAppConfig()
	appConfig.Firewall.Instances = []FirewallInstanceConfig{{
		ID: "host", NetNS: "host", IsHost: true, Enabled: true,
		Mode: firewall.ModeManaged, Backend: firewall.BackendAuto,
	}}
	service := newTestDaemonFromOwners(
		&AppContext{Config: appConfig}, verified, nil, runtime, &gossipStartupConfig{}, time.Second,
	)
	driver := &captureFirewallOwnerDriver{}
	driver.Backend = firewall.BackendNFT
	installTestFirewallDriver(service, driver)
	beforeRevision := uint64(service.StateStore.common.VerifiedRevision())
	notifications := 0
	service.Hooks.OnStateChanged = func() { notifications++ }

	// Validation canonicalizes selector order, so the differently ordered input
	// must still be recognized as the same committed ACL.
	incoming := acl
	incoming.Selectors = []string{"node-a.catofes.", "*.catofes."}
	result, _, _ := service.handleEvent(daemonEvent{Type: daemonEventEndpointACLApply, EndpointACL: &incoming})
	if result.Error != nil {
		t.Fatalf("no-op apply: %v", result.Error)
	}
	if result.StateCommitted {
		t.Fatal("no-op apply reported a committed state change")
	}
	if got := uint64(service.StateStore.common.VerifiedRevision()); got != beforeRevision {
		t.Fatalf("no-op apply revision = %d, want %d", got, beforeRevision)
	}
	if notifications != 0 || service.ipsecDirty || service.routingDirty || service.firewallDirty {
		t.Fatalf("no-op apply side effects: notifications=%d dirty=%v/%v/%v", notifications, service.ipsecDirty, service.routingDirty, service.firewallDirty)
	}
}

func TestEndpointACLRemoveMissingIsNoop(t *testing.T) {
	verified := &corestate.VerifiedState{ManagedZone: "node-a.catofes.", Network: zone.NewNetworkState()}
	runtime := &linuxRuntimeState{EndpointACLs: map[string]endpointACL{}}
	service := newTestDaemonFromOwners(
		&AppContext{Config: defaultAppConfig()}, verified, nil, runtime, &gossipStartupConfig{}, time.Second,
	)
	beforeRevision := uint64(service.StateStore.common.VerifiedRevision())
	notifications := 0
	service.Hooks.OnStateChanged = func() { notifications++ }

	result, _, _ := service.handleEvent(daemonEvent{Type: daemonEventEndpointACLRemove, Key: "missing"})
	if result.Error != nil {
		t.Fatalf("no-op remove: %v", result.Error)
	}
	if result.StateCommitted {
		t.Fatal("no-op remove reported a committed state change")
	}
	if got := uint64(service.StateStore.common.VerifiedRevision()); got != beforeRevision {
		t.Fatalf("no-op remove revision = %d, want %d", got, beforeRevision)
	}
	if notifications != 0 || service.ipsecDirty || service.routingDirty || service.firewallDirty {
		t.Fatalf("no-op remove side effects: notifications=%d dirty=%v/%v/%v", notifications, service.ipsecDirty, service.routingDirty, service.firewallDirty)
	}
}
