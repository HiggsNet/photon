package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/photonlinux"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
	"github.com/HiggsNet/photon/pkg/health"
	"github.com/HiggsNet/photon/pkg/routing"
	"github.com/HiggsNet/photon/pkg/routing/bird"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

type successfulHealthProber struct{}

func (successfulHealthProber) Probe(ctx context.Context, target health.ProbeTarget, cfg health.ProbeConfig) health.ProbeResult {
	return health.ProbeResult{InstanceID: target.InstanceID, RTT: 5 * time.Millisecond, Success: true}
}

func (successfulHealthProber) Type() string { return health.ProbeTypeICMP }

type fakeBirdProcessManager struct {
	started   bool
	startSpec bird.BirdInstanceSpec
	onStart   func(bird.BirdInstanceSpec)
	startErr  error
	stopped   bool
	stopSpec  bird.BirdInstanceSpec
	stopErr   error
	running   bool
	lastExit  *bird.ProcessExit
}

func (f *fakeBirdProcessManager) Start(ctx context.Context, spec bird.BirdInstanceSpec) error {
	f.started = true
	f.startSpec = spec
	if f.onStart != nil {
		f.onStart(spec)
	}
	return f.startErr
}

func (f *fakeBirdProcessManager) Stop(ctx context.Context, spec bird.BirdInstanceSpec) error {
	f.stopped = true
	f.stopSpec = spec
	f.running = false
	return f.stopErr
}

func (f *fakeBirdProcessManager) IsRunning(ctx context.Context) bool {
	return f.running
}

func (f *fakeBirdProcessManager) LastExit() *bird.ProcessExit {
	exit := f.lastExit
	f.lastExit = nil
	return exit
}

type fakeBirdClient struct {
	statusErr          error
	status             *bird.BirdObservation
	configureErr       error
	statusCalled       bool
	configureCalls     int
	configureSoftCalls int
	configurePath      string
	configureSoftPath  string
	raw                map[string]string
	rawErr             error
	rawCommands        []string
}

func (f *fakeBirdClient) Status(ctx context.Context) (*bird.BirdObservation, error) {
	f.statusCalled = true
	if f.status != nil {
		return f.status, f.statusErr
	}
	return &bird.BirdObservation{}, f.statusErr
}

func (f *fakeBirdClient) Configure(ctx context.Context, path string) error {
	f.configureCalls++
	f.configurePath = path
	return f.configureErr
}

func (f *fakeBirdClient) ConfigureSoft(ctx context.Context, path string) error {
	f.configureSoftCalls++
	f.configureSoftPath = path
	return f.configureErr
}

func (f *fakeBirdClient) Raw(ctx context.Context, cmd string) (string, error) {
	f.rawCommands = append(f.rawCommands, cmd)
	if f.raw != nil {
		return f.raw[cmd], f.rawErr
	}
	return "", f.rawErr
}

func boolPtr(v bool) *bool { return &v }

func buildTestRoutingOwners(t *testing.T) (*corestate.VerifiedState, *corestate.GossipCheckpoint, *photonlinux.LinuxState, *appConfig) {
	t.Helper()

	rootPub, rootPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(root): %v", err)
	}
	catofesPub, catofesPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(catofes): %v", err)
	}
	nodeAPub, nodeAPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(node-a): %v", err)
	}
	nodeBPub, nodeBPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(node-b): %v", err)
	}

	rootAuthority := &zone.ZoneAuthority{
		Zone:      zone.RootZone,
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: rootPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermDelegate},
			}},
		}},
	}
	catofesAuthority := &zone.ZoneAuthority{
		Zone:      "catofes.",
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: catofesPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermDelegate},
			}},
		}},
	}
	nodeAAuthority := &zone.ZoneAuthority{
		Zone:      "node-a.catofes.",
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: nodeAPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermWrite},
			}},
		}},
	}
	nodeBAuthority := &zone.ZoneAuthority{
		Zone:      "node-b.catofes.",
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: nodeBPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermWrite},
			}},
		}},
	}

	catofesDelegation := &zone.Delegation{
		ZoneName:  "catofes.",
		Scope:     zone.DelegationScopeDirectChild,
		Authority: *catofesAuthority,
	}
	if err := photoncrypto.SignDelegation(catofesDelegation, zone.RootZone, rootPriv); err != nil {
		t.Fatalf("SignDelegation(catofes): %v", err)
	}
	nodeADelegation := &zone.Delegation{
		ZoneName:  "node-a.catofes.",
		Scope:     zone.DelegationScopeDirectChild,
		Authority: *nodeAAuthority,
	}
	if err := photoncrypto.SignDelegation(nodeADelegation, "catofes.", catofesPriv); err != nil {
		t.Fatalf("SignDelegation(node-a): %v", err)
	}
	nodeBDelegation := &zone.Delegation{
		ZoneName:  "node-b.catofes.",
		Scope:     zone.DelegationScopeDirectChild,
		Authority: *nodeBAuthority,
	}
	if err := photoncrypto.SignDelegation(nodeBDelegation, "catofes.", catofesPriv); err != nil {
		t.Fatalf("SignDelegation(node-b): %v", err)
	}

	ns := zone.NewNetworkState()
	ns.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, rootAuthority)
	ns.Zones["catofes."] = zone.NewZoneState("catofes.", catofesAuthority)
	ns.Zones["node-a.catofes."] = zone.NewZoneState("node-a.catofes.", nodeAAuthority)
	ns.Zones["node-b.catofes."] = zone.NewZoneState("node-b.catofes.", nodeBAuthority)
	ns.Zones[zone.RootZone].Delegations["catofes."] = catofesDelegation
	ns.Zones["catofes."].Delegations["node-a.catofes."] = nodeADelegation
	ns.Zones["catofes."].Delegations["node-b.catofes."] = nodeBDelegation

	configureValidation(ns)

	now := time.Unix(123, 0)
	if err := photoncrypto.VerifyChain(ns, "catofes.", now); err != nil {
		t.Fatalf("VerifyChain(catofes): %v", err)
	}
	if err := photoncrypto.VerifyChain(ns, "node-a.catofes.", now); err != nil {
		t.Fatalf("VerifyChain(node-a): %v", err)
	}
	if err := photoncrypto.VerifyChain(ns, "node-b.catofes.", now); err != nil {
		t.Fatalf("VerifyChain(node-b): %v", err)
	}

	verified := &corestate.VerifiedState{
		ManagedZone:        "node-a.catofes.",
		Network:            ns,
		IdentityPrivateKey: nodeAPriv,
	}
	addIPAMPool(t, verified.Network, zone.RootZone, "10.0.0.0/8", zone.RootZone, time.Unix(123, 0), rootPriv)
	addIPAMPool(t, verified.Network, zone.RootZone, "10.0.0.0/16", "catofes.", time.Unix(124, 0), rootPriv)
	addIPAMPool(t, verified.Network, zone.RootZone, "10.1.0.0/16", "catofes.", time.Unix(125, 0), rootPriv)
	config := &appConfig{
		PeerID:     "node-a.catofes.",
		ListenAddr: "127.0.0.1:0",
	}

	// Pool delegations covering the assignments below.
	addIPAMPool(t, verified.Network, "catofes.", "10.0.0.0/16", "catofes.", now, catofesPriv)
	addIPAMPool(t, verified.Network, "catofes.", "10.1.0.0/16", "catofes.", now, catofesPriv)

	// Assign prefixes and announce routes.
	addRouteAssignment(t, verified.Network, "catofes.", "10.0.0.0/16", "node-a.catofes.", true, now, catofesPriv)
	addRouteAssignment(t, verified.Network, "catofes.", "10.1.0.0/16", "node-b.catofes.", true, now, catofesPriv)
	addRouteAnnouncement(t, verified.Network, "node-a.catofes.", "10.0.0.0/24", true, now, nodeAPriv)
	addRouteAnnouncement(t, verified.Network, "node-b.catofes.", "10.1.0.0/24", true, now, nodeBPriv)

	return verified, &corestate.GossipCheckpoint{}, &photonlinux.LinuxState{}, config
}

func buildDryRunSmokeOwners(t *testing.T) (*corestate.VerifiedState, *corestate.GossipCheckpoint, *photonlinux.LinuxState, *appConfig, map[zone.ZonePath]ed25519.PrivateKey) {
	t.Helper()

	rootPub, rootPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(root): %v", err)
	}
	catofesPub, catofesPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(catofes): %v", err)
	}
	nodeAPub, nodeAPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(node-a): %v", err)
	}
	nodeBPub, nodeBPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(node-b): %v", err)
	}

	rootAuthority := &zone.ZoneAuthority{
		Zone:      zone.RootZone,
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: rootPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermDelegate},
			}},
		}},
	}
	catofesAuthority := &zone.ZoneAuthority{
		Zone:      "catofes.",
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: catofesPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermDelegate},
			}},
		}},
	}
	nodeAAuthority := &zone.ZoneAuthority{
		Zone:      "node-a.catofes.",
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: nodeAPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermWrite},
			}},
		}},
	}
	nodeBAuthority := &zone.ZoneAuthority{
		Zone:      "node-b.catofes.",
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: nodeBPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermWrite},
			}},
		}},
	}

	catofesDelegation := &zone.Delegation{
		ZoneName:  "catofes.",
		Scope:     zone.DelegationScopeDirectChild,
		Authority: *catofesAuthority,
	}
	if err := photoncrypto.SignDelegation(catofesDelegation, zone.RootZone, rootPriv); err != nil {
		t.Fatalf("SignDelegation(catofes): %v", err)
	}
	nodeADelegation := &zone.Delegation{
		ZoneName:  "node-a.catofes.",
		Scope:     zone.DelegationScopeDirectChild,
		Authority: *nodeAAuthority,
	}
	if err := photoncrypto.SignDelegation(nodeADelegation, "catofes.", catofesPriv); err != nil {
		t.Fatalf("SignDelegation(node-a): %v", err)
	}
	nodeBDelegation := &zone.Delegation{
		ZoneName:  "node-b.catofes.",
		Scope:     zone.DelegationScopeDirectChild,
		Authority: *nodeBAuthority,
	}
	if err := photoncrypto.SignDelegation(nodeBDelegation, "catofes.", catofesPriv); err != nil {
		t.Fatalf("SignDelegation(node-b): %v", err)
	}

	ns := zone.NewNetworkState()
	ns.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, rootAuthority)
	ns.Zones["catofes."] = zone.NewZoneState("catofes.", catofesAuthority)
	ns.Zones["node-a.catofes."] = zone.NewZoneState("node-a.catofes.", nodeAAuthority)
	ns.Zones["node-b.catofes."] = zone.NewZoneState("node-b.catofes.", nodeBAuthority)
	ns.Zones[zone.RootZone].Delegations["catofes."] = catofesDelegation
	ns.Zones["catofes."].Delegations["node-a.catofes."] = nodeADelegation
	ns.Zones["catofes."].Delegations["node-b.catofes."] = nodeBDelegation

	configureValidation(ns)

	now := time.Unix(123, 0)
	if err := photoncrypto.VerifyChain(ns, "catofes.", now); err != nil {
		t.Fatalf("VerifyChain(catofes): %v", err)
	}
	if err := photoncrypto.VerifyChain(ns, "node-a.catofes.", now); err != nil {
		t.Fatalf("VerifyChain(node-a): %v", err)
	}
	if err := photoncrypto.VerifyChain(ns, "node-b.catofes.", now); err != nil {
		t.Fatalf("VerifyChain(node-b): %v", err)
	}

	verified := &corestate.VerifiedState{
		ManagedZone:        "node-a.catofes.",
		Network:            ns,
		IdentityPrivateKey: nodeAPriv,
	}
	addIPAMPool(t, verified.Network, zone.RootZone, "10.0.0.0/8", zone.RootZone, time.Unix(123, 0), rootPriv)
	addIPAMPool(t, verified.Network, zone.RootZone, "10.0.0.0/16", "catofes.", time.Unix(124, 0), rootPriv)
	addIPAMPool(t, verified.Network, zone.RootZone, "10.1.0.0/16", "catofes.", time.Unix(125, 0), rootPriv)
	config := &appConfig{
		PeerID:     "node-a.catofes.",
		ListenAddr: "127.0.0.1:0",
	}
	signers := map[zone.ZonePath]ed25519.PrivateKey{
		zone.RootZone:     rootPriv,
		"catofes.":        catofesPriv,
		"node-a.catofes.": nodeAPriv,
		"node-b.catofes.": nodeBPriv,
	}

	// Pool delegations covering the assignments below.
	addIPAMPool(t, verified.Network, "catofes.", "10.0.0.0/16", "catofes.", now, catofesPriv)
	addIPAMPool(t, verified.Network, "catofes.", "10.1.0.0/16", "catofes.", now, catofesPriv)

	// IPAM assignments in catofes. for the two leaf nodes.
	addRouteAssignment(t, verified.Network, "catofes.", "10.0.0.0/16", "node-a.catofes.", true, now, catofesPriv)
	addRouteAssignment(t, verified.Network, "catofes.", "10.1.0.0/16", "node-b.catofes.", true, now, catofesPriv)

	// Active route announcements in the respective leaf zones.
	addRouteAnnouncement(t, verified.Network, "node-a.catofes.", "10.0.1.0/24", true, now, nodeAPriv)
	addRouteAnnouncement(t, verified.Network, "node-b.catofes.", "10.1.1.0/24", true, now, nodeBPriv)

	return verified, &corestate.GossipCheckpoint{}, &photonlinux.LinuxState{}, config, signers
}

func buildIPAMRoutingSmokeOwners(t *testing.T) (*corestate.VerifiedState, *corestate.GossipCheckpoint, *photonlinux.LinuxState, *appConfig, map[zone.ZonePath]ed25519.PrivateKey, *AppContext) {
	t.Helper()

	rootPub, rootPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(root): %v", err)
	}
	catofesPub, catofesPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(catofes): %v", err)
	}
	nodeAPub, nodeAPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(node-a): %v", err)
	}

	rootAuthority := &zone.ZoneAuthority{
		Zone:      zone.RootZone,
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: rootPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermDelegate},
			}},
		}},
	}
	catofesAuthority := &zone.ZoneAuthority{
		Zone:      "catofes.",
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: catofesPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermDelegate, zone.PermAllocateIP},
			}},
		}},
	}
	nodeAAuthority := &zone.ZoneAuthority{
		Zone:      "node-a.catofes.",
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: nodeAPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermWrite},
			}},
		}},
	}

	catofesDelegation := &zone.Delegation{
		ZoneName:  "catofes.",
		Scope:     zone.DelegationScopeDirectChild,
		Authority: *catofesAuthority,
	}
	if err := photoncrypto.SignDelegation(catofesDelegation, zone.RootZone, rootPriv); err != nil {
		t.Fatalf("SignDelegation(catofes): %v", err)
	}
	nodeADelegation := &zone.Delegation{
		ZoneName:  "node-a.catofes.",
		Scope:     zone.DelegationScopeDirectChild,
		Authority: *nodeAAuthority,
	}
	if err := photoncrypto.SignDelegation(nodeADelegation, "catofes.", catofesPriv); err != nil {
		t.Fatalf("SignDelegation(node-a): %v", err)
	}

	ns := zone.NewNetworkState()
	ns.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, rootAuthority)
	ns.Zones["catofes."] = zone.NewZoneState("catofes.", catofesAuthority)
	ns.Zones["node-a.catofes."] = zone.NewZoneState("node-a.catofes.", nodeAAuthority)
	ns.Zones[zone.RootZone].Delegations["catofes."] = catofesDelegation
	ns.Zones["catofes."].Delegations["node-a.catofes."] = nodeADelegation

	configureValidation(ns)

	now := time.Unix(123, 0)
	if err := photoncrypto.VerifyChain(ns, "catofes.", now); err != nil {
		t.Fatalf("VerifyChain(catofes): %v", err)
	}
	if err := photoncrypto.VerifyChain(ns, "node-a.catofes.", now); err != nil {
		t.Fatalf("VerifyChain(node-a): %v", err)
	}

	verified := &corestate.VerifiedState{
		ManagedZone:        "node-a.catofes.",
		Network:            ns,
		IdentityPrivateKey: nodeAPriv,
	}
	addIPAMPool(t, verified.Network, zone.RootZone, "10.0.0.0/8", zone.RootZone, time.Unix(123, 0), rootPriv)
	addIPAMPool(t, verified.Network, zone.RootZone, "10.0.0.0/16", "catofes.", time.Unix(124, 0), rootPriv)
	config := &appConfig{
		PeerID:     "node-a.catofes.",
		ListenAddr: "127.0.0.1:0",
	}
	signers := map[zone.ZonePath]ed25519.PrivateKey{
		zone.RootZone:     rootPriv,
		"catofes.":        catofesPriv,
		"node-a.catofes.": nodeAPriv,
	}

	appConfig := defaultAppConfig()
	appConfig.DataDir = t.TempDir()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{{
		ID:              "ipsec-main",
		Provider:        ipsec.ProviderStrongSwan,
		NetNS:           ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "photontesth2", Create: true},
		DefaultPathMode: ipsec.PathModeFamilyRedundant,
	}}
	appConfig.Netns = netnsConfig{Names: map[string]ipsec.NetNSSpec{"photontesth2": {Kind: ipsec.NetNSName, Name: "photontesth2", Create: true}}}
	appConfig.Routing, _ = parseRoutingConfigInstances([]routingInstanceYAML{{ID: "ipsec-main", NetNS: "photontesth2", Enabled: boolPtr(true), Mode: ipsec.RoutingModeManaged}}, appConfig.Netns, appConfig.DataDir)

	rt := &AppContext{
		Config: appConfig,
		Clock:  func() time.Time { return time.Unix(4000, 0) },
	}

	return verified, &corestate.GossipCheckpoint{}, &photonlinux.LinuxState{}, config, signers, rt
}

func addIPAMPool(t *testing.T, network *zone.NetworkState, source zone.ZonePath, prefix string, delegatedTo zone.ZonePath, now time.Time, signer ed25519.PrivateKey) {
	t.Helper()
	canonical, err := routing.CanonicalizePrefix(prefix)
	if err != nil {
		t.Fatalf("invalid prefix %q: %v", prefix, err)
	}
	key, err := routing.NormalizeIPAMPoolKey(prefix)
	if err != nil {
		t.Fatalf("normalize pool key: %v", err)
	}
	record := routing.IPAMPoolRecord{Version: 1, Prefix: canonical, DelegatedTo: delegatedTo, Active: true}
	value, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("marshal pool: %v", err)
	}
	signed, err := buildSignedRecordAt(network, signer, source, key, value, routing.RecordTypeIPAMPool, now)
	if err != nil {
		t.Fatalf("buildSignedRecordAt: %v", err)
	}
	network.Zones[source].Records[key] = signed
}

func addRouteAssignment(t *testing.T, network *zone.NetworkState, source zone.ZonePath, prefix string, assignedTo zone.ZonePath, active bool, now time.Time, signer ed25519.PrivateKey) {
	t.Helper()
	canonical, err := routing.CanonicalizePrefix(prefix)
	if err != nil {
		t.Fatalf("invalid prefix %q: %v", prefix, err)
	}
	key, err := routing.NormalizeIPAMAssignmentKey(prefix)
	if err != nil {
		t.Fatalf("normalize assignment key: %v", err)
	}
	record := routing.IPAMAssignmentRecord{Version: 1, Prefix: canonical, AssignedTo: assignedTo, Active: active}
	value, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("marshal assignment: %v", err)
	}
	signed, err := buildSignedRecordAt(network, signer, source, key, value, routing.RecordTypeIPAMAssignment, now)
	if err != nil {
		t.Fatalf("buildSignedRecordAt: %v", err)
	}
	network.Zones[source].Records[key] = signed
}

func addRouteAnnouncement(t *testing.T, network *zone.NetworkState, path zone.ZonePath, prefix string, active bool, now time.Time, signer ed25519.PrivateKey) {
	t.Helper()
	canonical, err := routing.CanonicalizePrefix(prefix)
	if err != nil {
		t.Fatalf("invalid prefix %q: %v", prefix, err)
	}
	key, err := routing.NormalizeRouteAnnouncementKey(prefix)
	if err != nil {
		t.Fatalf("normalize route key: %v", err)
	}
	record := routing.RouteAnnouncementRecord{Version: 1, Prefix: canonical, Active: active}
	value, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("marshal route announcement: %v", err)
	}
	signed, err := buildSignedRecordAt(network, signer, path, key, value, routing.RecordTypeRouteAnnouncement, now)
	if err != nil {
		t.Fatalf("buildSignedRecordAt: %v", err)
	}
	network.Zones[path].Records[key] = signed
}

func readFileString(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func buildAutoAnnounceTestState(t *testing.T, managedZone zone.ZonePath, assignments []string, announcements map[string]bool) (*corestate.VerifiedState, *AppContext) {
	t.Helper()
	rootPub, rootPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(root): %v", err)
	}
	catofesPub, catofesPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(catofes): %v", err)
	}
	managedPub, managedPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(managed): %v", err)
	}

	rootAuthority := &zone.ZoneAuthority{
		Zone:      zone.RootZone,
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: rootPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermDelegate},
			}},
		}},
	}
	catofesAuthority := &zone.ZoneAuthority{
		Zone:      "catofes.",
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: catofesPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermDelegate, zone.PermAllocateIP},
			}},
		}},
	}
	managedAuthority := &zone.ZoneAuthority{
		Zone:      managedZone,
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: managedPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermWrite},
			}},
		}},
	}

	ns := zone.NewNetworkState()
	ns.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, rootAuthority)
	ns.Zones["catofes."] = zone.NewZoneState("catofes.", catofesAuthority)
	ns.Zones[managedZone] = zone.NewZoneState(managedZone, managedAuthority)

	catofesDelegation := testSignedDelegation(t, "catofes.", *catofesAuthority, zone.RootZone, rootPriv)
	managedDelegation := testSignedDelegation(t, managedZone, *managedAuthority, "catofes.", catofesPriv)
	ns.Zones[zone.RootZone].Delegations["catofes."] = catofesDelegation
	ns.Zones["catofes."].Delegations[managedZone] = managedDelegation
	addIPAMPool(t, ns, zone.RootZone, "10.0.0.0/8", zone.RootZone, time.Unix(1, 0), rootPriv)
	addIPAMPool(t, ns, zone.RootZone, "10.0.0.0/16", "catofes.", time.Unix(2, 0), rootPriv)

	poolRecord := routing.IPAMPoolRecord{Version: 1, Prefix: "10.0.0.0/16", DelegatedTo: "catofes.", Active: true}
	poolValue, err := json.Marshal(poolRecord)
	if err != nil {
		t.Fatalf("marshal pool: %v", err)
	}
	poolKey, err := routing.NormalizeIPAMPoolKey("10.0.0.0/16")
	if err != nil {
		t.Fatalf("normalize pool key: %v", err)
	}
	poolRec, err := buildSignedRecordAt(ns, catofesPriv, "catofes.", poolKey, poolValue, routing.RecordTypeIPAMPool, time.Unix(1, 0))
	if err != nil {
		t.Fatalf("sign pool: %v", err)
	}
	ns.Zones["catofes."].Records[poolKey] = poolRec

	for _, prefix := range assignments {
		assignRecord := routing.IPAMAssignmentRecord{Version: 1, Prefix: prefix, AssignedTo: managedZone, Active: true}
		assignValue, err := json.Marshal(assignRecord)
		if err != nil {
			t.Fatalf("marshal assignment: %v", err)
		}
		assignKey, err := routing.NormalizeIPAMAssignmentKey(prefix)
		if err != nil {
			t.Fatalf("normalize assignment key: %v", err)
		}
		assignRec, err := buildSignedRecordAt(ns, catofesPriv, "catofes.", assignKey, assignValue, routing.RecordTypeIPAMAssignment, time.Unix(1, 0))
		if err != nil {
			t.Fatalf("sign assignment: %v", err)
		}
		ns.Zones["catofes."].Records[assignKey] = assignRec
	}

	for prefix, active := range announcements {
		annRecord := routing.RouteAnnouncementRecord{Version: 1, Prefix: prefix, Active: active}
		annValue, err := json.Marshal(annRecord)
		if err != nil {
			t.Fatalf("marshal announcement: %v", err)
		}
		annKey, err := routing.NormalizeRouteAnnouncementKey(prefix)
		if err != nil {
			t.Fatalf("normalize announcement key: %v", err)
		}
		annRec, err := buildSignedRecordAt(ns, managedPriv, managedZone, annKey, annValue, routing.RecordTypeRouteAnnouncement, time.Unix(1, 0))
		if err != nil {
			t.Fatalf("sign announcement: %v", err)
		}
		ns.Zones[managedZone].Records[annKey] = annRec
	}

	configureValidation(ns)
	for _, path := range []zone.ZonePath{"catofes.", managedZone} {
		if err := photoncrypto.VerifyChain(ns, path, time.Unix(1000, 0)); err != nil {
			t.Fatalf("VerifyChain(%s): %v", path, err)
		}
	}

	verified := &corestate.VerifiedState{
		ManagedZone:        managedZone,
		Network:            ns,
		IdentityPrivateKey: managedPriv,
		RootPrivateKey:     rootPriv,
	}
	rt := &AppContext{
		Config: &appConfig{IPAM: ipamConfig{AutoAnnounceAssignedIPs: true}},
		Clock:  func() time.Time { return time.Unix(1000, 0) },
	}
	return verified, rt
}
