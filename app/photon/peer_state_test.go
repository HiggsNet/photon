package main

import (
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

// buildPeerStateTestOwners creates typed common/checkpoint/Linux owners for peer lifecycle
// tests: root -> catofes. -> node-a.catofes./node-b.catofes. with signed
// delegations. The managed zone is node-a.catofes.
type peerStateTestOwners struct {
	verified             *corestate.VerifiedState
	checkpoint           *corestate.GossipCheckpoint
	observationLinks     map[string]linkInstanceState
	observationReconcile *ipsecObservationSummary
}

func buildPeerStateTestOwners(t *testing.T) (*peerStateTestOwners, ed25519.PrivateKey, ed25519.PrivateKey, ed25519.PrivateKey) {
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
		Keys:      []zone.AuthorizedKey{{Key: rootPub, Capabilities: []zone.Capability{{Permissions: []zone.Permission{zone.PermDelegate}}}}},
	}
	catofesAuthority := &zone.ZoneAuthority{
		Zone:      "catofes.",
		Epoch:     1,
		Threshold: 1,
		Keys:      []zone.AuthorizedKey{{Key: catofesPub, Capabilities: []zone.Capability{{Permissions: []zone.Permission{zone.PermDelegate}}}}},
	}
	nodeAAuthority := &zone.ZoneAuthority{
		Zone:      "node-a.catofes.",
		Epoch:     1,
		Threshold: 1,
		Keys:      []zone.AuthorizedKey{{Key: nodeAPub, Capabilities: []zone.Capability{{Permissions: []zone.Permission{zone.PermWrite}}}}},
	}
	nodeBAuthority := &zone.ZoneAuthority{
		Zone:      "node-b.catofes.",
		Epoch:     1,
		Threshold: 1,
		Keys:      []zone.AuthorizedKey{{Key: nodeBPub, Capabilities: []zone.Capability{{Permissions: []zone.Permission{zone.PermWrite}}}}},
	}

	catofesDelegation := &zone.Delegation{ZoneName: "catofes.", Scope: zone.DelegationScopeDirectChild, Authority: *catofesAuthority}
	if err := photoncrypto.SignDelegation(catofesDelegation, zone.RootZone, rootPriv); err != nil {
		t.Fatalf("SignDelegation(catofes): %v", err)
	}
	nodeADelegation := &zone.Delegation{ZoneName: "node-a.catofes.", Scope: zone.DelegationScopeDirectChild, Authority: *nodeAAuthority}
	if err := photoncrypto.SignDelegation(nodeADelegation, "catofes.", catofesPriv); err != nil {
		t.Fatalf("SignDelegation(node-a): %v", err)
	}
	nodeBDelegation := &zone.Delegation{ZoneName: "node-b.catofes.", Scope: zone.DelegationScopeDirectChild, Authority: *nodeBAuthority}
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
	now := time.Unix(1000, 0)
	if err := photoncrypto.VerifyChain(ns, "catofes.", now); err != nil {
		t.Fatalf("VerifyChain(catofes): %v", err)
	}
	if err := photoncrypto.VerifyChain(ns, "node-a.catofes.", now); err != nil {
		t.Fatalf("VerifyChain(node-a): %v", err)
	}
	if err := photoncrypto.VerifyChain(ns, "node-b.catofes.", now); err != nil {
		t.Fatalf("VerifyChain(node-b): %v", err)
	}

	owners := &peerStateTestOwners{
		verified: &corestate.VerifiedState{
			ManagedZone:        "node-a.catofes.",
			Network:            ns,
			IdentityPrivateKey: nodeAPriv,
		},
		checkpoint:       &corestate.GossipCheckpoint{Peers: make(map[string]corestate.PeerCheckpoint)},
		observationLinks: make(map[string]linkInstanceState),
	}
	return owners, catofesPriv, nodeAPriv, nodeBPriv
}

// addRevocationToParent creates a signed revocation/tombstone for the given
// child zone in the parent zone state. The now parameter sets RevokedAt so the
// revocation is active at the test's simulated time.
func addRevocationToParent(t *testing.T, network *zone.NetworkState, parentZone, childZone zone.ZonePath, signer ed25519.PrivateKey, now time.Time) {
	t.Helper()
	parentState := network.Zones[parentZone]
	if parentState == nil {
		t.Fatalf("parent zone %s not found", parentZone)
	}
	revocation := &zone.DelegationRevocation{
		ChildZone:             childZone,
		ParentZone:            parentZone,
		RevokedAuthorityEpoch: 1,
		Reason:                "test revocation",
		RevokedAt:             now.Unix(),
		TTLSeconds:            int64(time.Hour.Seconds()),
	}
	if err := photoncrypto.SignDelegationRevocation(revocation, parentZone, signer); err != nil {
		t.Fatalf("SignDelegationRevocation(%s): %v", childZone, err)
	}
	parentState.Revocations[childZone] = revocation
	delete(parentState.Delegations, childZone)
}

func peerStatusForTest(owners *peerStateTestOwners, peerID string, peerZone zone.ZonePath, now time.Time, cfg inspect.PeerLifecycleConfig) inspect.PeerStatusInfo {
	return inspect.BuildPeerLifecycleStatus(peerLifecycleInput(
		owners.verified.Network, owners.checkpoint, owners.observationLinks, owners.observationReconcile,
		peerID, peerZone, now, cfg, false,
	))
}

func TestDerivePeerStatusRevoked(t *testing.T) {
	state, catofesPriv, _, _ := buildPeerStateTestOwners(t)
	now := time.Unix(2000, 0)
	cfg := inspect.DefaultPeerLifecycleConfig()

	// Before revocation: node-b should not be revoked.
	info := peerStatusForTest(state, "node-b.catofes.", "node-b.catofes.", now, cfg)
	if info.State == inspect.PeerStateRevoked {
		t.Fatalf("peer should not be revoked before revocation is added, got state=%s", info.State)
	}

	// Add revocation for node-b in catofes parent zone.
	addRevocationToParent(t, state.verified.Network, "catofes.", "node-b.catofes.", catofesPriv, now)

	// After revocation: node-b should be revoked, overriding any other state.
	info = peerStatusForTest(state, "node-b.catofes.", "node-b.catofes.", now, cfg)
	if info.State != inspect.PeerStateRevoked {
		t.Fatalf("state = %s, want revoked", info.State)
	}
	if info.Reason != "zone_revoked" {
		t.Fatalf("reason = %s, want zone_revoked", info.Reason)
	}
}

func TestDerivePeerStatusActiveWithUpLink(t *testing.T) {
	state, _, _, _ := buildPeerStateTestOwners(t)
	now := time.Unix(2000, 0)
	cfg := inspect.DefaultPeerLifecycleConfig()

	// Add a LinkInstance for node-b that is up.
	state.observationLinks["link-node-b"] = linkInstanceState{
		ID:             "link-node-b",
		PeerZone:       "node-b.catofes.",
		ActualState:    "up",
		LastTransition: now.Unix(),
	}

	info := peerStatusForTest(state, "node-b.catofes.", "node-b.catofes.", now, cfg)
	if info.State != inspect.PeerStateActive {
		t.Fatalf("state = %s, want active", info.State)
	}
	if info.UpLinks != 1 {
		t.Fatalf("up_links = %d, want 1", info.UpLinks)
	}
	if info.ActualLinks != 1 {
		t.Fatalf("actual_links = %d, want 1", info.ActualLinks)
	}
}

func TestDerivePeerStatusConnectingWithNonUpLink(t *testing.T) {
	state, _, _, _ := buildPeerStateTestOwners(t)
	now := time.Unix(2000, 0)
	cfg := inspect.DefaultPeerLifecycleConfig()

	// Add a LinkInstance for node-b that is connecting (not up).
	state.observationLinks["link-node-b"] = linkInstanceState{
		ID:             "link-node-b",
		PeerZone:       "node-b.catofes.",
		ActualState:    "connecting",
		LastTransition: now.Unix(),
	}

	info := peerStatusForTest(state, "node-b.catofes.", "node-b.catofes.", now, cfg)
	if info.State != inspect.PeerStateConnecting {
		t.Fatalf("state = %s, want connecting", info.State)
	}
}

func TestDerivePeerStatusStaleAfterThreshold(t *testing.T) {
	state, _, _, _ := buildPeerStateTestOwners(t)
	now := time.Unix(2000, 0)
	cfg := inspect.DefaultPeerLifecycleConfig() // stale_after=15m, offline_after=12h

	// Set last sync to 20 minutes ago; should be stale but not offline.
	lastSync := now.Add(-20 * time.Minute)
	state.checkpoint.Peers["node-b.catofes."] = corestate.PeerCheckpoint{
		LastSyncUnix: lastSync.Unix(),
	}

	info := peerStatusForTest(state, "node-b.catofes.", "node-b.catofes.", now, cfg)
	if info.State != inspect.PeerStateStale {
		t.Fatalf("state = %s, want stale", info.State)
	}
	if info.Reason != "stale_after_exceeded" {
		t.Fatalf("reason = %s, want stale_after_exceeded", info.Reason)
	}
}

func TestDerivePeerStatusOfflineAfterThreshold(t *testing.T) {
	state, _, _, _ := buildPeerStateTestOwners(t)
	now := time.Unix(2000, 0)
	cfg := inspect.DefaultPeerLifecycleConfig() // offline_after=12h, cleanup_after=48h

	// Set last sync to 13 hours ago; should be offline but not cleanup due.
	lastSync := now.Add(-13 * time.Hour)
	state.checkpoint.Peers["node-b.catofes."] = corestate.PeerCheckpoint{
		LastSyncUnix: lastSync.Unix(),
	}

	info := peerStatusForTest(state, "node-b.catofes.", "node-b.catofes.", now, cfg)
	if info.State != inspect.PeerStateOffline {
		t.Fatalf("state = %s, want offline", info.State)
	}
	if info.Reason != "offline_after_exceeded" {
		t.Fatalf("reason = %s, want offline_after_exceeded", info.Reason)
	}
}

func TestDerivePeerStatusCleanupAfterThreshold(t *testing.T) {
	state, _, _, _ := buildPeerStateTestOwners(t)
	now := time.Unix(2000, 0)
	cfg := inspect.DefaultPeerLifecycleConfig() // cleanup_after=48h

	// Set last sync to 49 hours ago; should be offline with cleanup due.
	lastSync := now.Add(-49 * time.Hour)
	state.checkpoint.Peers["node-b.catofes."] = corestate.PeerCheckpoint{
		LastSyncUnix: lastSync.Unix(),
	}

	info := peerStatusForTest(state, "node-b.catofes.", "node-b.catofes.", now, cfg)
	if info.State != inspect.PeerStateOffline {
		t.Fatalf("state = %s, want offline", info.State)
	}
	if info.Reason != "cleanup_after_exceeded" {
		t.Fatalf("reason = %s, want cleanup_after_exceeded", info.Reason)
	}
	if !inspect.PeerStatusRequiresCleanup(info) {
		t.Fatalf("inspect.PeerStatusRequiresCleanup should be true for cleanup_after_exceeded")
	}
}

func TestDerivePeerStatusCleanupAfterOverridesStaleLinkState(t *testing.T) {
	state, _, _, _ := buildPeerStateTestOwners(t)
	now := time.Unix(200_000, 0)
	cfg := inspect.DefaultPeerLifecycleConfig()
	state.checkpoint.Peers["node-b.catofes."] = corestate.PeerCheckpoint{
		LastSyncUnix: now.Add(-cfg.CleanupAfter - time.Minute).Unix(),
	}
	state.observationLinks["stale-link"] = linkInstanceState{
		ID:          "stale-link",
		PeerZone:    "node-b.catofes.",
		ActualState: "connecting",
	}

	info := peerStatusForTest(state, "node-b.catofes.", "node-b.catofes.", now, cfg)
	if info.State != inspect.PeerStateOffline || info.Reason != "cleanup_after_exceeded" {
		t.Fatalf("status = %+v, want cleanup_after_exceeded", info)
	}
}

func TestDerivePeerStatusNeverSeen(t *testing.T) {
	state, _, _, _ := buildPeerStateTestOwners(t)
	now := time.Unix(2000, 0)
	cfg := inspect.DefaultPeerLifecycleConfig()

	// No SyncPeers entry for node-b, no LinkInstance, no desired link.
	info := peerStatusForTest(state, "node-b.catofes.", "node-b.catofes.", now, cfg)
	// Without IPsec config, this should be eligible (no_overlay_config) since
	// the state alone has no IPsecReconcile.DesiredLinks.
	if info.State != inspect.PeerStateEligible && info.State != inspect.PeerStateOffline {
		t.Fatalf("state = %s, want eligible or offline", info.State)
	}
}

func TestCollectRevokedPeerZones(t *testing.T) {
	state, catofesPriv, _, _ := buildPeerStateTestOwners(t)
	now := time.Unix(2000, 0)

	// Before revocation: no revoked peers.
	revoked := collectRevokedPeerZones(state.verified.Network, state.observationLinks, state.checkpoint, now)
	if len(revoked) != 0 {
		t.Fatalf("expected 0 revoked zones, got %d", len(revoked))
	}

	// Add a LinkInstance for node-b.
	state.observationLinks["link-node-b"] = linkInstanceState{
		PeerZone: "node-b.catofes.",
	}
	// Add node-b to SyncPeers.
	state.checkpoint.Peers["node-b.catofes."] = corestate.PeerCheckpoint{}

	// Still no revoked zones.
	revoked = collectRevokedPeerZones(state.verified.Network, state.observationLinks, state.checkpoint, now)
	if len(revoked) != 0 {
		t.Fatalf("expected 0 revoked zones before revocation, got %d", len(revoked))
	}

	// Revoke node-b.
	addRevocationToParent(t, state.verified.Network, "catofes.", "node-b.catofes.", catofesPriv, now)

	// Now node-b should be in the revoked set (from both LinkInstances and SyncPeers).
	revoked = collectRevokedPeerZones(state.verified.Network, state.observationLinks, state.checkpoint, now)
	if !revoked["node-b.catofes."] {
		t.Fatalf("expected node-b.catofes. in revoked set, got %v", revoked)
	}
}

func TestParsePeerLifecycleConfig(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		config := defaultAppConfig()
		input := `
peer_lifecycle:
  stale_after: 5m
  offline_after: 30m
  cleanup_after: 2h
  keep_sa_while_stale: false
`
		if err := parseConfigYAML(input, config); err != nil {
			t.Fatalf("parseConfigYAML: %v", err)
		}
		if config.PeerLifecycle.StaleAfter != 5*time.Minute {
			t.Errorf("StaleAfter = %s, want 5m", config.PeerLifecycle.StaleAfter)
		}
		if config.PeerLifecycle.OfflineAfter != 30*time.Minute {
			t.Errorf("OfflineAfter = %s, want 30m", config.PeerLifecycle.OfflineAfter)
		}
		if config.PeerLifecycle.CleanupAfter != 2*time.Hour {
			t.Errorf("CleanupAfter = %s, want 2h", config.PeerLifecycle.CleanupAfter)
		}
		if config.PeerLifecycle.KeepSAWhileStale {
			t.Errorf("KeepSAWhileStale = true, want false")
		}
	})

	t.Run("stale_after >= offline_after rejected", func(t *testing.T) {
		config := defaultAppConfig()
		input := `
peer_lifecycle:
  stale_after: 30m
  offline_after: 30m
`
		err := parseConfigYAML(input, config)
		if err == nil {
			t.Fatalf("expected error for stale_after >= offline_after")
		}
		if !strings.Contains(err.Error(), "must be less than offline_after") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("offline_after >= cleanup_after rejected", func(t *testing.T) {
		config := defaultAppConfig()
		input := `
peer_lifecycle:
  offline_after: 1h
  cleanup_after: 1h
`
		err := parseConfigYAML(input, config)
		if err == nil {
			t.Fatalf("expected error for offline_after >= cleanup_after")
		}
		if !strings.Contains(err.Error(), "must be less than cleanup_after") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("invalid duration rejected", func(t *testing.T) {
		config := defaultAppConfig()
		input := `
peer_lifecycle:
  stale_after: not-a-duration
`
		err := parseConfigYAML(input, config)
		if err == nil {
			t.Fatalf("expected error for invalid duration")
		}
	})

	t.Run("missing uses defaults", func(t *testing.T) {
		config := defaultAppConfig()
		// No peer_lifecycle section — should use defaults from defaultAppConfig.
		// The field is zero-valued; normalizeAppConfig or explicit call fills defaults.
		norm := inspect.NormalizePeerLifecycleConfig(config.PeerLifecycle)
		def := inspect.DefaultPeerLifecycleConfig()
		if norm.StaleAfter != def.StaleAfter {
			t.Errorf("default StaleAfter = %s, want %s", norm.StaleAfter, def.StaleAfter)
		}
		if norm.OfflineAfter != def.OfflineAfter {
			t.Errorf("default OfflineAfter = %s, want %s", norm.OfflineAfter, def.OfflineAfter)
		}
		if norm.CleanupAfter != def.CleanupAfter {
			t.Errorf("default CleanupAfter = %s, want %s", norm.CleanupAfter, def.CleanupAfter)
		}
		if !norm.KeepSAWhileStale {
			t.Errorf("default KeepSAWhileStale = false, want true")
		}
	})
}

func TestDerivePeerStatusesAllPeers(t *testing.T) {
	state, _, _, _ := buildPeerStateTestOwners(t)
	now := time.Unix(2000, 0)
	cfg := inspect.DefaultPeerLifecycleConfig()

	// Add SyncPeers entries.
	state.checkpoint.Peers["node-b.catofes."] = corestate.PeerCheckpoint{
		LastSyncUnix: now.Add(-1 * time.Minute).Unix(),
	}

	peers := derivePeerStatuses(state.verified.ManagedZone, state.verified.Network, state.checkpoint, state.observationLinks, state.observationReconcile, now, cfg, false)
	if len(peers) == 0 {
		t.Fatalf("expected at least 1 peer, got 0")
	}

	// Should include node-b.catofes.
	foundNodeB := false
	for _, p := range peers {
		if p.PeerID == "node-b.catofes." {
			foundNodeB = true
		}
	}
	if !foundNodeB {
		t.Fatalf("expected node-b.catofes. in peer list, got %v", peers)
	}
}

func TestRevokedLinkPeersIncludesSyncPeers(t *testing.T) {
	state, catofesPriv, _, _ := buildPeerStateTestOwners(t)
	now := time.Unix(2000, 0)

	// Add node-b to SyncPeers (no LinkInstance).
	state.checkpoint.Peers["node-b.catofes."] = corestate.PeerCheckpoint{}

	// Before revocation: no revoked peers.
	revoked := revokedLinkPeers(state.verified.Network, state.observationLinks, state.checkpoint, now)
	if len(revoked) != 0 {
		t.Fatalf("expected 0 revoked, got %d", len(revoked))
	}

	// Revoke node-b.
	addRevocationToParent(t, state.verified.Network, "catofes.", "node-b.catofes.", catofesPriv, now)

	// After revocation: node-b should be in revoked set even without LinkInstance.
	revoked = revokedLinkPeers(state.verified.Network, state.observationLinks, state.checkpoint, now)
	if !revoked["node-b.catofes."] {
		t.Fatalf("expected node-b.catofes. in revoked set from SyncPeers, got %v", revoked)
	}
}
