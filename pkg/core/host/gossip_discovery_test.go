package host

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	"github.com/HiggsNet/photon/pkg/core/observability"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

func TestGossipDiscoveryPublishesAddressesWithoutPruningCheckpoints(t *testing.T) {
	now := time.Unix(1000, 0)
	const revoked = "revoked."
	const healthy = "healthy."
	network := zone.NewNetworkState()
	network.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, nil)
	network.Zones[zone.RootZone].Revocations[revoked] = &zone.DelegationRevocation{
		ParentZone: zone.RootZone, ChildZone: revoked, RevokedAt: now.Unix(),
	}
	wantErr := errors.New("checkpoint failed")
	writes := 0
	store := corestate.NewStoreWithCheckpoint(&corestate.VerifiedState{Network: network}, &corestate.GossipCheckpoint{
		Peers: map[string]corestate.PeerCheckpoint{
			revoked: {LastSuccessfulEndpoint: "192.0.2.1:33434"},
			healthy: {BackoffUntilUnix: now.Add(time.Minute).Unix()},
		},
	}, nil, func(context.Context, map[string]*corestate.PeerCheckpoint, corestate.VerifiedRevision) error {
		writes++
		if writes == 1 {
			return wantErr
		}
		return nil
	})
	driver := NewGossipDriver(newFakeClock(now), 1, store, GossipDriverConfig{
		Discovery: GossipDiscoveryConfig{Bootstrap: map[string]*net.UDPAddr{
			healthy: {IP: net.ParseIP("192.0.2.2"), Port: 33434},
		}},
	})
	defer driver.Stop()
	transport, _ := bindMemoryGossipTransport(t, driver, revoked)
	driver.Gossip.NewSession(revoked)
	driver.Gossip.DeferHint(revoked)
	driver.Observability.Update(revoked, now, func(peer *observability.PeerDiagnostics) { peer.HintAccepted = 1 })
	if err := driver.RefreshGossipDiscovery(now, transport); err != nil {
		t.Fatal(err)
	}
	if writes != 0 || transport.PeerAddr(revoked) != nil || transport.PeerAddr(healthy) == nil {
		t.Fatal("refresh wrote checkpoints or published the wrong addresses")
	}
	if _, err := driver.SyncGossipPeers(t.Context(), now, false); !errors.Is(err, wantErr) {
		t.Fatalf("first scan: %v, want checkpoint error", err)
	}
	if driver.Gossip.Session(revoked) != nil || driver.Gossip.TakePendingHint(revoked) {
		t.Fatal("revoked peer retained its session or hint after scanning")
	}
	if _, exists := driver.Observability.Snapshot(revoked, now); exists {
		t.Fatal("revoked peer retained its diagnostics after scanning")
	}
	if _, err := driver.SyncGossipPeers(t.Context(), now, false); err != nil {
		t.Fatalf("second scan: %v", err)
	}
	if _, exists := store.PeerCheckpoints([]string{revoked})[revoked]; exists || writes != 2 {
		t.Fatalf("checkpoint retained=%t, writes=%d", exists, writes)
	}
}

func TestPlanGossipDiscoveryIncludesVerifiedZoneAndDelegatedChild(t *testing.T) {
	now := time.Unix(1000, 0)
	network, _ := signedDiscoveryNetwork(t, "peer.catofes.", false, nil, now)
	plan := PlanGossipDiscovery(GossipDiscoveryInput{
		LocalPeerID: "local.catofes.", ManagedZone: "local.catofes.", Network: network,
	}, now)
	if !slices.Contains(plan.KnownPeerIDs, "peer.catofes.") {
		t.Fatalf("known peers = %v, want delegated child", plan.KnownPeerIDs)
	}

	network, _ = signedDiscoveryNetwork(t, "peer.catofes.", true, nil, now)
	plan = PlanGossipDiscovery(GossipDiscoveryInput{
		LocalPeerID: "local.catofes.", ManagedZone: "local.catofes.", Network: network,
	}, now)
	if !slices.Contains(plan.KnownPeerIDs, "peer.catofes.") {
		t.Fatalf("known peers = %v, want verified zone", plan.KnownPeerIDs)
	}
}

func TestPlanGossipDiscoveryRanksEndpointWithoutCheckpoint(t *testing.T) {
	now := time.Unix(1000, 0)
	entries := []gossip.EndpointEntry{
		{Address: "10.16.255.8", Port: 33435, Source: "interface", Priority: 200, LastObserved: now.Unix()},
		{Address: "203.0.113.10", Port: 33434, Source: "reflector", Priority: 10, LastObserved: now.Unix()},
	}
	network, _ := signedDiscoveryNetwork(t, "peer.catofes.", true, entries, now)
	plan := PlanGossipDiscovery(GossipDiscoveryInput{
		LocalPeerID: "local.catofes.", ManagedZone: "local.catofes.", Network: network,
	}, now)
	if addrs := plan.Addresses["peer.catofes."]; len(addrs) != 2 || addrs[0].String() != "203.0.113.10:33434" {
		t.Fatalf("addresses = %v, want public reflector first", addrs)
	}

	transport := &gossip.Transport{}
	ApplyGossipDiscoveryPlan(transport, plan)
	if addr := transport.PeerAddr("peer.catofes."); addr == nil || addr.String() != "203.0.113.10:33434" {
		t.Fatalf("published address = %v", addr)
	}
}

func TestPlanGossipDiscoveryReplacesAndExpiresEndpoint(t *testing.T) {
	now := time.Unix(1000, 0)
	const peerID = "peer.catofes."
	network, _ := signedDiscoveryNetwork(t, peerID, true, []gossip.EndpointEntry{{
		Address: "127.0.0.1", Port: 10000, Source: "advertise", LastObserved: now.Unix(),
	}}, now)
	transport := &gossip.Transport{}
	transport.AddPeer(peerID, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9999})
	ApplyGossipDiscoveryPlan(transport, PlanGossipDiscovery(GossipDiscoveryInput{Network: network}, now))
	if got := transport.PeerAddr(peerID); got == nil || got.String() != "127.0.0.1:10000" {
		t.Fatalf("replacement address = %v", got)
	}
	emptyNetwork, _ := signedDiscoveryNetwork(t, peerID, true, nil, now)
	ApplyGossipDiscoveryPlan(transport, PlanGossipDiscovery(GossipDiscoveryInput{Network: emptyNetwork}, now))
	if got := transport.PeerAddr(peerID); got != nil {
		t.Fatalf("expired address remained installed: %v", got)
	}
}

func TestObservedPathParticipatesInOutboundAndExpires(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	network, _ := signedDiscoveryNetwork(t, "peer.catofes.", true, nil, now)
	input := GossipDiscoveryInput{
		LocalPeerID: "local.catofes.", ManagedZone: "local.catofes.", Network: network,
		Peers: map[string]corestate.PeerCheckpoint{"peer.catofes.": {
			ObservedEndpoint: "127.0.0.1:2000", ObservedFirstSeenUnix: now.Unix(),
			ObservedLastSeenUnix: now.Unix(), ObservedUntilUnix: now.Add(time.Minute).Unix(),
			LastFailure: &corestate.PeerFailure{Code: corestate.PeerFailureTimeout, Message: "timed out", AtUnix: now.Unix()},
		}},
	}
	if peers := GossipOutboundPeers(input, now); len(peers) != 1 || peers[0] != "peer.catofes." {
		t.Fatalf("outbound peers = %v", peers)
	}
	transport := &gossip.Transport{}
	ApplyGossipDiscoveryPlan(transport, PlanGossipDiscovery(input, now))
	if addr := transport.ObservedPeerAddr("peer.catofes."); addr == nil || addr.String() != "127.0.0.1:2000" {
		t.Fatalf("observed address = %v", addr)
	}

	expiredAt := now.Add(2 * time.Minute)
	if peers := GossipOutboundPeers(input, expiredAt); len(peers) != 0 {
		t.Fatalf("outbound peers after expiry = %v", peers)
	}
	ApplyGossipDiscoveryPlan(transport, PlanGossipDiscovery(input, expiredAt))
	if addr := transport.ObservedPeerAddr("peer.catofes."); addr != nil {
		t.Fatalf("observed address after expiry = %v", addr)
	}
}

func TestPlanGossipDiscoveryObservedPathPreference(t *testing.T) {
	now := time.Unix(1000, 0)
	network, _ := signedDiscoveryNetwork(t, "peer.catofes.", true, nil, now)
	input := GossipDiscoveryInput{
		LocalPeerID: "local.catofes.", ManagedZone: "local.catofes.", Network: network,
		Peers: map[string]corestate.PeerCheckpoint{"peer.catofes.": {
			ObservedEndpoint: "127.0.0.1:2000", ObservedUntilUnix: now.Add(time.Minute).Unix(),
		}},
	}
	input.Bootstrap = map[string]*net.UDPAddr{"peer.catofes.": {IP: net.ParseIP("203.0.113.10"), Port: 9999}}
	if PlanGossipDiscovery(input, now).Peers["peer.catofes."].PreferObserved {
		t.Fatal("observed path preferred before direct endpoint failure")
	}
	peer := input.Peers["peer.catofes."]
	peer.LastFailure = &corestate.PeerFailure{Code: corestate.PeerFailureTimeout, Message: "timed out", AtUnix: now.Unix()}
	input.Peers["peer.catofes."] = peer
	if !PlanGossipDiscovery(input, now).Peers["peer.catofes."].PreferObserved {
		t.Fatal("observed path not preferred after direct endpoint failure")
	}
	peer.LastFailure = nil
	input.Bootstrap["peer.catofes."] = &net.UDPAddr{IP: net.ParseIP("10.16.255.8"), Port: 33435}
	input.Peers["peer.catofes."] = peer
	if !PlanGossipDiscovery(input, now).Peers["peer.catofes."].PreferObserved {
		t.Fatal("observed path not preferred over private discovered endpoint")
	}
}

func TestPlanVerifiedObservedCheckpointMovesPreviousPathToGrace(t *testing.T) {
	now := time.Unix(1000, 0)
	peerID := zone.ZonePath("peer.catofes.")
	network, _ := signedDiscoveryNetwork(t, peerID, true, nil, now)
	input := GossipDiscoveryInput{
		LocalPeerID: "local.catofes.", ManagedZone: "local.catofes.", Network: network,
		Peers: map[string]corestate.PeerCheckpoint{peerID.String(): {
			ObservedEndpoint: "198.51.100.10:33434", ObservedFirstSeenUnix: now.Add(-time.Minute).Unix(),
			ObservedUntilUnix: now.Add(time.Minute).Unix(),
		}},
	}
	patch, ok := PlanVerifiedObservedCheckpoint(input, peerID.String(), "198.51.100.20:33434", now)
	if !ok {
		t.Fatal("verified peer did not produce observed checkpoint patch")
	}
	if patch.ObservedEndpoint.Value != "198.51.100.20:33434" || patch.ObservedFirstUnix.Value != now.Unix() {
		t.Fatalf("observed patch = %#v", patch)
	}
	if len(patch.ObservedGrace.Value) != 1 || patch.ObservedGrace.Value[0].Endpoint != "198.51.100.10:33434" {
		t.Fatalf("observed grace = %#v", patch.ObservedGrace.Value)
	}
	expiredAt := now.Add(time.Minute)
	reobserved, ok := PlanVerifiedObservedCheckpoint(input, peerID.String(), "198.51.100.10:33434", expiredAt)
	if !ok || reobserved.ObservedFirstUnix.Value != expiredAt.Unix() {
		t.Fatalf("expired path did not start a new observation: %#v", reobserved)
	}
	if _, ok := PlanVerifiedObservedCheckpoint(input, "unknown.catofes.", "198.51.100.30:33434", now); ok {
		t.Fatal("unverified peer produced observed checkpoint patch")
	}
}

func TestApplyGossipDiscoveryPlanRestoresActiveObservedPaths(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	peerID := zone.ZonePath("peer.catofes.")
	entries := []gossip.EndpointEntry{{Address: "203.0.113.10", Port: 33434, Source: "reflector", LastObserved: now.Unix()}}
	network, _ := signedDiscoveryNetwork(t, peerID, true, entries, now)
	input := GossipDiscoveryInput{
		LocalPeerID: "local.catofes.", ManagedZone: "local.catofes.", Network: network,
		Peers: map[string]corestate.PeerCheckpoint{peerID.String(): {
			ObservedEndpoint: "198.51.100.20:33434", ObservedUntilUnix: now.Add(time.Minute).Unix(),
			ObservedGraceEndpoints: []corestate.ObservedGraceEndpoint{
				{Endpoint: "expired:33434", UntilUnix: now.Add(-time.Minute).Unix()},
				{Endpoint: "198.51.100.21:33434", UntilUnix: now.Add(time.Minute).Unix()},
			},
		}},
	}
	plan := PlanGossipDiscovery(input, now)
	if len(input.Peers[peerID.String()].ObservedGraceEndpoints) != 2 {
		t.Fatal("planning compacted checkpoint grace input")
	}
	transport := &gossip.Transport{}
	ApplyGossipDiscoveryPlan(transport, plan)
	if addr := transport.PeerAddr(peerID.String()); addr == nil || addr.String() != "203.0.113.10:33434" {
		t.Fatalf("repaired endpoint = %v", addr)
	}
	if paths := transport.ObservedPeerAddrs(peerID.String()); len(paths) != 2 ||
		paths[0].String() != "198.51.100.20:33434" || paths[1].String() != "198.51.100.21:33434" {
		t.Fatalf("repaired observed paths = %v", paths)
	}
}

func TestPlanGossipDiscoveryRepairsBootstrapWithoutVerifiedZone(t *testing.T) {
	now := time.Unix(1000, 0)
	peerID := "bootstrap.example."
	plan := PlanGossipDiscovery(GossipDiscoveryInput{
		Network:        zone.NewNetworkState(),
		Bootstrap:      map[string]*net.UDPAddr{peerID: {IP: net.ParseIP("127.0.0.1"), Port: 33434}},
		BootstrapPeers: []string{peerID},
	}, now)
	transport := &gossip.Transport{}
	ApplyGossipDiscoveryPlan(transport, plan)
	if addr := transport.PeerAddr(peerID); addr == nil || addr.String() != "127.0.0.1:33434" {
		t.Fatalf("bootstrap address = %v", addr)
	}
}

func signedDiscoveryNetwork(t testing.TB, peer zone.ZonePath, includePeer bool, endpoints []gossip.EndpointEntry, now time.Time) (*zone.NetworkState, ed25519.PrivateKey) {
	t.Helper()
	rootPublic, rootPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	parentPublic, parentPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	peerPublic, peerPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	rootAuthority := &zone.ZoneAuthority{Zone: zone.RootZone, Epoch: 1, Threshold: 1, Keys: []zone.AuthorizedKey{{
		Key: rootPublic, Capabilities: []zone.Capability{{Permissions: []zone.Permission{zone.PermDelegate, zone.PermWrite}}},
	}}}
	parent := peer.Parent()
	parentAuthority := &zone.ZoneAuthority{Zone: parent, Epoch: 1, Threshold: 1, Keys: []zone.AuthorizedKey{{
		Key: parentPublic, Capabilities: []zone.Capability{{Permissions: []zone.Permission{zone.PermDelegate, zone.PermWrite}}},
	}}}
	peerAuthority := &zone.ZoneAuthority{Zone: peer, Epoch: 1, Threshold: 1, Keys: []zone.AuthorizedKey{{
		Key: peerPublic, Capabilities: []zone.Capability{{Permissions: []zone.Permission{zone.PermWrite}}},
	}}}
	parentDelegation := &zone.Delegation{ZoneName: parent, Scope: zone.DelegationScopeDirectChild, Authority: *parentAuthority}
	if err := photoncrypto.SignDelegation(parentDelegation, zone.RootZone, rootPrivate); err != nil {
		t.Fatal(err)
	}
	delegation := &zone.Delegation{ZoneName: peer, Scope: zone.DelegationScopeDirectChild, Authority: *peerAuthority}
	if err := photoncrypto.SignDelegation(delegation, parent, parentPrivate); err != nil {
		t.Fatal(err)
	}
	network := zone.NewNetworkState()
	network.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, rootAuthority)
	network.Zones[zone.RootZone].Delegations[parent] = parentDelegation
	network.Zones[parent] = zone.NewZoneState(parent, parentAuthority)
	network.Zones[parent].ParentProof = []*zone.Delegation{parentDelegation}
	network.Zones[parent].Delegations[peer] = delegation
	if includePeer {
		network.Zones[peer] = zone.NewZoneState(peer, peerAuthority)
		network.Zones[peer].ParentProof = []*zone.Delegation{parentDelegation, delegation}
	}
	if includePeer && endpoints != nil {
		payload, err := json.Marshal(gossip.EndpointRecord{Endpoints: endpoints, TTL: int64(time.Hour / time.Second), UpdatedAt: now.Unix()})
		if err != nil {
			t.Fatal(err)
		}
		record := &zone.Record{Zone: peer, Key: gossip.EndpointRecordKeyUDP, Type: "sync.endpoint", Value: payload, Version: 1, Timestamp: now.Unix()}
		if err := photoncrypto.SignRecord(record, peerPrivate); err != nil {
			t.Fatal(err)
		}
		network.Zones[peer].Records[record.Key] = record
	}
	network.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
	return network, peerPrivate
}

func TestDiscoveryAddressOrder(t *testing.T) {
	bootstrap := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 33434}
	entries := []gossip.EndpointEntry{
		{Address: "203.0.113.10", Port: 33434, Source: "reflector"},
		{Address: "198.51.100.2", Port: 33434, Source: "advertise"},
	}
	addrs := GossipDiscoveryAddresses(entries, bootstrap, []string{"bootstrap", "advertise", "reflector"})
	want := []string{"127.0.0.1:33434", "198.51.100.2:33434", "203.0.113.10:33434"}
	if len(addrs) != len(want) {
		t.Fatalf("addresses = %v", addrs)
	}
	for i := range want {
		if addrs[i].String() != want[i] {
			t.Fatalf("address[%d] = %s, want %s", i, addrs[i], want[i])
		}
	}
}

func TestFilterGossipCatalogPageUsesCommonManagedAndRejectedState(t *testing.T) {
	now := time.Unix(1000, 0)
	input := GossipDiscoveryInput{
		ManagedZone: "local.catofes.",
		Network:     zone.NewNetworkState(),
		Peers: map[string]corestate.PeerCheckpoint{"peer-a": {RejectedObjects: map[zone.ZonePath]corestate.RejectedObject{
			"rejected.catofes.": {RootHash: []byte("rejected-root"), UntilUnix: now.Add(time.Minute).Unix()},
		}}},
	}
	page := &corestate.CatalogPage{Entries: []corestate.ZoneDigest{
		{Zone: "local.catofes.", RootHash: []byte("local-root")},
		{Zone: "rejected.catofes.", RootHash: []byte("rejected-root")},
		{Zone: "accepted.catofes.", RootHash: []byte("accepted-root")},
	}}
	_, filtered := FilterGossipCatalogPage(input, "peer-a", page, now)
	if len(filtered.Entries) != 1 || filtered.Entries[0].Zone != "accepted.catofes." {
		t.Fatalf("filtered entries = %#v", filtered.Entries)
	}
	if len(page.Entries) != 3 {
		t.Fatal("catalog filter mutated source page")
	}
}

func TestResolveGossipObjectPullAddressesUsesBootstrap(t *testing.T) {
	input := GossipDiscoveryInput{Bootstrap: map[string]*net.UDPAddr{
		"peer-a": {IP: net.ParseIP("192.0.2.10"), Port: 33434},
	}}
	if got := ResolveGossipObjectPullAddresses(input, "peer-a", time.Unix(1000, 0)); !slices.Equal(got, []string{"192.0.2.10:33434"}) {
		t.Fatalf("object-pull address = %q", got)
	}
	if got := ResolveGossipObjectPullAddresses(input, "unknown", time.Unix(1000, 0)); len(got) != 0 {
		t.Fatalf("unknown object-pull address = %q", got)
	}
}

func TestGossipPeerDiscoveryInputForObjectPull(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	peerID := zone.ZonePath("peer.catofes.")
	otherID := zone.ZonePath("other.catofes.")
	network, _ := signedDiscoveryNetwork(t, peerID, true, []gossip.EndpointEntry{{
		Address: "203.0.113.10", Port: 33434, Source: "advertise", LastObserved: now.Unix(),
	}}, now)
	network.Zones[otherID] = zone.NewZoneState(otherID, nil)
	network.Zones[peerID].Records["unrelated"] = &zone.Record{Zone: peerID, Key: "unrelated"}
	observed := corestate.PeerCheckpoint{
		ObservedEndpoint: "198.51.100.10:33434", ObservedUntilUnix: now.Add(time.Minute).Unix(),
	}
	store := corestate.NewStoreWithCheckpoint(&corestate.VerifiedState{Network: network}, &corestate.GossipCheckpoint{
		Peers: map[string]corestate.PeerCheckpoint{peerID.String(): observed, otherID.String(): observed},
	}, nil, nil)
	driver := NewGossipDriver(newFakeClock(now), 1, store, GossipDriverConfig{
		Discovery: GossipDiscoveryConfig{Bootstrap: map[string]*net.UDPAddr{
			peerID.String():  {IP: net.ParseIP("192.0.2.10"), Port: 33434},
			otherID.String(): {IP: net.ParseIP("192.0.2.20"), Port: 33434},
		}},
	})
	defer driver.Stop()

	input := driver.GossipPeerDiscoveryInput(peerID.String())
	if input.Network.Zones[otherID] != nil || len(input.Peers) != 1 || len(input.Bootstrap) != 1 {
		t.Fatal("object-pull input retained unrelated peer data")
	}
	if input.Network.Zones[peerID].Records["unrelated"] != nil {
		t.Fatal("object-pull input retained an unrelated record")
	}
	want := []string{"198.51.100.10:33434", "192.0.2.10:33434", "203.0.113.10:33434"}
	if got := ResolveGossipObjectPullAddresses(input, peerID.String(), now); !slices.Equal(got, want) {
		t.Fatalf("object-pull addresses = %q, want %q", got, want)
	}

	input.Peers["unknown.catofes."] = observed
	if got := ResolveGossipObjectPullAddresses(input, "unknown.catofes.", now); len(got) != 0 {
		t.Fatalf("unverified observed address = %q", got)
	}
}

func TestGossipOutboundPeersCombinesCommonSources(t *testing.T) {
	now := time.Unix(1000, 0)
	network := zone.NewNetworkState()
	path := zone.ZonePath("signed.catofes.")
	payload, err := json.Marshal(gossip.EndpointRecord{Endpoints: []gossip.EndpointEntry{{
		Address: "203.0.113.1", Port: 33434, LastObserved: now.Unix(),
	}}})
	if err != nil {
		t.Fatal(err)
	}
	peerZone := zone.NewZoneState(path, &zone.ZoneAuthority{Zone: path, Epoch: 1, Threshold: 1})
	peerZone.Records[gossip.EndpointRecordKeyUDP] = &zone.Record{Zone: path, Key: gossip.EndpointRecordKeyUDP, Value: payload, Timestamp: now.Unix()}
	network.Zones[path] = peerZone
	input := GossipDiscoveryInput{
		LocalPeerID:    "local.catofes.",
		ManagedZone:    "local.catofes.",
		Network:        network,
		Bootstrap:      map[string]*net.UDPAddr{"bootstrap.catofes.": {IP: net.ParseIP("192.0.2.1"), Port: 33434}},
		BootstrapPeers: []string{"bootstrap.catofes."},
		Peers: map[string]corestate.PeerCheckpoint{
			"observed.catofes.": {ObservedEndpoint: "198.51.100.1:33434", ObservedUntilUnix: now.Add(time.Minute).Unix()},
		},
	}
	// An observed path is admitted only when its authority chain is present in
	// verified state; the signed endpoint peer and bootstrap remain eligible.
	got := GossipOutboundPeers(input, now)
	if len(got) != 2 || got[0] != "bootstrap.catofes." || got[1] != "signed.catofes." {
		t.Fatalf("outbound peers = %v", got)
	}
}

func TestShouldRelayGossipUpdate(t *testing.T) {
	now := time.Unix(1000, 0)
	if allowed, reason := ShouldRelayGossipUpdate(corestate.PeerCheckpoint{}, "source", "source", "root", now); allowed || reason != "source_peer" {
		t.Fatalf("source decision = %v %q", allowed, reason)
	}
	checkpoint := corestate.PeerCheckpoint{BackoffUntilUnix: now.Add(time.Minute).Unix()}
	if allowed, reason := ShouldRelayGossipUpdate(checkpoint, "peer", "source", "root", now); allowed || reason != "backoff" {
		t.Fatalf("backoff decision = %v %q", allowed, reason)
	}
	checkpoint = corestate.PeerCheckpoint{LastRelayCatalogRootHex: "root"}
	if allowed, reason := ShouldRelayGossipUpdate(checkpoint, "peer", "source", "root", now); allowed || reason != "relay_root_unchanged" {
		t.Fatalf("root decision = %v %q", allowed, reason)
	}
	if allowed, reason := ShouldRelayGossipUpdate(corestate.PeerCheckpoint{}, "peer", "source", "root", now); !allowed || reason != "" {
		t.Fatalf("allowed decision = %v %q", allowed, reason)
	}
}

func TestObservedPathVerifierRechecksExpiryAndRevocation(t *testing.T) {
	const peer zone.ZonePath = "peer."
	now := time.Unix(1000, 0)
	expires := now.Add(time.Second)
	rootPublic, rootKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	network := zone.NewNetworkState()
	root := zone.NewZoneState(zone.RootZone, photoncrypto.ConfiguredRootAuthority(rootPublic))
	network.Zones[zone.RootZone] = root
	authority := &zone.ZoneAuthority{Zone: peer, Epoch: 1, Threshold: 1}
	network.Zones[peer] = zone.NewZoneState(peer, authority)
	delegation := &zone.Delegation{ZoneName: peer, Authority: *authority, ExpiresAt: &expires}
	if err := photoncrypto.SignDelegation(delegation, zone.RootZone, rootKey); err != nil {
		t.Fatal(err)
	}
	root.Delegations[peer] = delegation
	store := corestate.NewStore(&corestate.VerifiedState{Network: network}, nil, nil)
	driver := NewGossipDriver(nil, 1, store, GossipDriverConfig{})
	defer driver.Stop()
	check := func(at time.Time, endpoint string, want bool) {
		t.Helper()
		verified, committed, err := driver.recordGossipObservedPath(t.Context(), peer.String(), endpoint, false, at)
		if err != nil || verified.valid != want || committed != want {
			t.Fatalf("at %v: verified=%t committed=%t err=%v, want %t", at, verified.valid, committed, err, want)
		}
	}
	const original = "192.0.2.1:33434"
	const rejected = "192.0.2.2:33434"
	check(now, original, true)
	check(expires.Add(-time.Nanosecond), original, true)
	check(expires, rejected, false)
	if got := store.PeerCheckpoints([]string{peer.String()})[peer.String()].ObservedEndpoint; got != original {
		t.Fatalf("expired path replaced committed endpoint with %q", got)
	}

	revocation := &zone.DelegationRevocation{
		ParentZone: zone.RootZone, ChildZone: peer, RevokedAt: now.Unix(),
		RevokedAuthorityEpoch: delegation.AuthorityEpoch, RevokedAuthorityHash: delegation.AuthorityHash,
	}
	if err := photoncrypto.SignDelegationRevocation(revocation, zone.RootZone, rootKey); err != nil {
		t.Fatal(err)
	}
	root.Revocations[peer] = revocation
	snapshot, err := corestate.Snapshot(network, zone.RootZone)
	if err != nil {
		t.Fatal(err)
	}
	result, err := store.ApplyRemoteBatch(t.Context(), "relay", []corestate.RemoteSnapshot{{Snapshot: snapshot}}, now)
	if err != nil || !result.Committed {
		t.Fatalf("publish revocation: result=%+v err=%v", result, err)
	}
	check(now, rejected, false)
	if _, ok := store.PeerCheckpoints([]string{peer.String()})[peer.String()]; ok {
		t.Fatal("revoked peer checkpoint remains after the remote commit")
	}
}

func TestRememberedGossipEndpointIsAStartupCandidateOnlyForVerifiedPeer(t *testing.T) {
	now := time.Unix(1000, 0)
	const peerID = "peer.catofes."
	const unknownID = "unknown.catofes."
	network, _ := signedDiscoveryNetwork(t, peerID, true, nil, now)
	input := GossipDiscoveryInput{
		Network: network,
		Peers: map[string]corestate.PeerCheckpoint{
			peerID:    {LastSuccessfulEndpoint: "192.0.2.1:33434"},
			unknownID: {LastSuccessfulEndpoint: "192.0.2.2:33434"},
		},
	}
	if got := GossipOutboundPeers(input, now); !slices.Equal(got, []string{peerID}) {
		t.Fatalf("outbound peers = %v, want only the verified peer", got)
	}
	plan := PlanGossipDiscovery(input, now)
	datagram := &memoryGossipDatagram{}
	transport, err := gossip.NewTransport(gossip.Config{PeerID: "local.catofes."}, datagram)
	if err != nil {
		t.Fatal(err)
	}
	ApplyGossipDiscoveryPlan(transport, plan)
	if transport.HasRememberedPeerAddr(unknownID) {
		t.Fatal("unverified address installed")
	}
	if err := transport.Send(peerID, &gossip.Message{Type: gossip.MessagePing, Ping: &gossip.Ping{}}); err != nil {
		t.Fatal(err)
	}
	if _, addr := datagram.lastWrite(); addr.String() != input.Peers[peerID].LastSuccessfulEndpoint {
		t.Fatalf("probe sent to %v", addr)
	}
}
