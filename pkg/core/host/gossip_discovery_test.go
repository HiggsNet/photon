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
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

type failingDiscoveryWriter struct {
	err  error
	view corestate.View
}

func (writer failingDiscoveryWriter) ReadView() corestate.View { return writer.view }

func (writer failingDiscoveryWriter) ApplyRemoteBatch(context.Context, string, []corestate.RemoteSnapshot, time.Time) (corestate.RemoteBatchResult, error) {
	return corestate.RemoteBatchResult{}, nil
}

func (writer failingDiscoveryWriter) UpdatePeerCheckpoints(context.Context, map[string]corestate.PeerCheckpointPatch) (corestate.CommitResult, error) {
	return corestate.CommitResult{}, writer.err
}

func TestGossipDriverDiscoveryDoesNotPublishAddressBookBeforeCheckpoint(t *testing.T) {
	wantErr := errors.New("checkpoint failed")
	now := time.Unix(1000, 0)
	transport := &gossip.Transport{}
	input := GossipDiscoveryInput{
		Network:   zone.NewNetworkState(),
		Bootstrap: map[string]*net.UDPAddr{"peer-a": {IP: net.ParseIP("192.0.2.1"), Port: 33434}},
		Peers: map[string]corestate.PeerCheckpoint{"peer-a": {
			ObservedEndpoint:  "198.51.100.1:33434",
			ObservedUntilUnix: now.Add(-time.Minute).Unix(),
		}},
	}
	driver := NewGossipDriver(nil, 1, failingDiscoveryWriter{err: wantErr, view: corestate.View{
		State:  &corestate.VerifiedState{Network: input.Network},
		Gossip: &corestate.GossipCheckpoint{Peers: input.Peers},
	}}, GossipDriverConfig{Discovery: GossipDiscoveryConfig{Bootstrap: input.Bootstrap}})
	defer driver.Stop()
	if err := driver.RefreshGossipDiscovery(context.Background(), nil, now, transport); !errors.Is(err, wantErr) {
		t.Fatalf("RefreshGossipDiscovery error = %v", err)
	}
	if addr := transport.PeerAddr("peer-a"); addr != nil {
		t.Fatalf("address book published before checkpoint: %v", addr)
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

func TestPlanGossipDiscoveryRanksEndpointAndPublishesCheckpoint(t *testing.T) {
	now := time.Unix(1000, 0)
	entries := []gossip.EndpointEntry{
		{Address: "10.16.255.8", Port: 33435, Source: "interface", Priority: 200, LastObserved: now.Unix()},
		{Address: "203.0.113.10", Port: 33434, Source: "reflector", Priority: 10, LastObserved: now.Unix()},
	}
	network, _ := signedDiscoveryNetwork(t, "peer.catofes.", true, entries, now)
	plan := PlanGossipDiscovery(GossipDiscoveryInput{
		LocalPeerID: "local.catofes.", ManagedZone: "local.catofes.", Network: network,
	}, now)
	update := plan.Peers["peer.catofes."]
	if len(update.SetAddresses) != 2 || update.SetAddresses[0].String() != "203.0.113.10:33434" {
		t.Fatalf("addresses = %v, want public reflector first", update.SetAddresses)
	}
	patch := plan.Patches["peer.catofes."]
	if !patch.DiscoveredEndpoint.Set || patch.DiscoveredEndpoint.Value != "203.0.113.10:33434" || !patch.DiscoveredAtUnix.Set {
		t.Fatalf("checkpoint patch = %#v", patch)
	}

	transport := &gossip.Transport{}
	ApplyGossipDiscoveryPlan(transport, plan)
	if addr := transport.PeerAddr("peer.catofes."); addr == nil || addr.String() != "203.0.113.10:33434" {
		t.Fatalf("published address = %v", addr)
	}
}

func TestPlanGossipDiscoveryReplacesAndExpiresEndpoint(t *testing.T) {
	now := time.Unix(1000, 0)
	network, _ := signedDiscoveryNetwork(t, "peer.catofes.", true, []gossip.EndpointEntry{{
		Address: "127.0.0.1", Port: 10000, Source: "advertise", LastObserved: now.Unix(),
	}}, now)
	plan := PlanGossipDiscovery(GossipDiscoveryInput{
		LocalPeerID: "local.catofes.", ManagedZone: "local.catofes.", Network: network,
		Peers: map[string]corestate.PeerCheckpoint{"peer.catofes.": {
			DiscoveredEndpoint: "127.0.0.1:9999", DiscoveredAtUnix: now.Add(-time.Minute).Unix(),
		}},
	}, now)
	if got := plan.Patches["peer.catofes."].DiscoveredEndpoint; !got.Set || got.Value != "127.0.0.1:10000" {
		t.Fatalf("replacement patch = %#v", got)
	}

	emptyNetwork, _ := signedDiscoveryNetwork(t, "peer.catofes.", true, nil, now)
	plan = PlanGossipDiscovery(GossipDiscoveryInput{
		LocalPeerID: "local.catofes.", ManagedZone: "local.catofes.", Network: emptyNetwork,
		EndpointGrace: time.Nanosecond,
		Peers: map[string]corestate.PeerCheckpoint{"peer.catofes.": {
			DiscoveredEndpoint: "127.0.0.1:10000", DiscoveredAtUnix: now.Add(-time.Hour).Unix(), LastSyncUnix: now.Add(-time.Hour).Unix(),
		}},
	}, now)
	update := plan.Peers["peer.catofes."]
	patch := plan.Patches["peer.catofes."]
	if !update.RemoveAddresses || !patch.DiscoveredEndpoint.Set || patch.DiscoveredEndpoint.Value != "" {
		t.Fatalf("expired update/patch = %#v/%#v", update, patch)
	}
}

func TestPlanGossipDiscoveryDoesNotCompactCheckpointGraceInput(t *testing.T) {
	now := time.Unix(1000, 0)
	network, _ := signedDiscoveryNetwork(t, "peer.catofes.", true, nil, now)
	input := GossipDiscoveryInput{
		LocalPeerID: "local.catofes.", ManagedZone: "local.catofes.", Network: network,
		Peers: map[string]corestate.PeerCheckpoint{"peer.catofes.": {
			ObservedEndpoint:  "127.0.0.1:3000",
			ObservedUntilUnix: now.Add(time.Minute).Unix(),
			ObservedGraceEndpoints: []corestate.ObservedGraceEndpoint{
				{Endpoint: "127.0.0.1:1000", UntilUnix: now.Add(-time.Second).Unix()},
				{Endpoint: "127.0.0.1:2000", UntilUnix: now.Add(time.Minute).Unix()},
			},
		}},
	}
	plan := PlanGossipDiscovery(input, now)
	grace := input.Peers["peer.catofes."].ObservedGraceEndpoints
	if len(grace) != 2 || grace[0].Endpoint != "127.0.0.1:1000" || grace[1].Endpoint != "127.0.0.1:2000" {
		t.Fatalf("checkpoint grace paths were compacted in place: %#v", grace)
	}
	paths := plan.Peers["peer.catofes."].ObservedPaths
	if len(paths) != 2 || paths[0].Addr.String() != "127.0.0.1:3000" || paths[1].Addr.String() != "127.0.0.1:2000" {
		t.Fatalf("planned observed paths = %#v", paths)
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
			DiscoveredEndpoint: "127.0.0.1:9999", ObservedEndpoint: "127.0.0.1:2000", ObservedUntilUnix: now.Add(time.Minute).Unix(),
		}},
	}
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
	peer.DiscoveredEndpoint = "10.16.255.8:33435"
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
			ObservedUntilUnix: now.Add(time.Minute).Unix(), ObservedFailureCount: 2,
		}},
	}
	patch, ok := PlanVerifiedObservedCheckpoint(input, peerID.String(), "198.51.100.20:33434", now)
	if !ok {
		t.Fatal("verified peer did not produce observed checkpoint patch")
	}
	if patch.ObservedEndpoint.Value != "198.51.100.20:33434" || patch.ObservedFirstUnix.Value != now.Unix() || patch.ObservedFailures.Value != 0 {
		t.Fatalf("observed patch = %#v", patch)
	}
	if len(patch.ObservedGrace.Value) != 1 || patch.ObservedGrace.Value[0].Endpoint != "198.51.100.10:33434" {
		t.Fatalf("observed grace = %#v", patch.ObservedGrace.Value)
	}
	if _, ok := PlanVerifiedObservedCheckpoint(input, "unknown.catofes.", "198.51.100.30:33434", now); ok {
		t.Fatal("unverified peer produced observed checkpoint patch")
	}
}

func TestApplyGossipDiscoveryPlanRepairsTransportWithoutCheckpointPatch(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	peerID := zone.ZonePath("peer.catofes.")
	entries := []gossip.EndpointEntry{{Address: "203.0.113.10", Port: 33434, Source: "reflector", LastObserved: now.Unix()}}
	network, _ := signedDiscoveryNetwork(t, peerID, true, entries, now)
	input := GossipDiscoveryInput{
		LocalPeerID: "local.catofes.", ManagedZone: "local.catofes.", Network: network,
		Peers: map[string]corestate.PeerCheckpoint{peerID.String(): {
			DiscoveredEndpoint: "203.0.113.10:33434", DiscoveredAtUnix: now.Unix(),
			ObservedEndpoint: "198.51.100.20:33434", ObservedUntilUnix: now.Add(time.Minute).Unix(),
			ObservedGraceEndpoints: []corestate.ObservedGraceEndpoint{
				{Endpoint: "expired:33434", UntilUnix: now.Add(-time.Minute).Unix()},
				{Endpoint: "198.51.100.21:33434", UntilUnix: now.Add(time.Minute).Unix()},
			},
		}},
	}
	plan := PlanGossipDiscovery(input, now)
	if len(plan.Patches) != 0 {
		t.Fatalf("unchanged discovery produced checkpoint patches: %#v", plan.Patches)
	}
	if len(input.Peers[peerID.String()].ObservedGraceEndpoints) != 2 {
		t.Fatal("planning compacted checkpoint grace input")
	}
	transport := &gossip.Transport{}
	ApplyGossipDiscoveryPlan(transport, plan)
	if addr := transport.PeerAddr(peerID.String()); addr == nil || addr.String() != "203.0.113.10:33434" {
		t.Fatalf("repaired endpoint = %v", addr)
	}
	if paths := transport.ObservedPeerAddrs(peerID.String()); len(paths) != 2 {
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
	if len(plan.Patches) != 0 {
		t.Fatalf("bootstrap produced checkpoint patches: %#v", plan.Patches)
	}
	transport := &gossip.Transport{}
	ApplyGossipDiscoveryPlan(transport, plan)
	if addr := transport.PeerAddr(peerID); addr == nil || addr.String() != "127.0.0.1:33434" {
		t.Fatalf("bootstrap address = %v", addr)
	}
}

func signedDiscoveryNetwork(t *testing.T, peer zone.ZonePath, includePeer bool, endpoints []gossip.EndpointEntry, now time.Time) (*zone.NetworkState, ed25519.PrivateKey) {
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

func TestDiscoveryAddressOrderAndRecentFallback(t *testing.T) {
	now := time.Unix(1000, 0)
	bootstrap := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 33434}
	entries := []gossip.EndpointEntry{
		{Address: "203.0.113.10", Port: 33434, Source: "reflector"},
		{Address: "198.51.100.2", Port: 33434, Source: "advertise"},
	}
	peer := corestate.PeerCheckpoint{LastSyncUnix: now.Add(-time.Minute).Unix(), DiscoveredEndpoint: "192.0.2.9:33434"}
	addrs := buildDiscoveryAddresses(entries, bootstrap, peer, 10*time.Minute, []string{"bootstrap", "advertise", "reflector", "recent"}, now)
	want := []string{"127.0.0.1:33434", "198.51.100.2:33434", "203.0.113.10:33434", "192.0.2.9:33434"}
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

func TestResolveGossipObjectPullAddressUsesBootstrap(t *testing.T) {
	input := GossipDiscoveryInput{Bootstrap: map[string]*net.UDPAddr{
		"peer-a": {IP: net.ParseIP("192.0.2.10"), Port: 33434},
	}}
	if got := ResolveGossipObjectPullAddress(input, "peer-a", time.Unix(1000, 0)); got != "192.0.2.10:33434" {
		t.Fatalf("object-pull address = %q", got)
	}
	if got := ResolveGossipObjectPullAddress(input, "unknown", time.Unix(1000, 0)); got != "" {
		t.Fatalf("unknown object-pull address = %q", got)
	}
}

func TestResolveGossipObjectPullAddressPrefersVerifiedObservedPath(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	peerID := zone.ZonePath("peer.catofes.")
	network, _ := signedDiscoveryNetwork(t, peerID, true, nil, now)
	input := GossipDiscoveryInput{
		Network:   network,
		Bootstrap: map[string]*net.UDPAddr{peerID.String(): {IP: net.ParseIP("192.0.2.10"), Port: 33434}},
		Peers: map[string]corestate.PeerCheckpoint{peerID.String(): {
			ObservedEndpoint: "198.51.100.10:33434", ObservedUntilUnix: now.Add(time.Minute).Unix(),
		}},
	}
	if got := ResolveGossipObjectPullAddress(input, peerID.String(), now); got != "198.51.100.10:33434" {
		t.Fatalf("object-pull address = %q", got)
	}
	input.Peers["unknown.catofes."] = input.Peers[peerID.String()]
	if got := ResolveGossipObjectPullAddress(input, "unknown.catofes.", now); got != "" {
		t.Fatalf("unverified observed address = %q", got)
	}
}

func TestResolveGossipObjectPullAddressUsesSignedEndpoint(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	peerID := zone.ZonePath("peer.catofes.")
	network, _ := signedDiscoveryNetwork(t, peerID, true, []gossip.EndpointEntry{{
		Address: "203.0.113.10", Port: 33434, Source: "advertise", LastObserved: now.Unix(),
	}}, now)
	if got := ResolveGossipObjectPullAddress(GossipDiscoveryInput{Network: network}, peerID.String(), now); got != "203.0.113.10:33434" {
		t.Fatalf("object-pull address = %q", got)
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
