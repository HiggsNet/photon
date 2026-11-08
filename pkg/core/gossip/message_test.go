package gossip

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

func TestMarshalUnmarshalPing(t *testing.T) {
	message := &Message{
		Type:      MessagePing,
		PeerID:    "node-a",
		Nonce:     1,
		Timestamp: 123,
		Ping: &Ping{Summary: &corestate.CatalogSummary{
			CatalogRoot: []byte{1, 2, 3},
			ZoneCount:   1,
		}},
	}

	data, err := MarshalMessage(message)
	if err != nil {
		t.Fatalf("MarshalMessage: %v", err)
	}
	got, err := UnmarshalMessage(data)
	if err != nil {
		t.Fatalf("UnmarshalMessage: %v", err)
	}
	if got.Type != MessagePing || got.PeerID != "node-a" || got.Ping.Summary == nil {
		t.Fatalf("decoded message = %#v", got)
	}
	if got.Ping.Summary.ZoneCount != 1 || !bytes.Equal(got.Ping.Summary.CatalogRoot, []byte{1, 2, 3}) {
		t.Fatalf("decoded summary = %#v", got.Ping.Summary)
	}
}

func TestRejectsUnsupportedWireVersion(t *testing.T) {
	_, err := MarshalMessage(&Message{
		Version:   WireVersion + 1,
		Type:      MessagePing,
		PeerID:    "node-a",
		Nonce:     1,
		Timestamp: 123,
		Ping:      &Ping{},
	})
	if err == nil {
		t.Fatalf("MarshalMessage accepted unsupported wire version")
	}
}

func TestReplayWindow(t *testing.T) {
	now := time.Unix(1000, 0)
	rw := NewReplayWindow(5 * time.Minute)

	if err := rw.Check("node-a", 1, now.Unix(), now); err != nil {
		t.Fatalf("Check(first): %v", err)
	}
	if err := rw.Check("node-a", 1, now.Unix(), now); !errors.Is(err, ErrReplay) {
		t.Fatalf("Check(replay) = %v, want ErrReplay", err)
	}
	if err := rw.Check("node-a", 2, now.Add(-6*time.Minute).Unix(), now); !errors.Is(err, ErrMessageExpired) {
		t.Fatalf("Check(expired) = %v, want ErrMessageExpired", err)
	}
}

func TestReplayWindowPrunesInactivePeers(t *testing.T) {
	now := time.Unix(1000, 0)
	rw := NewReplayWindow(5 * time.Minute)

	if err := rw.Check("node-a", 1, now.Unix(), now); err != nil {
		t.Fatalf("Check(node-a): %v", err)
	}
	if _, ok := rw.seen["node-a"]; !ok {
		t.Fatalf("node-a replay state was not recorded")
	}

	later := now.Add(6 * time.Minute)
	if err := rw.Check("node-b", 1, later.Unix(), later); err != nil {
		t.Fatalf("Check(node-b): %v", err)
	}
	if _, ok := rw.seen["node-a"]; ok {
		t.Fatalf("inactive peer replay state was not pruned: %#v", rw.seen)
	}
}

func TestPeerQuotas(t *testing.T) {
	now := time.Unix(1000, 0)
	quotas := NewPeerQuotas(QuotaConfig{
		ByteRate:    10,
		ByteBurst:   10,
		ObjectRate:  1,
		ObjectBurst: 1,
	})

	if err := quotas.Allow("node-a", 9, 1, now); err != nil {
		t.Fatalf("Allow(first): %v", err)
	}
	if err := quotas.Allow("node-a", 2, 1, now); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("Allow(over quota) = %v, want ErrQuotaExceeded", err)
	} else {
		var quotaErr *QuotaExceededError
		if !errors.As(err, &quotaErr) {
			t.Fatalf("Allow(over quota) did not return QuotaExceededError: %T", err)
		}
		if quotaErr.RequestedBytes != 2 || quotaErr.AvailableBytes != 1 || quotaErr.RequestedObjects != 1 || quotaErr.AvailableObjects != 0 {
			t.Fatalf("quota diagnostics = %#v, want requested 2/1 available 1/0", quotaErr)
		}
	}
	if err := quotas.Allow("node-a", 10, 1, now.Add(time.Second)); err != nil {
		t.Fatalf("Allow(refilled): %v", err)
	}
}

func TestPeerQuotasPrunesInactivePeers(t *testing.T) {
	now := time.Unix(1000, 0)
	quotas := NewPeerQuotas(QuotaConfig{
		ByteRate:    10,
		ByteBurst:   10,
		ObjectRate:  1,
		ObjectBurst: 1,
		PeerTTL:     time.Minute,
	})

	if err := quotas.Allow("node-a", 1, 1, now); err != nil {
		t.Fatalf("Allow(node-a): %v", err)
	}
	if _, ok := quotas.peers["node-a"]; !ok {
		t.Fatalf("node-a quota state was not recorded")
	}

	later := now.Add(2 * time.Minute)
	if err := quotas.Allow("node-b", 1, 1, later); err != nil {
		t.Fatalf("Allow(node-b): %v", err)
	}
	if _, ok := quotas.peers["node-a"]; ok {
		t.Fatalf("inactive peer quota state was not pruned: %#v", quotas.peers)
	}
}

func TestRevokedZoneEndpointsAreNotDiscovered(t *testing.T) {
	now := time.Unix(1000, 0)
	ns, rootPriv, zonePriv := testNetworkWithKeys(t)
	ns.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
	value := []byte(`{"endpoints":[{"address":"192.0.2.10","port":33434,"protocol":"udp"}],"updated_at":1000}`)
	record := signedRecord(t, zonePriv, "catofes.", EndpointRecordKeyUDP, value, 1, nil, now.Unix())
	if err := ns.PutAt(record, now); err != nil {
		t.Fatalf("PutAt(endpoint): %v", err)
	}
	if got := ExtractPeerEndpointsAt(ns, now); len(got["catofes."]) != 1 {
		t.Fatalf("endpoints before revoke = %#v, want one", got)
	}
	delegation := ns.Zones[zone.RootZone].Delegations["catofes."]
	revocation := &zone.DelegationRevocation{
		ChildZone:             "catofes.",
		ParentZone:            zone.RootZone,
		RevokedAuthorityEpoch: delegation.AuthorityEpoch,
		RevokedAuthorityHash:  delegation.AuthorityHash,
		Reason:                "retired",
		RevokedAt:             now.Unix(),
	}
	if err := photoncrypto.SignDelegationRevocation(revocation, zone.RootZone, rootPriv); err != nil {
		t.Fatalf("SignDelegationRevocation: %v", err)
	}
	ns.Zones[zone.RootZone].Revocations["catofes."] = revocation
	if got := ExtractPeerEndpointsAt(ns, now); len(got["catofes."]) != 0 {
		t.Fatalf("endpoints after revoke = %#v, want none", got)
	}
}

func testNetworkWithKeys(t *testing.T) (*zone.NetworkState, ed25519.PrivateKey, ed25519.PrivateKey) {
	t.Helper()
	rootPub, rootPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(root): %v", err)
	}
	zonePub, zonePriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(zone): %v", err)
	}
	ns := zone.NewNetworkState()
	ns.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, &zone.ZoneAuthority{
		Zone:      zone.RootZone,
		Epoch:     1,
		Threshold: photoncrypto.SupportedThreshold,
		Keys: []zone.AuthorizedKey{{
			Key: rootPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermDelegate, zone.PermWrite},
			}},
		}},
	})
	authority := &zone.ZoneAuthority{
		Zone:      "catofes.",
		Epoch:     1,
		Threshold: photoncrypto.SupportedThreshold,
		Keys: []zone.AuthorizedKey{{
			Key: zonePub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermWrite, zone.PermDelegate},
			}},
		}},
	}
	ns.Zones["catofes."] = zone.NewZoneState("catofes.", authority)
	delegation := &zone.Delegation{
		ZoneName:  "catofes.",
		Scope:     zone.DelegationScopeDirectChild,
		Authority: *authority,
	}
	if err := photoncrypto.SignDelegation(delegation, zone.RootZone, rootPriv); err != nil {
		t.Fatalf("SignDelegation: %v", err)
	}
	ns.Zones[zone.RootZone].Delegations["catofes."] = delegation
	return ns, rootPriv, zonePriv
}

func signedRecord(t *testing.T, priv ed25519.PrivateKey, path zone.ZonePath, key string, value []byte, version uint64, prev []byte, ts int64) *zone.Record {
	t.Helper()
	record := &zone.Record{
		Zone:      path,
		Key:       key,
		Type:      "node.identity",
		Value:     value,
		Version:   version,
		PrevHash:  prev,
		Timestamp: ts,
	}
	if err := photoncrypto.SignRecord(record, priv); err != nil {
		t.Fatalf("SignRecord: %v", err)
	}
	return record
}

func TestTransportSendReceiveKnownPeer(t *testing.T) {
	now := time.Unix(1000, 0)
	a, err := listenTestTransport("127.0.0.1:0", Config{
		PeerID: "node-a",
		Clock:  func() time.Time { return now },
	})
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("Listen(a): %v", err)
	}
	defer a.Close()

	b, err := listenTestTransport("127.0.0.1:0", Config{
		PeerID: "node-b",
		KnownPeers: map[string]*net.UDPAddr{
			"node-a": a.LocalAddr(),
		},
		Clock: func() time.Time { return now },
	})
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("Listen(b): %v", err)
	}
	defer b.Close()

	a.AddPeer("node-b", b.LocalAddr())
	if err := a.Send("node-b", &Message{
		Type: MessagePing,
		Ping: &Ping{},
	}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	packet, err := b.Receive()
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if packet.Message.Type != MessagePing || packet.Message.PeerID != "node-a" {
		t.Fatalf("received message = %#v", packet.Message)
	}
}

func TestTransportRejectsUnknownPeer(t *testing.T) {
	now := time.Unix(1000, 0)
	a, err := listenTestTransport("127.0.0.1:0", Config{
		PeerID: "node-a",
		Clock:  func() time.Time { return now },
	})
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("Listen(a): %v", err)
	}
	defer a.Close()

	b, err := listenTestTransport("127.0.0.1:0", Config{
		PeerID: "node-b",
		Clock:  func() time.Time { return now },
	})
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("Listen(b): %v", err)
	}
	defer b.Close()

	a.AddPeer("node-b", b.LocalAddr())
	if err := a.Send("node-b", &Message{
		Type: MessagePing,
		Ping: &Ping{},
	}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if _, err := b.Receive(); !errors.Is(err, ErrUnknownPeer) {
		t.Fatalf("Receive = %v, want ErrUnknownPeer", err)
	}
}

func skipRestrictedSocket(t *testing.T, err error) {
	t.Helper()
	if errors.Is(err, os.ErrPermission) {
		t.Skipf("UDP sockets are not permitted in this environment: %v", err)
	}
}
