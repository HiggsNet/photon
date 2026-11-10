package host

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

type observedVerificationStore struct {
	GossipStateStore
	reads           int
	afterUpdateRead func(*corestate.DiscoveryView)
	updateErr       error
}

func (store *observedVerificationStore) UpdatePeerCheckpoints(ctx context.Context, patches map[string]corestate.PeerCheckpointPatch) (corestate.CommitResult, error) {
	if store.updateErr != nil {
		return corestate.CommitResult{}, store.updateErr
	}
	return store.GossipStateStore.UpdatePeerCheckpoints(ctx, patches)
}

func (store *observedVerificationStore) ReadPeerAuthorization(peerID string) *corestate.DiscoveryView {
	view := store.GossipStateStore.ReadPeerAuthorization(peerID)
	store.reads++
	if store.reads == 2 && store.afterUpdateRead != nil {
		store.afterUpdateRead(view)
	}
	return view
}

func TestInboundObservedPathUsesPublishedStateAndRechecksChangedRevision(t *testing.T) {
	for _, tc := range []struct {
		name                        string
		failUpdate, changeAuthority bool
	}{
		{"updated", false, false}, {"failed_update", true, false},
		{"changed_authority", false, true}, {"failed_update_and_changed_authority", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Unix(1000, 0)
			peer := zone.ZonePath("peer.catofes.")
			network, _ := signedDiscoveryNetwork(t, peer, true, nil, now)
			old := "198.51.100.1:33434"
			common := corestate.NewStoreWithCheckpoint(&corestate.VerifiedState{ManagedZone: "local.catofes.", Network: network},
				&corestate.GossipCheckpoint{Peers: map[string]corestate.PeerCheckpoint{peer.String(): {ObservedEndpoint: old, ObservedUntilUnix: now.Add(time.Minute).Unix()}}},
				nil, nil)
			store := &observedVerificationStore{GossipStateStore: common}
			if tc.failUpdate {
				store.updateErr = errors.New("observed path update failed")
			}
			if tc.changeAuthority {
				store.afterUpdateRead = func(view *corestate.DiscoveryView) {
					view.Revision++
					view.Network.Zones[peer.Parent()].Delegations[peer].Signature[0] ^= 0xff
				}
			}
			driver := NewGossipDriver(newFakeClock(now), 2, store, GossipDriverConfig{PeerID: "local.catofes."})
			defer driver.Stop()
			transport, err := gossip.NewTransport(gossip.Config{PeerID: "local.catofes.", Clock: func() time.Time { return now }}, &memoryGossipDatagram{})
			if err != nil {
				t.Fatal(err)
			}
			packet := &gossip.Packet{Addr: &net.UDPAddr{IP: net.ParseIP("198.51.100.2"), Port: 33434}, Message: &gossip.Message{PeerID: peer.String()}}
			driver.acceptGossipInboundPath(t.Context(), packet, now, nil, transport)
			addr := transport.ObservedPeerAddr(peer.String())
			if tc.changeAuthority {
				if addr != nil {
					t.Fatalf("published peer after authorization changed: %v", addr)
				}
			} else {
				want := packet.Addr.String()
				if tc.failUpdate {
					want = old
				}
				if addr == nil || addr.String() != want {
					t.Fatalf("observed %v, want published %s", addr, want)
				}
			}
		})
	}
}

func TestInboundObservedVerificationDoesNotSurviveNextPacket(t *testing.T) {
	now := time.Unix(1000, 0)
	peer := zone.ZonePath("peer.catofes.")
	network, _ := signedDiscoveryNetwork(t, peer, true, nil, now)
	network.Zones[zone.RootZone].Authority.Keys[0].NotAfter = now.Add(time.Second).Unix()
	store := corestate.NewStore(&corestate.VerifiedState{ManagedZone: "local.catofes.", Network: network}, nil, nil)
	driver := NewGossipDriver(newFakeClock(now), 2, store, GossipDriverConfig{PeerID: "local.catofes."})
	defer driver.Stop()
	transport, err := gossip.NewTransport(gossip.Config{PeerID: "local.catofes.", Clock: func() time.Time { return now }}, &memoryGossipDatagram{})
	if err != nil {
		t.Fatal(err)
	}
	packet := &gossip.Packet{Addr: &net.UDPAddr{IP: net.ParseIP("198.51.100.2"), Port: 33434}, Message: &gossip.Message{PeerID: peer.String()}}
	driver.acceptGossipInboundPath(t.Context(), packet, now, nil, transport)
	if transport.ObservedPeerAddr(peer.String()) == nil {
		t.Fatal("valid peer not published")
	}
	driver.acceptGossipInboundPath(t.Context(), packet, now.Add(2*time.Second), nil, transport)
	if transport.ObservedPeerAddr(peer.String()) != nil {
		t.Fatal("expired authority reused across packets")
	}
}
