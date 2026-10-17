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
	afterCommitRead func(*corestate.DiscoveryView)
}

func (store *observedVerificationStore) ReadPeerAuthorization(peerID string) *corestate.DiscoveryView {
	view := store.GossipStateStore.ReadPeerAuthorization(peerID)
	store.reads++
	if store.reads == 2 && store.afterCommitRead != nil {
		store.afterCommitRead(view)
	}
	return view
}

func TestInboundObservedPathUsesCommittedCheckpointAndRechecksChangedRevision(t *testing.T) {
	for _, tc := range []struct {
		name                        string
		failCommit, changeAuthority bool
	}{
		{"committed", false, false}, {"failed_commit", true, false},
		{"changed_authority", false, true}, {"failed_commit_and_changed_authority", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Unix(1000, 0)
			peer := zone.ZonePath("peer.catofes.")
			network, _ := signedDiscoveryNetwork(t, peer, true, nil, now)
			old := "198.51.100.1:33434"
			common := corestate.NewStoreWithCheckpoint(&corestate.VerifiedState{ManagedZone: "local.catofes.", Network: network},
				&corestate.GossipCheckpoint{Peers: map[string]corestate.PeerCheckpoint{peer.String(): {ObservedEndpoint: old, ObservedUntilUnix: now.Add(time.Minute).Unix()}}},
				nil, func(context.Context, map[string]*corestate.PeerCheckpoint, corestate.VerifiedRevision) error {
					if tc.failCommit {
						return errors.New("disk failed")
					}
					return nil
				})
			store := &observedVerificationStore{GossipStateStore: common}
			if tc.changeAuthority {
				store.afterCommitRead = func(view *corestate.DiscoveryView) {
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
				if tc.failCommit {
					want = old
				}
				if addr == nil || addr.String() != want {
					t.Fatalf("observed %v, want committed %s", addr, want)
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
