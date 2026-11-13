package main

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/photonlinux"
	"github.com/HiggsNet/photon/pkg/core/gossip"
	corehost "github.com/HiggsNet/photon/pkg/core/host"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestDaemonAdmissionPublishesBeforeReconcile(t *testing.T) {
	for _, mode := range []string{"auto_join", "join_accept", "join_accept_without_identity"} {
		t.Run(mode, func(t *testing.T) {
			admitted, _, _, config := buildTestDaemonOwners(t)
			admitted.ManagedZone = "node-b.catofes."
			config.PeerID = string(admitted.ManagedZone)
			pending := *admitted
			pending.Network = zone.CloneNetworkState(admitted.Network)
			delete(pending.Network.Zones, pending.ManagedZone)
			delete(pending.Network.Zones[pending.ManagedZone.Parent()].Delegations, pending.ManagedZone)
			if mode == "join_accept_without_identity" {
				pending = corestate.VerifiedState{Network: zone.NewNetworkState()}
			}
			config.ListenAddr = "198.51.100.20:33434"
			config.AdvertiseAddrs = []string{config.ListenAddr}
			config.Reflectors = nil
			config.IPsec.AnnounceGossipEndpoints = true
			config.IPsec.LinkGroups = []ipsec.LinkGroupSpec{testIPsecLinkGroup()}
			service := newTestDaemonFromOwners(
				&testApp{Config: config, Clock: func() time.Time { return time.Unix(8000, 0) }},
				&pending, &corestate.GossipCheckpoint{}, &photonlinux.LinuxState{}, config, time.Second,
			)
			t.Cleanup(func() { _ = service.Close() })
			if _, err := service.prepareLocalState(t.Context()); err != nil {
				t.Fatal(err)
			}
			service.processEvents(t.Context(), nil)
			beforeAdmission := service.State.Common.VerifiedRevision()
			var reply chan daemonEventResult
			if mode == "auto_join" {
				// Exercise the actual Gossip completion and managed-zone adoption.
				snapshot, err := corestate.Snapshot(admitted.Network, admitted.ManagedZone.Parent())
				if err != nil {
					t.Fatal(err)
				}
				peer := "node-a.catofes."
				session := gossip.NewSyncSession(peer)
				_, _ = session.OnEvent(&gossip.SyncTimerEvent{PeerID: peer}, service.now())
				_, _ = session.OnEvent(&gossip.CatalogPageReceivedEvent{PeerID: peer, Page: &corestate.CatalogPage{
					CatalogRoot: []byte("catalog"),
					Entries:     []corestate.ZoneDigest{{Zone: snapshot.Zone, RootHash: corestate.ZoneRoot(admitted.Network.Zones[snapshot.Zone])}},
				}}, service.now())
				service.gossipDriver.Gossip.SetSession(peer, session)
				if _, err := service.handleGossipDriverEvent(t.Context(), corehost.GossipEvent{Value: &gossip.ObjectPullResultEvent{PeerID: peer, Zone: snapshot.Zone, Snapshot: snapshot}}); err != nil {
					t.Fatal(err)
				}
			} else {
				key := admitted.IdentityPrivateKey
				reply = make(chan daemonEventResult, 1)
				service.Events <- daemonEvent{
					Type: daemonEventJoinAccept,
					JoinBundle: &joinBundle{
						Version: 1, Zone: admitted.ManagedZone, Network: admitted.Network,
						RootPublicKey: admitted.Network.Zones[zone.RootZone].Authority.Keys[0].Key,
					},
					PrivateKey: &privateKeyFile{Type: "photon.ed25519.private.v1", PublicKey: key.Public().(ed25519.PublicKey), PrivateKey: key},
					Reply:      reply,
				}
			}
			flushed := false
			service.Hooks.OnReconcileFlush = func(string) {
				flushed = true
				assertAdmissionRecords(t, service, admitted.ManagedZone)
			}
			service.processEvents(t.Context(), nil)
			if reply != nil {
				if result := <-reply; result.Error != nil {
					t.Fatal(result.Error)
				}
			}
			assertAdmissionRecords(t, service, admitted.ManagedZone)
			if !flushed || service.State.Common.VerifiedRevision() <= beforeAdmission {
				t.Fatal("admission did not publish and reconcile in the next batch")
			}
			// A later idle batch must not rewrite the announcements.
			revision := service.State.Common.VerifiedRevision()
			service.processEvents(t.Context(), nil)
			if service.State.Common.VerifiedRevision() != revision {
				t.Fatal("idle batch rewrote admission announcements")
			}
		})
	}
}

func assertAdmissionRecords(t *testing.T, service *Daemon, managed zone.ZonePath) {
	t.Helper()
	view := service.State.Common.ReadView()
	if gossip.AutoJoinPending(view.State) || view.State.ManagedZone != managed {
		t.Fatal("identity was not admitted")
	}
	for _, key := range []string{gossip.EndpointRecordKeyUDP, ipsec.RecordKeyTransportKey, ipsec.RecordKeyProfile, ipsec.RecordKeyAddresses, ipsec.RecordKeyPorts} {
		if view.State.Network.Zones[managed].Records[key] == nil {
			t.Fatalf("admitted node has not published %s before platform reconcile", key)
		}
	}
}
