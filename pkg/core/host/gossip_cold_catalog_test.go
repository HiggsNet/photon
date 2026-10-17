package host

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

type coldCatalogClient struct {
	source *zone.NetworkState
	pulls  chan zone.ZonePath
}

func (client coldCatalogClient) Exchange(_ context.Context, _ string, request *gossip.ObjectPullRequest) (*gossip.ObjectPullResponse, error) {
	client.pulls <- request.Zone
	snapshot, err := corestate.Snapshot(client.source, request.Zone)
	return &gossip.ObjectPullResponse{OK: err == nil, Snapshot: snapshot}, err
}

// The remote catalog puts children on the first page and their authorities on
// the last. Real workers, signatures, store commits and apply acknowledgements
// must converge in one session, without a restart or an ANNOUNCE payload.
func TestGossipColdCatalogAppliesAncestorsBeforeChildrenAcrossPages(t *testing.T) {
	for _, expire := range []bool{false, true} {
		t.Run(fmt.Sprintf("expire-after-parent=%t", expire), func(t *testing.T) {
			testGossipColdCatalog(t, expire)
		})
	}
}

func testGossipColdCatalog(t *testing.T, expireAfterParent bool) {
	now := time.Unix(1000, 0)
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	const managed zone.ZonePath = "node.catofes."
	candidate, err := corestate.NewPendingIdentity(managed, public, private)
	if err != nil {
		t.Fatal(err)
	}
	store := corestate.NewStore(candidate.Verified, nil, nil)
	defer store.Close()
	source := zone.NewNetworkState()
	source.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, photoncrypto.ConfiguredRootAuthority(public))
	paths := []zone.ZonePath{"catofes.", managed}
	for i := range 24 {
		paths = append(paths, zone.ZonePath(fmt.Sprintf("child-%02d.catofes.", i)))
	}
	for _, path := range paths {
		authority := zone.ZoneAuthority{Zone: path, Epoch: 1, Threshold: 1, Keys: []zone.AuthorizedKey{{Key: public, Capabilities: []zone.Capability{{Permissions: []zone.Permission{zone.PermWrite, zone.PermDelegate}}}}}}
		delegation := &zone.Delegation{ZoneName: path, Authority: authority}
		if err := photoncrypto.SignDelegation(delegation, path.Parent(), private); err != nil {
			t.Fatal(err)
		}
		source.Zones[path.Parent()].Delegations[path] = delegation
		source.Zones[path] = zone.NewZoneState(path, &authority)
	}
	clock := newFakeClock(now)
	driver := NewGossipDriver(clock, 128, store, GossipDriverConfig{PeerID: managed.String(), Limits: corestate.DefaultSyncLimits()})
	defer driver.Stop()
	bindMemoryGossipTransport(t, driver, "bootstrap")
	pulls := make(chan zone.ZonePath, 64)
	executor := NewGossipObjectPullExecutor(GossipObjectPullExecutorConfig{
		Client: coldCatalogClient{source: source, pulls: pulls}, Now: clock.Now,
		Discovery: func() GossipDiscoveryInput {
			return GossipDiscoveryInput{Network: store.ReadView().State.Network, Bootstrap: map[string]*net.UDPAddr{"bootstrap": {IP: net.ParseIP("127.0.0.1"), Port: 1}}}
		},
		// This test concerns scheduling rather than the separate traffic quota.
		Quota: gossip.QuotaConfig{ByteRate: 8 << 20, ByteBurst: 8 << 20, ObjectRate: 1000, ObjectBurst: 1000},
	})
	if err := driver.StartGossipObjectPullWorkers(t.Context(), executor, 4, 64); err != nil {
		t.Fatal(err)
	}
	driver.Gossip.NewSession("bootstrap")
	handle := func(event gossip.SyncEvent) GossipHostEventResult {
		t.Helper()
		result, err := driver.HandleGossipHostEvent(t.Context(), GossipEvent{Value: event}, now, nil)
		if err != nil || result.Session.TerminalErr != nil {
			t.Fatalf("cold catalog event %T: result=%+v error=%v", event, result.Session, err)
		}
		return result
	}
	handle(&gossip.SyncTimerEvent{PeerID: "bootstrap"})
	digests := corestate.ZoneDigests(source)
	root := corestate.CatalogRoot(digests)
	var children, parents []corestate.ZoneDigest
	for _, digest := range digests {
		if digest.Zone == zone.RootZone || digest.Zone == "catofes." {
			parents = append(parents, digest)
		} else {
			children = append(children, digest)
		}
	}
	pages := func() {
		handle(&gossip.CatalogPageReceivedEvent{PeerID: "bootstrap", Page: &corestate.CatalogPage{CatalogRoot: root, Entries: children, NextCursor: "parents"}})
		handle(&gossip.CatalogPageReceivedEvent{PeerID: "bootstrap", Page: &corestate.CatalogPage{CatalogRoot: root, Entries: parents}})
	}
	pages()
	expired := false
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	for driver.Gossip.Session("bootstrap") != nil {
		var event Event
		select {
		case event = <-driver.Events():
		case event = <-driver.Completions():
		case event = <-driver.Continuations():
		case <-deadline.C:
			t.Fatal("cold catalog did not finish")
		}
		result, err := driver.HandleGossipHostEvent(t.Context(), event, now, nil)
		if err != nil || result.Session.TerminalErr != nil {
			t.Fatalf("cold catalog event %T: result=%+v error=%v", event, result.Session, err)
		}
		if expireAfterParent && !expired && store.ReadView().State.Network.Zones["catofes."] != nil && store.ReadView().State.Network.Zones["catofes."].Authority != nil {
			// Parent commit survives the finite round deadline. Its queued
			// apply ACK must not finish a replacement session, which resumes
			// from the committed catalog without fetching this parent again.
			timedOut, err := driver.HandleGossipHostEvent(t.Context(), GossipEvent{Value: &gossip.RoundTimeoutEvent{PeerID: "bootstrap"}}, now, nil)
			if err != nil || !timedOut.Session.Done || timedOut.Session.TerminalErr == nil {
				t.Fatalf("round did not expire: %+v, %v", timedOut, err)
			}
			driver.Gossip.NewSession("bootstrap")
			handle(&gossip.SyncTimerEvent{PeerID: "bootstrap"})
			expired = true
			pages()
		}
	}
	view := store.ReadView()
	if gossip.AutoJoinPending(view.State) || len(view.State.Network.Zones) != len(source.Zones) {
		t.Fatalf("catalog did not adopt and converge: pending=%t zones=%d want=%d", gossip.AutoJoinPending(view.State), len(view.State.Network.Zones), len(source.Zones))
	}
	if expireAfterParent && !expired {
		t.Fatal("did not exercise partial progress across a round timeout")
	}
	counts := make(map[zone.ZonePath]int)
	for len(pulls) > 0 {
		counts[<-pulls]++
	}
	for _, path := range []zone.ZonePath{zone.RootZone, "catofes."} {
		if counts[path] != 1 {
			t.Fatalf("committed ancestor %s fetched %d times", path, counts[path])
		}
	}
}
