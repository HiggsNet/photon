package host

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

type coldCatalogClient struct {
	source     *zone.NetworkState
	pulls      chan zone.ZonePath
	beforeRead func(context.Context, zone.ZonePath)
}

func (client coldCatalogClient) Exchange(ctx context.Context, _ string, request *gossip.ObjectPullRequest) (*gossip.ObjectPullResponse, error) {
	client.pulls <- request.Zone
	if client.beforeRead != nil {
		client.beforeRead(ctx, request.Zone)
	}
	snapshot, err := corestate.Snapshot(client.source, request.Zone)
	return &gossip.ObjectPullResponse{OK: err == nil, Snapshot: snapshot}, err
}

// The remote catalog puts children on the first page and their authorities on
// the last. Real workers, signatures, store commits and apply acknowledgements
// must converge and retain committed ancestors if the first round expires.
func TestGossipColdCatalogAppliesAncestorsBeforeChildrenAcrossPages(t *testing.T) {
	for _, tc := range []struct {
		name           string
		pullsAtTimeout int
	}{
		{"without-timeout", 0},
		{"one-running-one-queued", 1},
		{"two-running", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testGossipColdCatalog(t, tc.pullsAtTimeout)
		})
	}
}

func testGossipColdCatalog(t *testing.T, pullsAtTimeout int) {
	expireAfterParent := pullsAtTimeout > 0
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
	client := coldCatalogClient{source: source, pulls: pulls}
	started, canceled := make(chan struct{}, 2), make(chan struct{}, 2)
	release := make(chan struct{})
	releaseWorkers := sync.OnceFunc(func() { close(release) })
	defer releaseWorkers()
	if expireAfterParent {
		var childPulls atomic.Int32
		client.beforeRead = func(ctx context.Context, path zone.ZonePath) {
			if path.Parent() == "catofes." && childPulls.Add(1) <= int32(pullsAtTimeout) {
				started <- struct{}{}
				<-ctx.Done()
				canceled <- struct{}{}
				<-release
			}
		}
	}
	executor := NewGossipObjectPullExecutor(GossipObjectPullExecutorConfig{
		Client: client, Now: clock.Now,
		Discovery: func() GossipDiscoveryInput {
			return GossipDiscoveryInput{Network: store.ReadView().State.Network, Bootstrap: map[string]*net.UDPAddr{"bootstrap": {IP: net.ParseIP("127.0.0.1"), Port: 1}}}
		},
		// This test concerns scheduling rather than the separate traffic quota.
		Quota: gossip.QuotaConfig{ByteRate: 8 << 20, ByteBurst: 8 << 20, ObjectRate: 1000, ObjectBurst: 1000},
	})
	workers := 4
	if pullsAtTimeout == 1 {
		workers = 1
	}
	if err := driver.StartGossipObjectPullWorkers(t.Context(), executor, workers, 64); err != nil {
		t.Fatal(err)
	}
	driver.Gossip.NewSession("bootstrap")
	handle := func(event gossip.SyncEvent) GossipHostEventResult {
		t.Helper()
		result, err := driver.HandleGossipHostEvent(t.Context(), GossipEvent{Value: event}, now)
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
	expired, restarted := false, false
	var oldRound *gossipObjectPullRound
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	for driver.Gossip.Session("bootstrap") != nil || (expireAfterParent && !restarted) {
		var event Event
		select {
		case event = <-driver.Events():
		case event = <-driver.Completions():
		case event = <-driver.Continuations():
		case <-deadline.C:
			t.Fatal("cold catalog did not finish")
		}
		result, err := driver.HandleGossipHostEvent(t.Context(), event, now)
		if err != nil || result.Session.TerminalErr != nil {
			t.Fatalf("cold catalog event %T: result=%+v error=%v", event, result.Session, err)
		}
		if queued, ok := event.(GossipEvent); expired && !restarted && ok {
			if _, ok := queued.Value.(*gossip.SyncTimerEvent); ok {
				restarted = true
				pages()
				stale := GossipEvent{
					Value: &gossip.ObjectPullResultEvent{
						PeerID: "bootstrap", Zone: "child-00.catofes.", Err: errors.New("late error from expired round"),
					},
					pullRound: oldRound,
				}
				result, err := driver.HandleGossipHostEvent(t.Context(), stale, now)
				if err != nil || result.Session.PeerID != "" {
					t.Fatalf("old result reached the replacement session: %+v, %v", result, err)
				}
			}
		}
		if expireAfterParent && !expired && store.ReadView().State.Network.Zones["catofes."] != nil && store.ReadView().State.Network.Zones["catofes."].Authority != nil {
			for range pullsAtTimeout {
				select {
				case <-started:
				case <-deadline.C:
					t.Fatal("old round did not start the expected child pulls")
				}
			}
			oldRound = driver.objectPullRounds["bootstrap"]
			if oldRound == nil {
				t.Fatal("active worker jobs have no round owner")
			}
			timedOut, err := driver.HandleGossipHostEvent(t.Context(), GossipEvent{Value: &gossip.RoundTimeoutEvent{PeerID: "bootstrap"}}, now)
			if err != nil || !timedOut.Session.Done || timedOut.Session.TerminalErr == nil {
				t.Fatalf("round did not expire: %+v, %v", timedOut, err)
			}
			for range pullsAtTimeout {
				select {
				case <-canceled:
				case <-deadline.C:
					t.Fatal("timeout did not cancel the running child pulls")
				}
				if err := driver.StartGossipSession("bootstrap", "ping_summary"); err != nil {
					t.Fatal(err)
				}
			}
			if driver.Gossip.Session("bootstrap") != nil || !driver.Gossip.PendingHint("bootstrap") {
				t.Fatal("follow-up was not deferred while the old round's workers were still active")
			}
			expired = true
			releaseWorkers()
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
	if pullsAtTimeout == 1 && counts["child-01.catofes."] != 1 {
		t.Fatalf("queued child was fetched %d times, want once in the replacement round", counts["child-01.catofes."])
	}
}
