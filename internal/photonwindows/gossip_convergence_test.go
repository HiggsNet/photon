package photonwindows

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corehost "github.com/HiggsNet/photon/pkg/core/host"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

func TestGossipDriversConvergeCommonStateAndReloadWithoutClientRuntime(t *testing.T) {
	fixture := newWindowsGossipFixture(t)
	leftIO, rightIO := newMemoryGossipDatagramPair()
	leftTransport := newWindowsGossipTransport(t, "node-a.catofes.", "node-b.catofes.", leftIO, rightIO.LocalAddr())
	rightTransport := newWindowsGossipTransport(t, "node-b.catofes.", "node-a.catofes.", rightIO, leftIO.LocalAddr())

	leftState := fixture.openState(t, fixture.leftPath, "node-a.catofes.")
	rightState := fixture.openState(t, fixture.rightPath, "node-b.catofes.")
	left := newMemoryHostNode(leftState, leftTransport)
	right := newMemoryHostNode(rightState, rightTransport)
	left.start(t)
	right.start(t)
	right.startObjectPull(t, left)

	right.beginSync(t, "node-a.catofes.")
	waitForWindowsState(t, time.Second, func() bool {
		view := right.store.ReadView()
		return view.State != nil && view.State.Network.Zones["node-a.catofes."] != nil
	})
	select {
	case peerID := <-right.completed:
		if peerID != "node-a.catofes." {
			t.Fatalf("completed peer = %q", peerID)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for gossip session completion")
	}
	// GossipDriver now owns authenticated inbound-path checkpointing. The
	// completion that triggered relay is reported before the remote relay packet
	// necessarily reaches this node, so wait for that independent checkpoint
	// commit before taking the byte-for-byte persistence baseline.
	waitForWindowsState(t, time.Second, func() bool {
		peer := right.store.ReadView().Gossip.Peers["node-a.catofes."]
		return peer.ObservedEndpoint != "" && peer.ObservedLastSyncUnix != 0
	})
	converged := right.store.ReadView()
	if converged.Revision != fixture.rightRevision+1 {
		t.Fatalf("right revision = %d, want %d", converged.Revision, fixture.rightRevision+1)
	}
	if converged.State.ManagedZone != "node-b.catofes." || converged.State.Network.Zones["node-b.catofes."] == nil {
		t.Fatalf("right managed state was replaced: %+v", converged.State)
	}
	right.assertNoError(t)
	left.assertNoError(t)

	snapshot, err := corestate.Snapshot(left.store.ReadView().State.Network, "node-a.catofes.")
	if err != nil {
		t.Fatal(err)
	}
	beforeReject := right.store.VerifiedRevision()
	// Completed sessions are now removed by GossipDriver itself. This direct
	// executor check supplies its own detached protocol context instead of
	// relying on a stale session retained after convergence.
	rejectSession := gossip.NewSyncSession("node-a.catofes.")
	execution := right.runtime.ExecuteGossipActions(t.Context(), rejectSession, []gossip.SyncAction{gossip.ApplySnapshotAction{
		PeerID:       "node-a.catofes.",
		Snapshot:     snapshot,
		ExpectedRoot: []byte("wrong-root"),
	}}, right)
	if execution.Aborted {
		t.Fatal("individual rejected snapshot aborted the common batch")
	}
	rejected := right.store.ReadView()
	if rejected.Revision != beforeReject {
		t.Fatalf("reject advanced revision from %d to %d", beforeReject, rejected.Revision)
	}
	if item := rejected.Gossip.Peers["node-a.catofes."].RejectedObjects["node-a.catofes."]; item.Reason == "" {
		t.Fatalf("rejected checkpoint = %+v, want stable reason", item)
	}

	wantBytes := canonicalWindowsCommonBytes(t, rejected)
	wantCatalog := corestate.CatalogSummaryFor(rejected.State.Network)
	right.stop(t)
	reopened := fixture.openState(t, fixture.rightPath, "node-b.catofes.")
	reloaded, err := reopened.ReadView(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := canonicalWindowsCommonBytes(t, reloaded); !bytes.Equal(got, wantBytes) {
		t.Fatalf("reloaded common view differs\n got: %s\nwant: %s", got, wantBytes)
	}
	if got := corestate.CatalogSummaryFor(reloaded.State.Network); !bytes.Equal(got.CatalogRoot, wantCatalog.CatalogRoot) || got.ZoneCount != wantCatalog.ZoneCount {
		t.Fatalf("reloaded catalog = %+v, want %+v", got, wantCatalog)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
	left.stop(t)
}

type memoryHostNode struct {
	runtime   *corehost.GossipDriver
	storeRoot *StateStore
	store     *corestate.Store
	transport *gossip.Transport
	ctx       context.Context
	cancel    context.CancelFunc
	done      chan struct{}
	completed chan string

	errMu sync.Mutex
	err   error
}

func newMemoryHostNode(state *StateStore, transport *gossip.Transport) *memoryHostNode {
	ctx, cancel := context.WithCancel(context.Background())
	return &memoryHostNode{
		runtime: corehost.NewGossipDriver(corehost.NewClock(nil), corehost.DefaultEventBuffer, state.Store(), corehost.GossipDriverConfig{
			PeerID: transport.PeerID(), Limits: corestate.DefaultSyncLimits(),
		}),
		storeRoot: state,
		store:     state.Store(),
		transport: transport,
		ctx:       ctx,
		cancel:    cancel,
		done:      make(chan struct{}),
		completed: make(chan string, 4),
	}
}

func (node *memoryHostNode) start(t *testing.T) {
	t.Helper()
	if err := node.runtime.StartGossipTransport(node.ctx, node.transport, node.recordError); err != nil {
		t.Fatal(err)
	}
	go node.run()
}

func (node *memoryHostNode) run() {
	defer close(node.done)
	for {
		select {
		case <-node.ctx.Done():
			return
		case event := <-node.runtime.Events():
			if err := node.handleEvent(event); err != nil {
				node.recordError(err)
				return
			}
		}
	}
}

func (node *memoryHostNode) handleEvent(event corehost.Event) error {
	hostResult, err := node.runtime.HandleGossipHostEvent(node.ctx, event, time.Now(), nil)
	if errors.Is(err, corehost.ErrGossipSessionNotFound) {
		return nil
	}
	if err == nil && hostResult.Session.PeerID != "" && hostResult.Session.Done {
		select {
		case node.completed <- hostResult.Session.PeerID:
		default:
		}
	}
	return err
}

func (node *memoryHostNode) beginSync(t *testing.T, peerID string) {
	t.Helper()
	view := node.store.ReadView()
	node.runtime.Gossip.NewSession(peerID)
	if err := node.runtime.PostGossip(&gossip.SyncTimerEvent{
		PeerID:       peerID,
		LocalSummary: corestate.CatalogSummaryFor(view.State.Network),
	}); err != nil {
		t.Fatal(err)
	}
}

func (node *memoryHostNode) startObjectPull(t *testing.T, remote *memoryHostNode) {
	t.Helper()
	executor := corehost.NewGossipObjectPullExecutor(corehost.GossipObjectPullExecutorConfig{
		Client: memoryObjectPullClient{store: remote.store},
		Discovery: func() corehost.GossipDiscoveryInput {
			view := node.store.ReadView()
			return corehost.GossipDiscoveryInput{
				Network: view.State.Network,
				Bootstrap: map[string]*net.UDPAddr{
					remote.transport.PeerID(): {IP: net.ParseIP("127.0.0.1"), Port: 1},
				},
			}
		},
	})
	if err := node.runtime.StartGossipObjectPullWorkers(node.ctx, executor, 1, 4); err != nil {
		t.Fatal(err)
	}
}

func (node *memoryHostNode) stop(t *testing.T) {
	t.Helper()
	node.cancel()
	node.runtime.Stop()
	select {
	case <-node.done:
	case <-time.After(time.Second):
		t.Fatal("timed out stopping memory GossipDriver")
	}
	if err := node.storeRoot.Close(); err != nil {
		t.Fatal(err)
	}
}

func (node *memoryHostNode) recordError(err error) {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
		return
	}
	node.errMu.Lock()
	node.err = errors.Join(node.err, err)
	node.errMu.Unlock()
}

func (node *memoryHostNode) assertNoError(t *testing.T) {
	t.Helper()
	node.errMu.Lock()
	defer node.errMu.Unlock()
	if node.err != nil {
		t.Fatal(node.err)
	}
}

type memoryObjectPullClient struct {
	store *corestate.Store
}

func (client memoryObjectPullClient) Exchange(_ context.Context, _ string, request *gossip.ObjectPullRequest) (*gossip.ObjectPullResponse, error) {
	if client.store == nil || request == nil {
		return nil, errors.New("memory object-pull source is unavailable")
	}
	view := client.store.ReadView()
	snapshot, err := corestate.Snapshot(view.State.Network, request.Zone)
	if err != nil {
		return nil, err
	}
	return &gossip.ObjectPullResponse{OK: true, Snapshot: snapshot}, nil
}

func (node *memoryHostNode) GossipDatagramBudget() int { return node.transport.MaxMessageBytes() }

func (node *memoryHostNode) SendGossip(_ context.Context, outbound gossip.OutboundMessage) error {
	return node.transport.Send(outbound.PeerID, outbound.Message)
}

type windowsGossipFixture struct {
	leftPath, rightPath string
	rootPublic          ed25519.PublicKey
	rightRevision       corestate.VerifiedRevision
}

func newWindowsGossipFixture(t *testing.T) windowsGossipFixture {
	t.Helper()
	rootPublic, rootPrivate := generateWindowsKey(t)
	parentPublic, parentPrivate := generateWindowsKey(t)
	leftPublic, leftPrivate := generateWindowsKey(t)
	rightPublic, rightPrivate := generateWindowsKey(t)
	capabilities := []zone.Capability{{Permissions: []zone.Permission{zone.PermWrite, zone.PermDelegate, zone.PermAllocateIP}}}
	authority := func(path zone.ZonePath, key ed25519.PublicKey) *zone.ZoneAuthority {
		return &zone.ZoneAuthority{Zone: path, Epoch: 1, Threshold: 1, Keys: []zone.AuthorizedKey{{Key: key, Capabilities: capabilities}}}
	}
	rootAuthority := authority(zone.RootZone, rootPublic)
	parentAuthority := authority("catofes.", parentPublic)
	leftAuthority := authority("node-a.catofes.", leftPublic)
	rightAuthority := authority("node-b.catofes.", rightPublic)
	parentDelegation := &zone.Delegation{ZoneName: "catofes.", Authority: *parentAuthority}
	if err := photoncrypto.SignDelegation(parentDelegation, zone.RootZone, rootPrivate); err != nil {
		t.Fatal(err)
	}
	leftDelegation := &zone.Delegation{ZoneName: "node-a.catofes.", Authority: *leftAuthority}
	if err := photoncrypto.SignDelegation(leftDelegation, "catofes.", parentPrivate); err != nil {
		t.Fatal(err)
	}
	rightDelegation := &zone.Delegation{ZoneName: "node-b.catofes.", Authority: *rightAuthority}
	if err := photoncrypto.SignDelegation(rightDelegation, "catofes.", parentPrivate); err != nil {
		t.Fatal(err)
	}
	base := zone.NewNetworkState()
	base.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, rootAuthority)
	base.Zones[zone.RootZone].Delegations["catofes."] = parentDelegation
	base.Zones["catofes."] = zone.NewZoneState("catofes.", parentAuthority)
	base.Zones["catofes."].Delegations["node-a.catofes."] = leftDelegation
	base.Zones["catofes."].Delegations["node-b.catofes."] = rightDelegation
	leftNetwork := zone.CloneNetworkState(base)
	leftNetwork.Zones["node-a.catofes."] = zone.NewZoneState("node-a.catofes.", leftAuthority)
	rightNetwork := zone.CloneNetworkState(base)
	rightNetwork.Zones["node-b.catofes."] = zone.NewZoneState("node-b.catofes.", rightAuthority)
	fixture := windowsGossipFixture{
		leftPath:      filepath.Join(t.TempDir(), "left.db"),
		rightPath:     filepath.Join(t.TempDir(), "right.db"),
		rootPublic:    rootPublic,
		rightRevision: 11,
	}
	writeWindowsCommon(t, fixture.leftPath, &corestate.VerifiedState{
		ManagedZone: "node-a.catofes.", Network: leftNetwork, TrustedRootPublicKey: rootPublic, IdentityPrivateKey: leftPrivate,
	}, 5)
	writeWindowsCommon(t, fixture.rightPath, &corestate.VerifiedState{
		ManagedZone: "node-b.catofes.", Network: rightNetwork, TrustedRootPublicKey: rootPublic, IdentityPrivateKey: rightPrivate,
	}, fixture.rightRevision)
	return fixture
}

func (fixture windowsGossipFixture) openState(t *testing.T, path string, managed zone.ZonePath) *StateStore {
	t.Helper()
	state, err := OpenStateStore(path, managed, fixture.rootPublic, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func generateWindowsKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return public, private
}

func writeWindowsCommon(t *testing.T, path string, verified *corestate.VerifiedState, revision corestate.VerifiedRevision) {
	t.Helper()
	store, err := corestate.OpenBoltStore(path, 0o600, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	candidate := &corestate.CommitCandidate{Verified: verified, Gossip: &corestate.GossipCheckpoint{}}
	if err := store.CommitCommon(t.Context(), candidate, corestate.ChangeSet{VerifiedRevision: revision, NetworkChanged: true}); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}

func newWindowsGossipTransport(t *testing.T, local, peer string, datagram *memoryGossipDatagram, peerAddr *net.UDPAddr) *gossip.Transport {
	t.Helper()
	transport, err := gossip.NewTransport(gossip.Config{
		PeerID:     local,
		KnownPeers: map[string]*net.UDPAddr{peer: peerAddr},
	}, datagram)
	if err != nil {
		t.Fatal(err)
	}
	return transport
}

func waitForWindowsState(t *testing.T, timeout time.Duration, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !ready() {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for memory GossipDrivers to converge")
		}
		time.Sleep(time.Millisecond)
	}
}

func canonicalWindowsCommonBytes(t *testing.T, view corestate.View) []byte {
	t.Helper()
	encoded, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
