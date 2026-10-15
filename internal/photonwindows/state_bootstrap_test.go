package photonwindows

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corehost "github.com/HiggsNet/photon/pkg/core/host"
	"github.com/HiggsNet/photon/pkg/core/share"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

func autoJoinConfig(t *testing.T) *Config {
	t.Helper()
	root, _ := generateWindowsKey(t)
	return &Config{State: StateConfig{Path: filepath.Join(t.TempDir(), "new", "state.db")}, ManagedZone: "node-a.catofes.", TrustedRootPublicKey: root, GossipListen: "127.0.0.1:0", Gateway: GatewayConfig{AllowedZones: []zone.ZonePath{"catofes."}, BootstrapHints: []BootstrapHint{{Peer: "catofes.", Address: "127.0.0.1:1"}}}}
}

func TestAutoJoinColdStateAndStableIdentity(t *testing.T) {
	config := autoJoinConfig(t)
	if _, err := OpenState(config.State.Path, config.ManagedZone, config.TrustedRootPublicKey, time.Second); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("strict open initialized state: %v", err)
	}
	state, err := OpenOrInitializeState(config, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	view := state.Store().ReadView()
	public := append(ed25519.PublicKey(nil), view.State.IdentityPrivateKey.Public().(ed25519.PublicKey)...)
	if !gossip.AutoJoinPending(view.State) || view.Revision != 0 || len(view.State.RootPrivateKey) != 0 || view.State.Network.Zones[config.ManagedZone].Authority != nil {
		t.Fatal("cold state was admitted or acquired root authority")
	}
	driver := corehost.NewGossipDriver(nil, 0, state.Store(), corehost.GossipDriverConfig{Discovery: corehost.GossipDiscoveryConfig{BootstrapPeers: []string{"catofes."}}})
	diagnosis := driver.AdmissionDiagnosis(time.Now())
	driver.Stop()
	var request gossip.JoinRequest
	if err := share.DecodeBase64JSON(diagnosis.JoinRequestB64, &request); err != nil {
		t.Fatal(err)
	}
	if !diagnosis.Pending || diagnosis.Reason != gossip.AdmissionReasonMissingParentZone || request.Zone != config.ManagedZone || !bytes.Equal(request.PublicKey, public) {
		t.Fatalf("cold diagnosis: %+v", diagnosis)
	}
	if _, err := state.EnsureLocalTransport(t.Context(), config, time.Now(), GatewayPlan{}, netip.MustParseAddrPort("127.0.0.1:19096")); err == nil {
		t.Fatal("pending state published a transport identity")
	}
	if len(state.Store().ReadView().State.Network.Zones[config.ManagedZone].Records) != 0 {
		t.Fatal("pending state published local records")
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	// Existing imported/pending databases do not require bootstrap just to open.
	config.Gateway.BootstrapHints = nil
	reopened, err := OpenOrInitializeState(config, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if !bytes.Equal(reopened.Store().ReadView().State.IdentityPrivateKey.Public().(ed25519.PublicKey), public) {
		t.Fatal("restart replaced the stable signing identity")
	}
	files, err := os.ReadDir(filepath.Dir(config.State.Path))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0].Name() != "state.db" {
		t.Fatalf("private material or staging files escaped database: %v", files)
	}
}

func TestAutoJoinMissingBootstrapDoesNotCreateState(t *testing.T) {
	config := autoJoinConfig(t)
	config.Gateway.BootstrapHints = nil
	if _, err := OpenOrInitializeState(config, time.Second); err == nil {
		t.Fatal("cold state accepted without bootstrap")
	}
	if _, err := os.Stat(config.State.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cold failure created state: %v", err)
	}
}

func TestAutoJoinRejectsExistingMismatchAndCorruptionWithoutOverwrite(t *testing.T) {
	for _, kind := range []string{"root", "managed", "corrupt", "empty"} {
		t.Run(kind, func(t *testing.T) {
			config := autoJoinConfig(t)
			if kind == "corrupt" || kind == "empty" {
				if err := os.MkdirAll(filepath.Dir(config.State.Path), 0700); err != nil {
					t.Fatal(err)
				}
				data := []byte("not a Bolt database")
				if kind == "empty" {
					data = nil
				}
				if err := os.WriteFile(config.State.Path, data, 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				state, err := OpenOrInitializeState(config, time.Second)
				if err != nil {
					t.Fatal(err)
				}
				if err := state.Close(); err != nil {
					t.Fatal(err)
				}
				if kind == "root" {
					config.TrustedRootPublicKey, _ = generateWindowsKey(t)
				} else {
					config.ManagedZone = "other.catofes."
				}
			}
			before, err := os.ReadFile(config.State.Path)
			if err != nil {
				t.Fatal(err)
			}
			if state, err := OpenOrInitializeState(config, time.Second); err == nil {
				state.Close()
				t.Fatal("existing invalid state replaced")
			}
			after, err := os.ReadFile(config.State.Path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("rejected existing state changed bytes")
			}
		})
	}
}

func TestAutoJoinConcurrentInitializationNeverReplacesWinner(t *testing.T) {
	config := autoJoinConfig(t)
	const count = 8
	start := make(chan struct{})
	results := make(chan ed25519.PublicKey, count)
	failures := make(chan error, count)
	var wg sync.WaitGroup
	for range count {
		wg.Go(func() {
			<-start
			state, err := OpenOrInitializeState(config, 2*time.Second)
			if err != nil {
				failures <- err
				return
			}
			results <- append(ed25519.PublicKey(nil), state.Store().ReadView().State.IdentityPrivateKey.Public().(ed25519.PublicKey)...)
			failures <- state.Close()
		})
	}
	close(start)
	wg.Wait()
	close(results)
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	var first ed25519.PublicKey
	for public := range results {
		if first == nil {
			first = public
		}
		if !bytes.Equal(first, public) {
			t.Fatal("concurrent creator replaced persisted identity")
		}
	}
	if first == nil {
		t.Fatal("no initializer succeeded")
	}
}

func TestAutoJoinPendingRuntimeRemainsObservableAndUnpublished(t *testing.T) {
	config := autoJoinConfig(t)
	d := NewDaemon(config, slog.New(slog.NewTextHandler(io.Discard, nil)))
	var opened atomic.Int32
	d.deviceFactory = func(context.Context, string, []netip.Prefix, []netip.Prefix, uint32, uint32) (ownedPacketDevice, error) {
		opened.Add(1)
		return nil, errors.New("unexpected pending device open")
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	run := make(chan error, 1)
	go func() { run <- d.Run(ctx) }()
	select {
	case <-d.Started():
	case err := <-run:
		t.Fatalf("pending runtime startup: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("pending runtime failed to start")
	}
	defer d.Stop(t.Context())
	for range 3 {
		out, err := d.Observe(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if !out.Running || !out.Admission.Pending || out.Admission.JoinRequestB64 == "" || out.UDPAddress == "" || out.TunnelReady || out.IKE.Live || out.IKE.ChildLive || out.Wintun.Configured || out.Babel.Live {
			t.Fatalf("pending observation: %+v", out)
		}
	}
	if opened.Load() != 0 {
		t.Fatal("pending runtime opened Wintun")
	}
	if err := d.Stop(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := <-run; err != nil {
		t.Fatal(err)
	}
	state, err := OpenState(config.State.Path, config.ManagedZone, config.TrustedRootPublicKey, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	if len(state.Store().ReadView().State.Network.Zones[config.ManagedZone].Records) != 0 {
		t.Fatal("pending runtime published local records")
	}
}

func TestAutoJoinCommonGossipRejectsWrongKeyThenAdoptsWithoutRestart(t *testing.T) {
	network, root, parentPrivate := signedNetwork(t)
	managed := zone.ZonePath("node-a.catofes.")
	delete(network.Zones, managed)
	config := autoJoinConfig(t)
	config.TrustedRootPublicKey = root
	state, err := OpenOrInitializeState(config, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	public := append(ed25519.PublicKey(nil), state.Store().ReadView().State.IdentityPrivateKey.Public().(ed25519.PublicKey)...)
	parentPath := filepath.Join(t.TempDir(), "parent.db")
	writeWindowsCommon(t, parentPath, &corestate.VerifiedState{ManagedZone: "catofes.", Network: network, TrustedRootPublicKey: root, IdentityPrivateKey: parentPrivate}, 1)
	parent, err := OpenState(parentPath, "catofes.", root, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	leftIO, rightIO := newMemoryGossipDatagramPair()
	left := newMemoryHostNode(parent, newWindowsGossipTransport(t, "catofes.", string(managed), leftIO, rightIO.LocalAddr()))
	right := newMemoryHostNode(state, newWindowsGossipTransport(t, string(managed), "catofes.", rightIO, leftIO.LocalAddr()))
	// Catalog changes can trigger reverse pulls too. Match the real daemon:
	// both peers need object-pull workers before either begins synchronizing.
	left.startObjectPull(t, right)
	right.startObjectPull(t, left)
	left.start(t)
	// Engine is synchronous: start both pulls on its one event owner, including
	// when delayed packets from the first round arrive during the second one.
	requests := make(chan chan error)
	if err := right.runtime.StartGossipTransport(right.ctx, right.transport, right.recordError); err != nil {
		t.Fatal(err)
	}
	go func() {
		defer close(right.done)
		for {
			select {
			case <-right.ctx.Done():
				return
			case reply := <-requests:
				reply <- right.runtime.StartGossipSession("catofes.", "auto-join fixture")
			case event := <-right.runtime.Events():
				if err := right.handleEvent(event); err != nil {
					right.recordError(err)
					return
				}
			}
		}
	}()
	beginSync := func() {
		t.Helper()
		reply := make(chan error, 1)
		select {
		case requests <- reply:
		case <-time.After(2 * time.Second):
			t.Fatal("sync request event owner unavailable")
		}
		if err := <-reply; err != nil {
			t.Fatal(err)
		}
	}
	defer left.stop(t)
	rightStopped := false
	defer func() {
		if !rightStopped {
			right.stop(t)
		}
	}()
	beginSync()
	waitForWindowsState(t, 2*time.Second, func() bool {
		return right.runtime.AdmissionDiagnosis(time.Now()).Reason == gossip.AdmissionReasonDelegationKeyMismatch
	})
	if !gossip.AutoJoinPending(right.store.ReadView().State) || right.store.ReadView().State.Network.Zones[managed].Authority != nil {
		t.Fatal("wrong delegation adopted local identity")
	}
	// This is an isolated parent authority fixture. Use the real local intent
	// to replace its wrong public key, then the same GossipDriver must adopt it.
	authority := &zone.ZoneAuthority{Zone: managed, Epoch: 2, Threshold: 1, Keys: []zone.AuthorizedKey{{Key: public, Capabilities: []zone.Capability{{Permissions: []zone.Permission{zone.PermWrite}}}}}}
	if _, err := left.store.ApplyLocalIntent(t.Context(), corestate.PutDelegationIntent{Parent: "catofes.", Authority: authority}, time.Now()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-right.completed:
	case <-time.After(2 * time.Second):
		t.Fatal("initial mismatch sync did not complete")
	}
	beginSync()
	waitForWindowsState(t, 2*time.Second, func() bool { return !right.runtime.AdmissionDiagnosis(time.Now()).Pending })
	view := right.store.ReadView()
	if err := photoncrypto.VerifyChain(view.State.Network, managed, time.Now()); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(view.State.IdentityPrivateKey.Public().(ed25519.PublicKey), public) || len(view.State.Network.Zones[managed].Records) != 0 {
		t.Fatal("adoption changed the identity or published local runtime records")
	}
	right.assertNoError(t)
	left.assertNoError(t)
	right.stop(t)
	rightStopped = true
	reopened, err := OpenOrInitializeState(config, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if gossip.AutoJoinPending(reopened.Store().ReadView().State) || !bytes.Equal(reopened.Store().ReadView().State.IdentityPrivateKey.Public().(ed25519.PublicKey), public) {
		t.Fatal("adoption or identity did not survive restart")
	}
}

func TestAutoJoinLoggerCreatesDirectoryBeforeDatabase(t *testing.T) {
	config := autoJoinConfig(t)
	logger, closer, err := NewRuntimeLogger(config, io.Discard, "")
	if err != nil {
		t.Fatal(err)
	}
	logger.Info("runtime_started")
	if err := closer.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(config.State.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("logger created the state database")
	}
	state, err := OpenOrInitializeState(config, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	state.Close()
}

func TestAutoJoinInitialDNSFailureRetainsStatusAndUsesPlannerRetry(t *testing.T) {
	config := autoJoinConfig(t)
	d := NewDaemon(config, slog.New(slog.NewTextHandler(io.Discard, nil)))
	var calls atomic.Int32
	d.resolveBootstrap = func(context.Context, *Config, netip.AddrPort) (map[string]*net.UDPAddr, error) {
		if calls.Add(1) == 1 {
			return nil, errors.New("fixture: temporary DNS failure")
		}
		return map[string]*net.UDPAddr{"catofes.": {IP: net.IPv4(127, 0, 0, 1), Port: 1}}, nil
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	run := make(chan error, 1)
	go func() { run <- d.Run(ctx) }()
	select {
	case <-d.Started():
	case err := <-run:
		t.Fatalf("offline startup failed: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("offline startup did not expose status")
	}
	defer d.Stop(t.Context())
	out, err := d.Observe(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !out.Running || !out.Admission.Pending || out.Admission.JoinRequestB64 == "" || out.TunnelReady {
		t.Fatalf("offline admission status unavailable: %+v", out)
	}
	waitForWindowsState(t, 2*time.Second, func() bool { return calls.Load() >= 2 })
	if err := d.Stop(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := <-run; err != nil {
		t.Fatal(err)
	}
}
