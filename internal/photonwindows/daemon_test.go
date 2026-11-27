package photonwindows

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestDaemonRebindKeepsStateAndObjectPull(t *testing.T) {
	fixture := newWindowsGossipFixture(t)
	config := &Config{State: StateConfig{Path: fixture.leftPath}, ManagedZone: "node-a.catofes.", TrustedRootPublicKey: fixture.rootPublic, GossipListen: "127.0.0.1:0"}
	logs := consoleLog{ready: make(chan string, 1)}
	daemon := NewDaemon(config, slog.New(slog.NewJSONHandler(logs, nil)))
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- daemon.Run(ctx) }()
	defer cancel()
	var address string
	select {
	case address = <-logs.ready:
	case err := <-done:
		t.Fatalf("startup: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("startup timed out")
	}
	for range 3 {
		if err := daemon.Rebind(t.Context()); err != nil {
			t.Fatal(err)
		}
		response, err := (objectPullClient{}).Exchange(t.Context(), address, &gossip.ObjectPullRequest{Type: gossip.ObjectPullZone, Zone: "node-a.catofes."})
		if err != nil || !response.OK {
			t.Fatalf("object-pull after rebind: %v %v", response, err)
		}
	}
	if err := daemon.Run(ctx); err == nil {
		t.Fatal("duplicate daemon run accepted")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("daemon did not stop")
	}
	if !errors.Is(daemon.Rebind(t.Context()), net.ErrClosed) {
		t.Fatal("stopped daemon accepted rebind")
	}
	// Closing the daemon releases the original database handle.
	state := fixture.openState(t, fixture.leftPath, "node-a.catofes.")
	state.Close()
}

func TestDaemonServesControlWhileOldSocketCloses(t *testing.T) {
	fixture := newWindowsGossipFixture(t)
	config := &Config{State: StateConfig{Path: fixture.leftPath}, ManagedZone: "node-a.catofes.", TrustedRootPublicKey: fixture.rootPublic, GossipListen: "127.0.0.1:0"}
	logs := consoleLog{ready: make(chan string, 1)}
	d := NewDaemon(config, slog.New(slog.NewJSONHandler(logs, nil)))
	pinned := make(chan *packetSockets, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	unpin := func() { releaseOnce.Do(func() { close(release) }) }
	d.rebindSocket = func(sockets *packetSockets, ctx context.Context) error {
		sockets.mu.Lock()
		conn := sockets.udp
		sockets.mu.Unlock()
		raw, err := conn.SyscallConn()
		if err != nil {
			return err
		}
		held := make(chan struct{})
		go func() {
			_ = raw.Control(func(uintptr) {
				close(held)
				<-release
			})
		}()
		select {
		case <-held:
		case <-ctx.Done():
			return ctx.Err()
		}
		pinned <- sockets
		return sockets.Rebind(ctx)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()
	t.Cleanup(func() {
		unpin()
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("daemon did not stop")
		}
	})
	var original string
	select {
	case original = <-logs.ready:
	case <-time.After(3 * time.Second):
		t.Fatal("daemon did not start")
	}
	rebound := make(chan error, 1)
	go func() { rebound <- d.Rebind(ctx) }()
	var sockets *packetSockets
	select {
	case sockets = <-pinned:
	case <-time.After(time.Second):
		t.Fatal("old socket was not pinned")
	}
	detached := make(chan struct{})
	go func() {
		defer close(detached)
		for sockets.bound() && ctx.Err() == nil {
			time.Sleep(time.Millisecond)
		}
	}()
	select {
	case <-detached:
	case <-time.After(time.Second):
		t.Fatal("socket state was blocked behind close")
	}
	query, stopQuery := context.WithTimeout(ctx, time.Second)
	defer stopQuery()
	if sample, err := d.Observe(query); err != nil || !sample.Running {
		t.Fatalf("event loop did not serve an observation while the socket was closing: running=%t, err=%v", sample.Running, err)
	}
	select {
	case err := <-rebound:
		t.Fatalf("replacement completed while old socket was pinned: %v", err)
	default:
	}
	unpin()
	select {
	case err := <-rebound:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("replacement did not complete after unpinning the old socket")
	}
	response, err := (objectPullClient{}).Exchange(ctx, original, &gossip.ObjectPullRequest{Type: gossip.ObjectPullZone, Zone: "node-a.catofes."})
	if err != nil || !response.OK {
		t.Fatalf("same endpoint did not resume after replacement: %v %v", response, err)
	}
}

type daemonPlanLog struct {
	consoleLog
	plans chan struct{}
}

func (l daemonPlanLog) Write(data []byte) (int, error) {
	var record struct {
		Message string `json:"msg"`
	}
	if json.Unmarshal(data, &record) == nil && record.Message == "gateway_plan_changed" {
		l.plans <- struct{}{}
	}
	return l.consoleLog.Write(data)
}

func TestDaemonDiscardsPlannerCompletionAfterRebind(t *testing.T) {
	fixture := newWindowsGossipFixture(t)
	config := &Config{State: StateConfig{Path: fixture.leftPath}, ManagedZone: "node-a.catofes.", TrustedRootPublicKey: fixture.rootPublic, GossipListen: "127.0.0.1:0"}
	logs := daemonPlanLog{consoleLog: consoleLog{ready: make(chan string, 1)}, plans: make(chan struct{}, 16)}
	daemon := NewDaemon(config, slog.New(slog.NewJSONHandler(logs, nil)))
	entered := make(chan context.Context, 2)
	release := make(chan struct{})
	daemon.planGateway = func(ctx context.Context, _ *Config, view corestate.View, now time.Time, _ ipsec.DNSResolver) GatewayPlan {
		entered <- ctx
		// Model a resolver completion racing with cancellation: it returns an old
		// result even though its request has been superseded by network rebind.
		select {
		case <-ctx.Done():
		case <-release:
		}
		return GatewayPlan{Revision: view.Revision, EvaluatedAt: now, Rejected: "no contact"}
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- daemon.Run(ctx) }()
	defer cancel()
	select {
	case <-logs.ready:
	case <-time.After(5 * time.Second):
		t.Fatal("startup timeout")
	}
	var old context.Context
	select {
	case old = <-entered:
	case <-time.After(time.Second):
		t.Fatal("planner did not start")
	}
	if err := daemon.Rebind(t.Context()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-old.Done():
	case <-time.After(time.Second):
		t.Fatal("rebind did not cancel old lookup")
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("replacement plan did not start")
	}
	// Querying while DNS is blocked must remain responsive and fail closed.
	observation, err := daemon.Observe(t.Context())
	if err != nil || observation.Gateway.Selected != "" || observation.Gateway.RevalidationRejected == "" {
		t.Fatalf("pending plan: %+v, %v", observation.Gateway, err)
	}
	select {
	case <-logs.plans:
		t.Fatal("superseded completion was consumed")
	default:
	}
	close(release)
	select {
	case <-logs.plans:
	case <-time.After(time.Second):
		t.Fatal("current completion was not consumed")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown blocked by planner")
	}
}

type fixtureGatewayDNS struct {
	outboundDNS
	lookup func(context.Context, string) ([]net.IPAddr, error)
}

func (d fixtureGatewayDNS) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	return d.lookup(ctx, host)
}

func TestDaemonPlansOtherGatewaysWhileDNSIsBlocked(t *testing.T) {
	f := newGatewayPatternFixture(t)
	f.ensureAuthority(t, f.config.ManagedZone)
	for _, peer := range []zone.ZonePath{"node-a.catofes.", "node-b.catofes."} {
		f.addGateway(t, peer)
		f.put(t, peer, ipsec.RecordKeyAddresses, ipsec.RecordTypeAddresses, ipsec.AddressRecord{
			Version: 1, UpdatedAt: f.now.Unix(), Addresses: []ipsec.AddressAdvertisement{
				{ID: "dns", Source: ipsec.SourceManualDNS, Host: string(peer) + "example", Family: ipsec.FamilyIPv4, TTLSeconds: 60},
			},
		})
	}
	f.config.State.Path = filepath.Join(t.TempDir(), "state.db")
	f.config.GossipListen = "127.0.0.1:0"
	f.view.State.ManagedZone = f.config.ManagedZone
	f.view.State.TrustedRootPublicKey = f.config.TrustedRootPublicKey
	f.view.State.IdentityPrivateKey = f.private
	writeWindowsCommon(t, f.config.State.Path, f.view.State, f.view.Revision)
	logs := consoleLog{ready: make(chan string, 1)}
	daemon := NewDaemon(f.config, slog.New(slog.NewJSONHandler(logs, nil)))
	unblock := make(chan struct{})
	recoverDNS := make(chan struct{})
	resolver := fixtureGatewayDNS{net.DefaultResolver, func(ctx context.Context, name string) ([]net.IPAddr, error) {
		if name == "node-a.catofes.example" {
			select {
			case <-unblock:
				select {
				case <-recoverDNS:
					return []net.IPAddr{{IP: net.IPv4(192, 0, 2, 45)}}, nil
				default:
					return nil, errors.New("fixture DNS server timed out")
				}
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return []net.IPAddr{{IP: net.IPv4(192, 0, 2, 44)}}, nil
	}}
	ctx, cancel := context.WithCancel(context.WithValue(t.Context(), outboundDNSKey{}, resolver))
	done := make(chan error, 1)
	go func() { done <- daemon.Run(ctx) }()
	defer cancel()
	select {
	case <-logs.ready:
	case <-time.After(5 * time.Second):
		t.Fatal("startup timeout")
	}
	waitForWindowsState(t, 2*time.Second, func() bool {
		out, err := daemon.Observe(ctx)
		return err == nil && out.Gateway.Selected == "node-b.catofes." &&
			len(out.Gateway.Candidates) == 2 && strings.Contains(out.Gateway.Candidates[0].Rejected, errGatewayDNSPending.Error()) &&
			len(out.Connections) == 2 && out.Connections[0].Peer == "node-a.catofes." &&
			out.Connections[0].WaitingForDNS && !out.Connections[0].IKE.AttemptActive &&
			out.Connections[1].Peer == "node-b.catofes." && !out.Connections[1].WaitingForDNS
	})
	close(unblock)
	waitForWindowsState(t, 2*time.Second, func() bool {
		out, err := daemon.Observe(ctx)
		return err == nil && out.Gateway.Selected == "node-b.catofes." &&
			len(out.Gateway.Candidates) == 2 && strings.Contains(out.Gateway.Candidates[0].Rejected, "fixture DNS server timed out") &&
			len(out.Connections) == 2 && out.Connections[0].WaitingForDNS
	})
	close(recoverDNS)
	waitForWindowsState(t, 12*time.Second, func() bool {
		out, err := daemon.Observe(ctx)
		return err == nil && out.Gateway.Selected == "node-a.catofes." &&
			len(out.Connections) == 2 && out.Connections[0].Peer == "node-a.catofes." && !out.Connections[0].WaitingForDNS &&
			out.Connections[0].IKE.AttemptGateway == "node-a.catofes."
	})
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown blocked")
	}
}
