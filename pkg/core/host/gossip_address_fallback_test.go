package host

import (
	"context"
	"errors"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

type failingAddressDatagram struct{ memoryGossipDatagram }

func (d *failingAddressDatagram) WriteDatagram(payload []byte, addr *net.UDPAddr) (int, error) {
	_, _ = d.memoryGossipDatagram.WriteDatagram(payload, addr)
	if addr.IP.To4() == nil {
		return 0, &net.OpError{Op: "write", Net: "udp", Err: errors.New("network unreachable")}
	}
	return len(payload), nil
}

func TestGossipUDPImmediateFailureFallsBackAndRemembersAddress(t *testing.T) {
	d := &failingAddressDatagram{}
	var events []gossip.Event
	transport, err := gossip.NewTransport(gossip.Config{PeerID: "local", Log: func(e gossip.Event) { events = append(events, e) }}, d)
	if err != nil {
		t.Fatal(err)
	}
	v6 := &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 33434}
	v4 := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 33434}
	transport.SetPeerAddrs("peer", []*net.UDPAddr{v6, v4})
	for range 2 {
		if err := transport.Send("peer", &gossip.Message{Type: gossip.MessagePing, Ping: &gossip.Ping{}}); err != nil {
			t.Fatal(err)
		}
	}
	if got := d.writeAddrs; len(got) != 3 || got[0].String() != v6.String() || got[1].String() != v4.String() || got[2].String() != v4.String() {
		t.Fatalf("write attempts = %v, want IPv6, IPv4, IPv4", got)
	}
	if transport.AddrFailureCount("peer", v6) != 1 || len(events) != 3 || events[0].Error == "" || events[0].Addr != v6.String() {
		t.Fatalf("failure not retained/logged: health=%v events=%v", transport.PeerAddrStates("peer"), events)
	}
}

func TestGossipUDPTimeoutOverridesRecentSuccess(t *testing.T) {
	clock := newFakeClock(time.Unix(100, 0))
	driver := NewGossipDriver(clock, 4, &memoryGossipStateStore{views: []corestate.View{loadedGossipState()}}, GossipDriverConfig{PeerID: "local.catofes.", Limits: corestate.DefaultSyncLimits()})
	defer driver.Stop()
	transport, _ := bindMemoryGossipTransport(t, driver, "peer-a")
	v6 := &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 33434}
	v4 := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 33434}
	transport.SetPeerAddrs("peer-a", []*net.UDPAddr{v6, v4})
	transport.RecordAddrSuccess("peer-a", v6)
	driver.Gossip.NewSession("peer-a")
	if _, err := driver.HandleGossipHostEvent(t.Context(), GossipEvent{Value: &gossip.SyncTimerEvent{PeerID: "peer-a"}}, clock.Now(), nil); err != nil {
		t.Fatal(err)
	}
	result, err := driver.HandleGossipHostEvent(t.Context(), GossipEvent{Value: &gossip.RoundTimeoutEvent{PeerID: "peer-a"}}, clock.Now(), nil)
	if err != nil || !result.Session.Done {
		t.Fatalf("timeout result = %#v, error = %v", result, err)
	}
	if err := transport.Send("peer-a", &gossip.Message{Type: gossip.MessagePing, Ping: &gossip.Ping{}}); err != nil {
		t.Fatal(err)
	}
	if got := transport.LastSendAddr("peer-a"); got.String() != v4.String() {
		t.Fatalf("next request address = %v, want IPv4 after first timeout", got)
	}
}

type addressFallbackClient struct {
	attempts []string
	exchange func(context.Context, string, *gossip.ObjectPullRequest) (*gossip.ObjectPullResponse, error)
}

func (c *addressFallbackClient) Exchange(ctx context.Context, addr string, req *gossip.ObjectPullRequest) (*gossip.ObjectPullResponse, error) {
	c.attempts = append(c.attempts, addr)
	return c.exchange(ctx, addr, req)
}

func dualAddressDiscovery(t *testing.T, now time.Time) GossipDiscoveryInput {
	t.Helper()
	network, _ := signedDiscoveryNetwork(t, "peer.catofes.", true, []gossip.EndpointEntry{
		{Address: "2001:db8::1", Port: 33434, Source: "advertise", Priority: 100},
		{Address: "192.0.2.1", Port: 33434, Source: "advertise", Priority: 90},
	}, now)
	return GossipDiscoveryInput{Network: network}
}

func TestGossipTCPFallsBackAndRemembersReachability(t *testing.T) {
	now := time.Now()
	input := dualAddressDiscovery(t, now)
	client := &addressFallbackClient{exchange: func(_ context.Context, addr string, req *gossip.ObjectPullRequest) (*gossip.ObjectPullResponse, error) {
		if addr == "[2001:db8::1]:33434" {
			return nil, &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("network unreachable")}
		}
		return &gossip.ObjectPullResponse{OK: true, Snapshot: &corestate.ZoneSnapshot{Zone: req.Zone}}, nil
	}}
	executor := NewGossipObjectPullExecutor(GossipObjectPullExecutorConfig{Client: client, Now: func() time.Time { return now }})
	for range 2 {
		result := executor.PullFrom(t.Context(), input, gossip.StartObjectPullAction{PeerID: "peer.catofes.", Zone: "peer.catofes."})
		if result.Err != nil || result.Addr != "192.0.2.1:33434" || result.Snapshot == nil || result.Unreachable {
			t.Fatalf("pull result = %#v", result)
		}
	}
	want := []string{"[2001:db8::1]:33434", "192.0.2.1:33434", "192.0.2.1:33434"}
	if !reflect.DeepEqual(client.attempts, want) {
		t.Fatalf("TCP attempts = %v, want %v", client.attempts, want)
	}
	// Idle history expires, allowing the discovery order to be tried again.
	now = now.Add(objectPullAddressTTL + time.Second)
	addresses := executor.orderAddresses("peer.catofes.", ResolveGossipObjectPullAddresses(input, "peer.catofes.", now), now)
	if len(executor.addrs) != 0 || addresses[0] != "[2001:db8::1]:33434" {
		t.Fatalf("expired history = %v, addresses = %v", executor.addrs, addresses)
	}
}

func TestGossipTCPTimeoutReservesBudgetForFallback(t *testing.T) {
	input := dualAddressDiscovery(t, time.Now())
	client := &addressFallbackClient{exchange: func(ctx context.Context, addr string, req *gossip.ObjectPullRequest) (*gossip.ObjectPullResponse, error) {
		if addr == "[2001:db8::1]:33434" {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return &gossip.ObjectPullResponse{OK: true, Snapshot: &corestate.ZoneSnapshot{Zone: req.Zone}}, ctx.Err()
	}}
	executor := NewGossipObjectPullExecutor(GossipObjectPullExecutorConfig{Client: client})
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	result := executor.PullFrom(ctx, input, gossip.StartObjectPullAction{PeerID: "peer.catofes.", Zone: "peer.catofes."})
	if result.Err != nil || len(client.attempts) != 2 || ctx.Err() != nil {
		t.Fatalf("fallback result = %#v, attempts = %v, context = %v", result, client.attempts, ctx.Err())
	}
}

func TestGossipTCPDoesNotRetryProtocolFailuresOrCancellation(t *testing.T) {
	for _, mode := range []string{"wrong-zone", "rejected", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			input := dualAddressDiscovery(t, time.Now())
			client := &addressFallbackClient{exchange: func(context.Context, string, *gossip.ObjectPullRequest) (*gossip.ObjectPullResponse, error) {
				return &gossip.ObjectPullResponse{OK: mode != "rejected", Snapshot: &corestate.ZoneSnapshot{Zone: "other.catofes."}}, nil
			}}
			executor := NewGossipObjectPullExecutor(GossipObjectPullExecutorConfig{Client: client})
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			wantAttempts := 1
			if mode == "canceled" {
				cancel()
				wantAttempts = 0
			}
			result := executor.PullFrom(ctx, input, gossip.StartObjectPullAction{PeerID: "peer.catofes.", Zone: "peer.catofes."})
			if result.Err == nil || len(client.attempts) != wantAttempts || result.Snapshot != nil {
				t.Fatalf("result = %#v, attempts = %v", result, client.attempts)
			}
		})
	}
}

func TestGossipDiscoveryRetainsGraceAndUnknownSources(t *testing.T) {
	now := time.Now()
	input := dualAddressDiscovery(t, now)
	network, _ := signedDiscoveryNetwork(t, "peer.catofes.", true, []gossip.EndpointEntry{
		{Address: "2001:db8::1", Port: 33434, Source: "advertise"},
		{Address: "192.0.2.1", Port: 33434, Source: "advertise+grace"},
		{Address: "192.0.2.2", Port: 33434, Source: "legacy"},
	}, now)
	input.Network = network
	plan := PlanGossipDiscovery(input, now)
	if got := plan.Peers["peer.catofes."].SetAddresses; len(got) != 3 {
		t.Fatalf("UDP candidates = %v, want all valid sources", got)
	}
	input.Bootstrap = map[string]*net.UDPAddr{"peer.catofes.": {IP: net.ParseIP("192.0.2.1"), Port: 33434}}
	input.Peers = map[string]corestate.PeerCheckpoint{"peer.catofes.": {
		ObservedEndpoint: "[2001:db8::1]:33434", ObservedUntilUnix: now.Add(time.Minute).Unix(),
		ObservedGraceEndpoints: []corestate.ObservedGraceEndpoint{
			{Endpoint: "192.0.2.3:33434", UntilUnix: now.Add(time.Minute).Unix()},
			{Endpoint: "192.0.2.4:33434", UntilUnix: now.Add(-time.Minute).Unix()},
		},
	}}
	want := []string{"[2001:db8::1]:33434", "192.0.2.3:33434", "192.0.2.1:33434", "192.0.2.2:33434"}
	if got := ResolveGossipObjectPullAddresses(input, "peer.catofes.", now); !reflect.DeepEqual(got, want) {
		t.Fatalf("TCP candidates = %v, want %v", got, want)
	}
	input.Peers["unknown.catofes."] = input.Peers["peer.catofes."]
	if got := ResolveGossipObjectPullAddresses(input, "unknown.catofes.", now); len(got) != 0 {
		t.Fatalf("unverified observed paths accepted: %v", got)
	}
}
