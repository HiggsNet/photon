package photonwindows

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/photonclient/babel"
	"github.com/HiggsNet/photon/internal/photonclient/esp"
	"github.com/HiggsNet/photon/internal/photonclient/ike"
	"github.com/HiggsNet/photon/internal/photonclient/sadr"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
	"github.com/HiggsNet/photon/pkg/routing"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestMeshPlanConnectsEveryAuthorizedPeer(t *testing.T) {
	f := newGatewayPatternFixture(t)
	f.addGateway(t, "node-b.catofes.")
	f.ensureAuthority(t, "unsigned.catofes.")
	plan := planGateway(t.Context(), f.config, f.view, f.now, nil)
	if len(plan.Targets) != 2 {
		t.Fatalf("want two independent targets, got %+v", plan)
	}
	socket, err := openPacketSockets(t.Context(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	m := newMeshRuntime(t.Context(), f.config, nil, socket, nil, slog.New(slog.NewTextHandler(io.Discard, nil)), func() {})
	defer m.close()
	m.update(plan)
	if len(m.peers) != 2 {
		t.Fatal("planner still reduces peers to one gateway")
	}
	a, b := m.peers[meshPath{"node-a.catofes.", ipsec.FamilyIPv4}], m.peers[meshPath{"node-b.catofes.", ipsec.FamilyIPv4}]
	if a == nil || b == nil || a.tunnel.data == b.tunnel.data {
		t.Fatal("peers share mutable SA state")
	}
	// Even two identities sharing one public endpoint retain separate lifetimes.
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	endpoint := server.LocalAddr().(*net.UDPAddr).AddrPort()
	_, private, _ := ed25519.GenerateKey(nil)
	for _, p := range []*meshPeer{a, b} {
		p.plan.Selected.Contact.Address = endpoint.Addr().String()
		p.plan.Selected.Contact.IKEPort, p.plan.Selected.Contact.NATTPort = endpoint.Port(), endpoint.Port()
		if err := p.tunnel.start(p.plan, "local.catofes.", private, f.now); err != nil {
			t.Fatal(err)
		}
	}
	secondGeneration := b.tunnel.generation
	m.stopPeer(a, "first peer unreachable")
	if b.tunnel.phase != 1 || b.tunnel.generation != secondGeneration {
		t.Fatal("one failure reset healthy peer")
	}
	if _, ok := socket.tunnels[secondGeneration]; !ok {
		t.Fatal("one failure removed other endpoint reservation")
	}
	if b.backoff != m.initial || !b.next.IsZero() {
		t.Fatal("one failure changed another peer's retry")
	}
	// A signed candidate disappearing removes exactly its own connection.
	delete(f.view.State.Network.Zones["node-a.catofes."].Records, ipsec.RecordKeyProfile)
	m.update(planGateway(t.Context(), f.config, f.view, f.now, nil))
	if len(m.peers) != 1 || m.peers[meshPath{"node-b.catofes.", ipsec.FamilyIPv4}] != b || b.tunnel.generation != secondGeneration {
		t.Fatal("revocation disturbed the surviving connection")
	}
}

func TestMeshSocketReservationsSurviveOtherPeerRetirement(t *testing.T) {
	s, err := openPacketSockets(t.Context(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	endpoint := netip.MustParseAddrPort("127.0.0.1:4500")
	a, b := s.reserveTunnel(endpoint, endpoint), s.reserveTunnel(endpoint, endpoint)
	packet := []byte{1, 2, 3, 4, 0, 0, 0, 1, 0x42}
	s.mu.Lock()
	consumed := s.demuxLocked(packet, endpoint)
	s.mu.Unlock()
	if !consumed || len(s.espPackets) != 2 {
		t.Fatal("shared endpoint did not reach both authenticated SA owners")
	}
	first, second := <-s.espPackets, <-s.espPackets
	if first.generation == second.generation || !bytes.Equal(first.packet, packet) || !bytes.Equal(second.packet, packet) {
		t.Fatal("incorrect shared-endpoint demux")
	}
	first.packet[0] = 0
	if second.packet[0] != packet[0] {
		t.Fatal("different decrypt attempts share a mutable buffer")
	}
	s.releaseTunnel(a)
	s.mu.Lock()
	s.demuxLocked(packet, endpoint)
	s.mu.Unlock()
	if got := <-s.espPackets; got.generation != b || len(s.espPackets) != 0 {
		t.Fatal("retired peer still receives, or healthy peer was cleared")
	}
	if err := s.WriteTunnel(a, packet, endpoint); err == nil {
		t.Fatal("retired generation wrote to network")
	}
	if err := s.Rebind(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteTunnel(b, packet, endpoint); err == nil {
		t.Fatal("old generation survived socket replacement")
	}
}

func TestMeshSameGatewayKeepsBothOuterFamilies(t *testing.T) {
	socket, err := openPacketSockets(t.Context(), "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	m := newMeshRuntime(t.Context(), &Config{}, nil, socket, nil, slog.New(slog.NewTextHandler(io.Discard, nil)), func() {})
	defer m.close()
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	const gateway = "node-a.catofes."
	candidate := GatewayCandidate{Zone: gateway}
	var responders []*net.UDPConn
	for _, address := range []string{"127.0.0.1", "::1"} {
		addr := netip.MustParseAddr(address)
		server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IP(addr.AsSlice())})
		if err != nil {
			t.Fatal(err)
		}
		defer server.Close()
		responders = append(responders, server)
		port := uint16(server.LocalAddr().(*net.UDPAddr).Port)
		candidate.Contacts = append(candidate.Contacts, ipsec.ContactPoint{Address: address, IKEPort: port, NATTPort: port})
	}
	now := time.Now()
	plan := GatewayPlan{Candidates: []GatewayCandidate{candidate}, EvaluatedAt: now}
	m.update(plan)
	v4, v6 := m.peers[meshPath{gateway, ipsec.FamilyIPv4}], m.peers[meshPath{gateway, ipsec.FamilyIPv6}]
	if v4 == nil || v6 == nil || v4.tunnel.data == v6.tunnel.data {
		t.Fatal("gateway does not own two independent paths")
	}
	for i, peer := range []*meshPeer{v4, v6} {
		if err := peer.tunnel.start(peer.plan, "local.catofes.", private, now); err != nil {
			t.Fatal(err)
		}
		if err := responders[i].SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		var wire [2048]byte
		if n, source, err := responders[i].ReadFromUDPAddrPort(wire[:]); err != nil ||
			n == 0 || outerFamily(source.Addr()) != peer.plan.outerFamily {
			t.Fatalf("no IKE request on %s: source=%s bytes=%d err=%v", peer.plan.outerFamily, source, n, err)
		}
	}
	generation := v4.tunnel.generation
	plan.Candidates[0].Contacts = candidate.Contacts[:1]
	m.update(plan)
	_, reserved := socket.tunnels[generation]
	if len(m.peers) != 1 || v4.tunnel.phase != 1 || v4.tunnel.generation != generation ||
		!reserved || v6.tunnel.phase != 0 {
		t.Fatal("withdrawing IPv6 disturbed the IPv4 path")
	}
}

func TestMeshDeviceHasOneReaderAndSurvivesPeerFailure(t *testing.T) {
	device := newRuntimeDevice()
	var opens atomic.Int32
	var lifetime context.Context
	m := newMeshDevice(t.Context(), func(ctx context.Context, _ string, _ []netip.Prefix, _ []netip.Prefix, _ uint32, _ uint32) (ownedPacketDevice, error) {
		lifetime = ctx
		opens.Add(1)
		return device, nil
	})
	addresses := []netip.Prefix{netip.MustParsePrefix("10.9.0.1/32")}
	firstContext, cancelFirst := context.WithCancel(t.Context())
	defer cancelFirst()
	a, err := m.acquire(firstContext, "mesh", addresses, nil, 1400, 100)
	if err != nil {
		t.Fatal(err)
	}
	b, err := m.acquire(t.Context(), "mesh", addresses, nil, 1400, 100)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if opens.Load() != 1 {
		t.Fatal("multiple peers created duplicate OS adapters")
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	cancelFirst()
	if lifetime.Err() != nil {
		t.Fatal("first peer cancellation killed shared Windows device lifetime")
	}
	select {
	case <-device.closed:
		t.Fatal("first peer removed shared adapter")
	default:
	}
	device.input <- []byte{1, 2, 3}
	source := m.source.Load()
	if source == nil || !m.current(source.generation) {
		t.Fatal("first peer retired the shared packet source")
	}
	readCtx, cancelRead := context.WithTimeout(t.Context(), time.Second)
	defer cancelRead()
	packet, err := source.device.Read(readCtx)
	if err != nil || !bytes.Equal(packet, []byte{1, 2, 3}) {
		t.Fatalf("shared packet source stopped with first peer: %v, %v", packet, err)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if m.source.Load() != nil || m.current(source.generation) {
		t.Fatal("last peer did not retire the packet source")
	}
	select {
	case <-device.closed:
	default:
		t.Fatal("last peer leaked adapter")
	}
}

// Two real signed peers, independent ESP SAs and Babel neighbors share the
// same local host. No route or authorization is invented by the selector.
func meshRouteFixture(t *testing.T) (*meshRuntime, *gatewayPatternFixture) {
	t.Helper()
	f := newGatewayPatternFixture(t)
	f.addGateway(t, "node-b.catofes.")
	f.ensureAuthority(t, f.config.ManagedZone)
	f.config.TrustedRootPublicKey = f.private.Public().(ed25519.PublicKey)
	f.view.State.Network.Zones[zone.RootZone].Authority = photoncrypto.ConfiguredRootAuthority(f.config.TrustedRootPublicKey)
	if err := photoncrypto.SignDelegation(f.view.State.Network.Zones[zone.RootZone].Delegations["catofes."], zone.RootZone, f.private); err != nil {
		t.Fatal(err)
	}
	f.config.Overlay.SplitRoutes = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	put := func(path zone.ZonePath, key, kind string, value any) { f.put(t, path, key, kind, value) }
	key, _ := routing.NormalizeIPAMPoolKey("10.0.0.0/8")
	put(zone.RootZone, key, routing.RecordTypeIPAMPool, routing.IPAMPoolRecord{Version: 1, Prefix: "10.0.0.0/8", DelegatedTo: zone.RootZone, Active: true})
	for _, entry := range []struct {
		peer   zone.ZonePath
		prefix string
	}{{f.config.ManagedZone, "10.9.0.1/32"}, {"node-a.catofes.", "10.1.0.0/16"}, {"node-b.catofes.", "10.2.0.0/16"}} {
		key, _ = routing.NormalizeIPAMAssignmentKey(entry.prefix)
		put(zone.RootZone, key, routing.RecordTypeIPAMAssignment, routing.IPAMAssignmentRecord{Version: 1, Prefix: entry.prefix, AssignedTo: entry.peer, Active: true})
		key, _ = routing.NormalizeRouteAnnouncementKey(entry.prefix)
		put(entry.peer, key, routing.RecordTypeRouteAnnouncement, routing.RouteAnnouncementRecord{Version: 1, Prefix: entry.prefix, Active: true})
	}
	// Local transport pin is signed exactly as for the peer fixtures.
	for _, k := range []string{ipsec.RecordKeyProfile, ipsec.RecordKeyTransportKey, ipsec.RecordKeyAddresses, ipsec.RecordKeyPorts} {
		r := f.view.State.Network.Zones["node-a.catofes."].Records[k]
		// The profile's identity is independent of its zone signing key.
		put(f.config.ManagedZone, k, r.Type, jsonValue(t, r.Value))
	}
	for _, path := range []zone.ZonePath{f.config.ManagedZone, "node-a.catofes.", "node-b.catofes."} {
		put(path, ipsec.OverlayIntentRecordKey("main"), ipsec.RecordTypeOverlayIntent, ipsec.OverlayIntentRecord{
			Version: 1, OverlayID: "main", Provider: ipsec.ProviderStrongSwan,
			PathKeys:      []string{ipsec.DefaultPathKey},
			TunnelAddress: ipsec.TunnelAddressSpec{Mode: ipsec.TunnelAddressDerivedLinkLocal, Family: ipsec.FamilyIPv6},
		})
	}
	socket, err := openPacketSockets(t.Context(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { socket.Close() })
	m := newMeshRuntime(t.Context(), f.config, nil, socket, nil, slog.New(slog.NewTextHandler(io.Discard, nil)), func() {})
	plan := planGateway(t.Context(), f.config, f.view, f.now, nil)
	m.update(plan)
	t.Cleanup(func() { m.close() })
	binding, err := localTransportAuthorization(f.config, f.view, f.now)
	if err != nil {
		t.Fatal(err)
	}
	for i, p := range m.ordered() {
		endpoint := netip.MustParseAddrPort("192.0.2.1:4500")
		p.tunnel.generation = socket.reserveTunnel(endpoint, endpoint)
		p.tunnel.phase, p.tunnel.plan, p.tunnel.session = 3, p.plan, &ike.Initiator{}
		p.tunnel.localAuthorization = binding
		p.tunnel.expiresAt, p.tunnel.ikeExpiresAt = f.now.Add(time.Hour), f.now.Add(time.Hour)
		p.tunnel.data.reset(p.tunnel.generation)
		child := dataplaneChild(uint32(500 + i))
		selectors := []ike.TrafficSelector{{StartAddr: netip.MustParseAddr("0.0.0.0"), EndAddr: netip.MustParseAddr("255.255.255.255"), EndPort: 65535}}
		child.LocalSelectors, child.RemoteSelectors = selectors, selectors
		if err := p.tunnel.data.install(p.tunnel.generation, p.plan, endpoint, child); err != nil {
			t.Fatal(err)
		}
		local, remote, err := leafLinkLocalAddresses(&p.config, f.view, p.plan, f.now)
		if err != nil {
			t.Fatal(err)
		}
		p.leaf.pipeline, err = newGatewayBabelPipeline(p.tunnel, &memoryPacketDevice{}, local, remote, [8]byte{1}, []netip.Addr{netip.MustParseAddr("10.9.0.1")})
		if err != nil {
			t.Fatal(err)
		}
		prefix := "10.1.0.0/16"
		if i == 1 {
			prefix = "10.2.0.0/16"
		}
		meshLearn(t, p, f.view, f.now, prefix, 10)
	}
	return m, f
}

func meshLearn(t *testing.T, p *meshPeer, view corestate.View, now time.Time, prefix string, metric uint16, source ...netip.Prefix) {
	t.Helper()
	pipeline := p.leaf.pipeline
	update := babel.Message{Type: babel.TLVUpdate, Prefix: netip.MustParsePrefix(prefix), RouterID: [8]byte{2}, NextHop: pipeline.peer, Seqno: 7, Metric: metric, Interval: 1600}
	if len(source) > 0 {
		update.SourcePrefix = source[0]
	}
	payload, err := babel.Encode([]babel.Message{{Type: babel.TLVHello, Seqno: 1, Interval: 400}, {Type: babel.TLVIHU, Address: pipeline.local, Metric: 100, Interval: 400}, update})
	if err != nil {
		t.Fatal(err)
	}
	packet, err := babel.BuildPacket(pipeline.peer, pipeline.local, payload)
	if err != nil {
		t.Fatal(err)
	}
	facts, ok := pipeline.prepare(&p.config, view, p.plan, now)
	if !ok {
		t.Fatal("signed peer policy rejected")
	}
	if _, err := pipeline.leaf.Receive(packet, now, facts.authorizeRoute); err != nil {
		t.Fatal(err)
	}
}

func jsonValue(t *testing.T, raw []byte) any {
	t.Helper()
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func TestMeshSelectsDestinationAndSurvivingRouteWithoutTransit(t *testing.T) {
	m, f := meshRouteFixture(t)
	packet := dataplanePacket(true)
	copy(packet[12:16], []byte{10, 9, 0, 1})
	copy(packet[16:20], []byte{10, 1, 2, 3})
	a := m.selectRoute(packet, f.view, f.now)
	if a.peer == nil || a.peer.config.Gateway.AllowedZones[0] != "node-a.catofes." {
		t.Fatal("first destination did not select its peer")
	}
	copy(packet[16:20], []byte{10, 2, 2, 3})
	b := m.selectRoute(packet, f.view, f.now)
	if b.peer == nil || b.peer == a.peer {
		t.Fatal("different destination did not use simultaneous second connection")
	}
	// A second valid path to the same prefix is immediately eligible after
	// the first neighbor fails; no gateway switch or adapter recreation occurs.
	meshLearn(t, b.peer, f.view, f.now, "10.1.0.0/16", 30)
	copy(packet[16:20], []byte{10, 1, 2, 3})
	if choice := m.selectRoute(packet, f.view, f.now); choice.peer == nil || choice.peer != a.peer {
		t.Fatal("lowest metric path not selected")
	}
	m.stopPeer(a.peer, "peer disconnected")
	if choice := m.selectRoute(packet, f.view, f.now); choice.peer == nil || choice.peer != b.peer {
		t.Fatal("healthy peer did not take over route")
	}
	// A packet sourced by another node is not local traffic, even with a route.
	copy(packet[12:16], []byte{10, 2, 2, 3})
	if m.selectRoute(packet, f.view, f.now).peer != nil {
		t.Fatal("transit/source-spoofing packet entered a peer tunnel")
	}
	facts, ok := b.peer.leaf.pipeline.prepare(&b.peer.config, f.view, b.peer.plan, f.now)
	if !ok {
		t.Fatal("second peer policy unavailable")
	}
	if b.peer.leaf.pipeline.authorize(facts, packet, false) {
		t.Fatal("inbound remote-to-remote transit accepted")
	}
	// No learned remote prefix is ever advertised on the other adjacency.
	for _, message := range b.peer.leaf.pipeline.leaf.Tick(f.now) {
		if message.Type == babel.TLVUpdate && message.Metric != babel.MetricInfinity && message.Prefix.String() != "10.9.0.1/32" {
			t.Fatal("learned route advertised as transit", message)
		}
	}
}

func TestMeshDecryptsBothPeersButNeverRelaysTheirTraffic(t *testing.T) {
	m, f := meshRouteFixture(t)
	f.view.State.ManagedZone = f.config.ManagedZone
	f.view.State.TrustedRootPublicKey = f.config.TrustedRootPublicKey
	store, err := corestate.RestoreStore(&corestate.CommitCandidate{Verified: f.view.State}, f.view.Revision, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	m.state = &State{common: store}
	m.policy = newMeshPolicyWorker(store)
	var inputs meshPolicyInputs
	for _, p := range m.ordered() {
		if _, pending := m.policy.project(p, f.view.Revision, f.now); !pending {
			t.Fatal("initial policy was not queued")
		}
		request := <-m.policy.requests
		m.policy.finish(meshPolicyResult{request: request, projection: inputs.project(request, f.view, f.now)}, f.view.Revision, f.now)
	}
	for i, p := range m.ordered() {
		device := p.leaf.pipeline.device.(*memoryPacketDevice)
		child := dataplaneChild(uint32(500 + i))
		sender, err := esp.NewSender(child.InitiatorSPI, child.Keys.ResponderToInitiator)
		if err != nil {
			t.Fatal(err)
		}
		packet := dataplanePacket(false)
		copy(packet[12:16], []byte{10, byte(i + 1), 2, 3})
		copy(packet[16:20], []byte{10, 9, 0, 1})
		wire, err := sender.Seal(packet)
		if err != nil {
			t.Fatal(err)
		}
		m.handleESP(tunnelDatagram{generation: p.tunnel.generation, peer: netip.MustParseAddrPort("192.0.2.1:4500"), packet: wire})
		if len(device.written) != 1 || !bytes.Equal(device.written[0], packet) {
			t.Fatal("independent peer could not deliver local traffic")
		}
		// The same authenticated/encrypted source cannot use Windows as a hop
		// to the other neighbor, even though that neighbor has a valid route.
		copy(packet[16:20], []byte{10, byte(2 - i), 2, 3})
		wire, err = sender.Seal(packet)
		if err != nil {
			t.Fatal(err)
		}
		m.handleESP(tunnelDatagram{generation: p.tunnel.generation, peer: netip.MustParseAddrPort("192.0.2.1:4500"), packet: wire})
		if len(device.written) != 1 || len(m.jobs) != 0 {
			t.Fatal("remote-to-remote transit reached host or another peer")
		}
	}
}

func TestMeshSlowPeerDNSDoesNotDiscardReachablePeer(t *testing.T) {
	f := newGatewayPatternFixture(t)
	f.addGateway(t, "node-b.catofes.")
	f.put(t, "node-b.catofes.", ipsec.RecordKeyAddresses, ipsec.RecordTypeAddresses, ipsec.AddressRecord{Version: 1, Addresses: []ipsec.AddressAdvertisement{{ID: "slow", Source: ipsec.SourceManualDNS, Host: "slow.example", Family: ipsec.FamilyIPv4}}})
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	plan := planGateway(ctx, f.config, f.view, f.now, blockingGatewayResolver{})
	if len(plan.Targets) != 1 || plan.Targets[0].Zone != "node-a.catofes." || plan.Rejected != "" {
		t.Fatal("one DNS failure suppressed a valid peer", plan)
	}
}

func TestMeshDefaultDiscoversAllVerifiedPeers(t *testing.T) {
	text := strings.Replace(validConfigYAML(), "  allowed_zones:\n    - gateway-a.catofes.\n", "", 1)
	config, err := ParseConfig(strings.NewReader(text))
	if err != nil || len(config.Gateway.AllowedZones) != 1 || config.Gateway.AllowedZones[0] != "*" {
		t.Fatal("default mesh selector", config, err)
	}
}

func TestMeshSelectionPrefersDestinationThenSourceThenCost(t *testing.T) {
	m, f := meshRouteFixture(t)
	a, b := m.peers[meshPath{"node-a.catofes.", ipsec.FamilyIPv4}], m.peers[meshPath{"node-b.catofes.", ipsec.FamilyIPv4}]
	meshLearn(t, b, f.view, f.now, "10.1.0.0/16", 300, netip.MustParsePrefix("10.9.0.0/24"))
	packet := dataplanePacket(true)
	copy(packet[12:16], []byte{10, 9, 0, 1})
	copy(packet[16:20], []byte{10, 1, 2, 3})
	if choice := m.selectRoute(packet, f.view, f.now); choice.peer == nil || choice.peer != b {
		t.Fatal("more-specific source should precede metric across peers")
	}
	key, _ := routing.NormalizeRouteAnnouncementKey("10.1.2.0/24")
	f.put(t, "node-a.catofes.", key, routing.RecordTypeRouteAnnouncement, routing.RouteAnnouncementRecord{Version: 1, Prefix: "10.1.2.0/24", Active: true})
	meshLearn(t, a, f.view, f.now, "10.1.2.0/24", 500)
	if choice := m.selectRoute(packet, f.view, f.now); choice.peer == nil || choice.peer != a {
		t.Fatal("more-specific destination should precede source and metric across peers")
	}
}

func TestMeshLocalOriginSequencesRemainCommonAcrossNeighbors(t *testing.T) {
	m, f := meshRouteFixture(t)
	a, b := m.peers[meshPath{"node-a.catofes.", ipsec.FamilyIPv4}], m.peers[meshPath{"node-b.catofes.", ipsec.FamilyIPv4}]
	for _, p := range []*meshPeer{a, b} {
		facts, ok := p.leaf.pipeline.prepare(&p.config, f.view, p.plan, f.now)
		if !ok {
			t.Fatal("no current peer")
		}
		if _, err := p.leaf.pipeline.leaf.SetLocal(facts.localOrigins); err != nil {
			t.Fatal(err)
		}
	}
	b.leaf.pipeline.leaf.SynchronizeSequence(42)
	m.noteSequence(b)
	for _, p := range []*meshPeer{a, b} {
		for _, message := range p.leaf.pipeline.leaf.Tick(f.now) {
			if message.Type == babel.TLVUpdate && message.Metric != babel.MetricInfinity {
				if message.Seqno != 42 || message.Prefix.String() != "10.9.0.1/32" {
					t.Fatal("local seqno diverged or remote origin escaped", message)
				}
			}
		}
	}
}

func meshHostRouteFixture(t *testing.T) (*meshRuntime, *gatewayPatternFixture, *meshPeer, leafDevicePacket) {
	t.Helper()
	m, f := meshRouteFixture(t)
	f.view.State.ManagedZone = f.config.ManagedZone
	f.view.State.TrustedRootPublicKey = f.config.TrustedRootPublicKey
	store, err := corestate.RestoreStore(&corestate.CommitCandidate{Verified: f.view.State}, f.view.Revision, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	m.state = &State{common: store}
	m.policy = newMeshPolicyWorker(store)
	var inputs meshPolicyInputs
	for _, p := range m.ordered() {
		if _, pending := m.policy.project(p, f.view.Revision, f.now); !pending {
			t.Fatal("initial policy was not queued")
		}
		request := <-m.policy.requests
		m.policy.finish(meshPolicyResult{request: request, projection: inputs.project(request, f.view, f.now)}, f.view.Revision, f.now)
	}
	m.device.activeGeneration.Store(1)
	packet := dataplanePacket(true)
	copy(packet[12:16], []byte{10, 9, 0, 1})
	copy(packet[16:20], []byte{10, 1, 2, 3})
	return m, f, m.peers[meshPath{"node-a.catofes.", ipsec.FamilyIPv4}], leafDevicePacket{generation: 1, packet: packet}
}

func TestMeshHostAdmissionTracksInstalledBabelRetraction(t *testing.T) {
	m, f, p, event := meshHostRouteFixture(t)
	p.policy.current.authorize = func(sadr.Route) bool {
		t.Error("host admission reran signed authorization on the installed route")
		return false
	}
	completion, ok := m.prepareHost(event)
	if !ok || m.currentHost(&completion, time.Now()) != p {
		t.Fatal("initial route did not admit a packet")
	}
	meshLearn(t, p, f.view, time.Now(), "10.1.0.0/16", babel.MetricInfinity)
	if _, ok := m.prepareHost(event); ok {
		t.Fatal("next host packet used a retracted route")
	}
	if m.currentHost(&completion, time.Now()) != p {
		t.Fatal("Babel retraction canceled a packet already admitted in this turn")
	}
	if m.currentHost(&completion, p.tunnel.expiresAt) != nil {
		t.Fatal("an admitted packet could submit after the hard CHILD expiry")
	}
	p.tunnel.data.retire(completion.job.sa.spi)
	if m.currentHost(&completion, time.Now()) != nil {
		t.Fatal("an admitted packet could submit on a retired CHILD")
	}
}

func TestMeshHostAdmissionRevalidatesOnSignedPolicyInstallation(t *testing.T) {
	m, f, p, event := meshHostRouteFixture(t)
	if _, ok := m.prepareHost(event); !ok {
		t.Fatal("initial signed route did not admit a packet")
	}
	key, _ := routing.NormalizeIPAMAssignmentKey("10.1.0.0/16")
	records := f.view.State.Network.Zones[zone.RootZone].Records
	previous := records[key]
	value, err := json.Marshal(routing.IPAMAssignmentRecord{Version: 1, Prefix: "10.1.0.0/16", AssignedTo: "node-a.catofes.", Active: false})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	withdrawal := &zone.Record{Zone: zone.RootZone, Key: key, Type: routing.RecordTypeIPAMAssignment, Value: value,
		Version: previous.Version + 1, PrevHash: photoncrypto.RecordHash(previous), Timestamp: now.Unix()}
	if err := photoncrypto.SignRecord(withdrawal, f.private); err != nil {
		t.Fatal(err)
	}
	records[key] = withdrawal
	snapshot, err := corestate.Snapshot(f.view.State.Network, zone.RootZone)
	if err != nil {
		t.Fatal(err)
	}
	store := m.state.Store()
	limits := corestate.DefaultSyncLimits()
	result, err := store.ApplyRemoteBatch(t.Context(), "mesh-signed-withdrawal",
		[]corestate.RemoteSnapshot{{Snapshot: snapshot, Limits: limits}}, now)
	if err != nil || !result.Committed || len(result.Outcomes) != 1 || result.Outcomes[0].Err != nil {
		t.Fatalf("signed withdrawal did not publish: %+v, %v", result, err)
	}
	view := store.ReadView()
	now = time.Now()
	if _, pending := m.policy.project(p, view.Revision, now); !pending {
		t.Fatal("updated signed policy was not queued")
	}
	request := <-m.policy.requests
	var inputs meshPolicyInputs
	m.policy.finish(meshPolicyResult{request: request, projection: inputs.project(request, view, now)}, view.Revision, now)
	if p.policy.current == nil || p.policy.current.request.revision != view.Revision {
		t.Fatal("updated signed policy was not installed")
	}
	if _, ok := m.prepareHost(event); ok {
		t.Fatal("next host packet used a route revoked by the installed signed policy")
	}
}
