package photonwindows

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/photonclient/babel"
	"github.com/HiggsNet/photon/internal/photonclient/esp"
	"github.com/HiggsNet/photon/internal/photonclient/ike"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/routing"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

type memoryPacketDevice struct {
	read    chan []byte
	written [][]byte
}

func (d *memoryPacketDevice) Write(packet []byte) error {
	d.written = append(d.written, bytes.Clone(packet))
	return nil
}
func (d *memoryPacketDevice) Read(ctx context.Context) ([]byte, error) {
	select {
	case packet := <-d.read:
		return packet, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

type pipelineFixture struct {
	config   *Config
	view     corestate.View
	now      time.Time
	put      func(zone.ZonePath, string, string, any)
	plan     GatewayPlan
	p        *gatewayBabelPipeline
	device   *memoryPacketDevice
	peer     *net.UDPConn
	child    ike.ChildResult
	sender   *esp.Sender
	receiver *esp.Receiver
	remoteID [8]byte
}

func newPipelineFixture(t testing.TB) *pipelineFixture {
	t.Helper()
	config, view, now, put := gatewayPlanFixture(t)
	// A real local unicast address keeps the production rejection of loopback
	// gateway contacts intact; both UDP endpoints still belong to this test.
	var address netip.Addr
	interfaces, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range interfaces {
		prefix, err := netip.ParsePrefix(a.String())
		if err == nil && prefix.Addr().Is4() && prefix.Addr().IsGlobalUnicast() {
			address = prefix.Addr()
			break
		}
	}
	if !address.IsValid() {
		t.Skip("real UDP pipeline needs a local non-loopback IPv4 address")
	}
	peer, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(address, 0)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { peer.Close() })
	socket, err := openPacketSockets(t.Context(), netip.AddrPortFrom(address, 0).String())
	if err != nil {
		t.Fatal(err)
	}
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		buffer := make([]byte, 1201)
		for {
			if _, _, err := socket.ReadDatagram(buffer); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { socket.Close(); <-readDone })
	endpoint := peer.LocalAddr().(*net.UDPAddr).AddrPort()
	gateway := zone.ZonePath("node-a.catofes.")
	config.ManagedZone = "catofes."
	for key, record := range view.State.Network.Zones[gateway].Records {
		if len(key) < 6 || key[:6] != "ipsec/" {
			continue
		}
		var value any
		if err := json.Unmarshal(record.Value, &value); err != nil {
			t.Fatal(err)
		}
		put(config.ManagedZone, key, record.Type, value)
	}
	put(gateway, ipsec.RecordKeyPorts, ipsec.RecordTypePorts, ipsec.PortRecord{Version: 1, Mode: ipsec.PortModeFixed, Current: &ipsec.PortSelection{Generation: 1, IKE: ipsec.PortBinding{Advertised: endpoint.Port()}, NATT: ipsec.PortBinding{Advertised: endpoint.Port()}}})
	prefix := "10.9.0.1/32"
	key, _ := routing.NormalizeIPAMAssignmentKey(prefix)
	put(zone.RootZone, key, routing.RecordTypeIPAMAssignment, routing.IPAMAssignmentRecord{Version: 1, Prefix: prefix, AssignedTo: config.ManagedZone, Active: true})
	key, _ = routing.NormalizeRouteAnnouncementKey(prefix)
	put(config.ManagedZone, key, routing.RecordTypeRouteAnnouncement, routing.RouteAnnouncementRecord{Version: 1, Prefix: prefix, Active: true})
	localID, remoteID := [8]byte{1}, [8]byte{2}
	for path, id := range map[zone.ZonePath][8]byte{config.ManagedZone: localID, gateway: remoteID} {
		put(path, routing.RecordKeyBabelIdentity, routing.RecordTypeBabelIdentity, routing.BabelIdentityRecord{Version: 1, RouterIDs: []string{hex.EncodeToString(id[:])}, ExpiresAt: now.Add(time.Hour).Unix()})
	}
	plan := planGateway(t.Context(), config, view, now, gatewayResolvedHosts{"gateway.example": {{IP: net.IP(address.AsSlice())}}})
	if plan.Selected == nil {
		t.Fatal("verified gateway fixture rejected", plan)
	}
	binding, err := localTransportAuthorization(config, view, now)
	if err != nil {
		t.Fatal(err)
	}
	data := newGatewayDataplane(t.Context())
	t.Cleanup(data.close)
	generation := socket.SelectTunnel(endpoint, endpoint)
	data.reset(generation)
	child := dataplaneChild(512)
	selectors := []ike.TrafficSelector{{StartAddr: netip.MustParseAddr("0.0.0.0"), EndAddr: netip.MustParseAddr("255.255.255.255"), EndPort: 65535}, {StartAddr: netip.MustParseAddr("::"), EndAddr: netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), EndPort: 65535}}
	child.LocalSelectors, child.RemoteSelectors = selectors, selectors
	if err := data.install(generation, plan, endpoint, child); err != nil {
		t.Fatal(err)
	}
	tunnel := &gatewayTunnel{phase: 3, session: &ike.Initiator{}, socket: socket, data: data, plan: plan, generation: generation, localAuthorization: binding, expiresAt: now.Add(time.Hour), ikeExpiresAt: now.Add(time.Hour)}
	device := &memoryPacketDevice{read: make(chan []byte, 64)}
	p, err := newGatewayBabelPipeline(tunnel, device, netip.MustParseAddr("fe80::1"), netip.MustParseAddr("fe80::2"), localID, []netip.Addr{netip.MustParseAddr("10.9.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	sender, _ := esp.NewSender(child.InitiatorSPI, child.Keys.ResponderToInitiator)
	receiver, _ := esp.NewReceiver(child.ResponderSPI, child.Keys.InitiatorToResponder)
	return &pipelineFixture{config, view, now, put, plan, p, device, peer, child, sender, receiver, remoteID}
}

func (f *pipelineFixture) accept(t testing.TB, c dataplaneCompletion) bool {
	t.Helper()
	ok, err := f.p.Accept(f.config, f.view, f.plan, f.now, c)
	if err != nil {
		t.Fatal(err)
	}
	return ok
}
func (f *pipelineFixture) inbound(t testing.TB, packet []byte) bool {
	t.Helper()
	return f.accept(t, f.inboundCompletion(t, packet))
}
func (f *pipelineFixture) inboundCompletion(t testing.TB, packet []byte) dataplaneCompletion {
	t.Helper()
	wire, err := f.sender.Seal(packet)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.peer.WriteToUDP(wire, f.p.tunnel.socket.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	select {
	case received := <-f.p.tunnel.socket.espPackets:
		if !f.p.tunnel.data.submitInbound(received.generation, f.plan, received.peer, received.packet) {
			t.Fatal("ESP ingress rejected")
		}
	case <-time.After(time.Second):
		t.Fatal("shared UDP ESP ingress timeout")
	}
	for {
		c := dataplaneResult(t, f.p.tunnel.data)
		if !c.job.outbound {
			return c
		}
		f.accept(t, c)
	}
}
func (f *pipelineFixture) learn(t testing.TB) {
	t.Helper()
	payload, err := babel.Encode([]babel.Message{{Type: babel.TLVHello, Seqno: 1, Interval: 400}, {Type: babel.TLVIHU, Address: f.p.local, Metric: 100, Interval: 400}, {Type: babel.TLVUpdate, Prefix: netip.MustParsePrefix("10.1.2.0/24"), RouterID: f.remoteID, NextHop: f.p.peer, Seqno: 7, Metric: 10, Interval: 1600}})
	if err != nil {
		t.Fatal(err)
	}
	packet, err := babel.BuildPacket(f.p.peer, f.p.local, payload)
	if err != nil {
		t.Fatal(err)
	}
	if !f.inbound(t, packet) {
		t.Fatal("authenticated Babel control rejected")
	}
	if len(f.device.written) != 0 {
		t.Fatal("Babel leaked to host device")
	}
}
func (f *pipelineFixture) packet(outbound bool) []byte {
	packet := dataplanePacket(true)
	copy(packet[12:16], []byte{10, 9, 0, 1})
	copy(packet[16:20], []byte{10, 1, 2, 3})
	if !outbound {
		copy(packet[12:16], []byte{10, 1, 2, 3})
		copy(packet[16:20], []byte{10, 9, 0, 1})
	}
	return packet
}
func (f *pipelineFixture) submitFromDevice(t testing.TB, packet []byte) bool {
	t.Helper()
	f.device.read <- bytes.Clone(packet)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	read, err := f.device.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return f.p.SubmitPacket(f.config, f.view, f.plan, f.now, read)
}
func (f *pipelineFixture) businessCompletion(t testing.TB) dataplaneCompletion {
	t.Helper()
	for {
		c := dataplaneResult(t, f.p.tunnel.data)
		if _, _, ok := businessEndpoints(c.job.packet); ok && c.job.outbound {
			return c
		}
		f.accept(t, c)
	}
}
func (f *pipelineFixture) receiveBusiness(t testing.TB) []byte {
	t.Helper()
	if err := f.peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	for {
		buffer := make([]byte, 65536)
		n, from, err := f.peer.ReadFromUDP(buffer)
		if err != nil {
			t.Fatal(err)
		}
		if from.String() != f.p.tunnel.socket.LocalAddr().String() {
			t.Fatal("ESP used another endpoint")
		}
		plain, err := f.receiver.Open(buffer[:n])
		if err != nil {
			t.Fatal(err)
		}
		if _, _, ok := businessEndpoints(plain); ok {
			return plain
		}
	}
}

func TestBabelPipelineMemoryDeviceESPSharedUDP(t *testing.T) {
	f := newPipelineFixture(t)
	if f.submitFromDevice(t, f.packet(true)) {
		t.Fatal("missing route accepted")
	}
	f.learn(t)
	if !f.submitFromDevice(t, f.packet(true)) {
		t.Fatal("authorized memory read refused")
	}
	if !f.accept(t, f.businessCompletion(t)) {
		t.Fatal("current outbound completion refused")
	}
	if got := f.receiveBusiness(t); !bytes.Equal(got, f.packet(true)) {
		t.Fatal("device to UDP payload changed")
	}
	if !f.inbound(t, f.packet(false)) || len(f.device.written) != 1 || !bytes.Equal(f.device.written[0], f.packet(false)) {
		t.Fatal("UDP to device delivery failed")
	}
	forged := f.packet(true)
	forged[15]++
	if f.submitFromDevice(t, forged) {
		t.Fatal("foreign local source accepted")
	}
	transit := f.packet(false)
	transit[19]++
	if f.inbound(t, transit) {
		t.Fatal("remote transit accepted")
	}
	foreign := f.packet(false)
	foreign[12] = 11
	if f.inbound(t, foreign) {
		t.Fatal("remote source without reverse authorized route accepted")
	}
	payload, _ := babel.Encode([]babel.Message{{Type: babel.TLVHello, Seqno: 2, Interval: 400}})
	control, _ := babel.BuildPacket(f.p.local, f.p.peer, payload)
	if f.submitFromDevice(t, control) {
		t.Fatal("host injected Babel accepted")
	}
	control, _ = babel.BuildPacket(netip.MustParseAddr("fe80::3"), f.p.local, payload)
	if f.inbound(t, control) {
		t.Fatal("foreign link-local peer accepted")
	}
}

func TestBabelPipelineCompletionRevalidation(t *testing.T) {
	for _, direction := range []string{"outbound", "inbound"} {
		for _, scenario := range []string{"route-withdraw", "local-withdraw", "identity-expiry", "child-expiry", "generation", "gateway-revoke", "local-id-withdraw"} {
			t.Run(direction+"/"+scenario, func(t *testing.T) {
				f := newPipelineFixture(t)
				f.learn(t)
				var completion dataplaneCompletion
				if direction == "outbound" {
					if !f.submitFromDevice(t, f.packet(true)) {
						t.Fatal("submit failed")
					}
					completion = f.businessCompletion(t)
				} else {
					completion = f.inboundCompletion(t, f.packet(false))
				}
				switch scenario {
				case "route-withdraw":
					key, _ := routing.NormalizeRouteAnnouncementKey("10.1.2.0/24")
					f.put("node-a.catofes.", key, routing.RecordTypeRouteAnnouncement, routing.RouteAnnouncementRecord{Version: 1, Prefix: "10.1.2.0/24", Active: false})
					f.view.Revision++
				case "local-withdraw":
					key, _ := routing.NormalizeRouteAnnouncementKey("10.9.0.1/32")
					f.put(f.config.ManagedZone, key, routing.RecordTypeRouteAnnouncement, routing.RouteAnnouncementRecord{Version: 1, Prefix: "10.9.0.1/32", Active: false})
					f.view.Revision++
				case "identity-expiry":
					f.put("node-a.catofes.", routing.RecordKeyBabelIdentity, routing.RecordTypeBabelIdentity, routing.BabelIdentityRecord{Version: 1, RouterIDs: []string{hex.EncodeToString(f.remoteID[:])}, ExpiresAt: f.now.Add(time.Second).Unix()})
					f.now = f.now.Add(time.Second)
				case "child-expiry":
					f.p.tunnel.expiresAt = f.now
				case "generation":
					f.p.tunnel.generation++
				case "gateway-revoke":
					f.view.State.Network.Zones["node-a.catofes."].Records[ipsec.RecordKeyTransportKey].Signature[0] ^= 1
				case "local-id-withdraw":
					f.put(f.config.ManagedZone, routing.RecordKeyBabelIdentity, routing.RecordTypeBabelIdentity, routing.BabelIdentityRecord{Version: 1, ExpiresAt: f.now.Add(time.Hour).Unix()})
				}
				if f.accept(t, completion) || len(f.device.written) != 0 {
					t.Fatal("revoked or expired completion delivered")
				}
			})
		}
	}
}

func TestBabelPipelineRekeyAndBoundedQueue(t *testing.T) {
	f := newPipelineFixture(t)
	f.learn(t)
	if !f.submitFromDevice(t, f.packet(true)) {
		t.Fatal("submit failed")
	}
	old := f.businessCompletion(t)
	next := dataplaneChild(513)
	next.LocalSelectors, next.RemoteSelectors = f.child.LocalSelectors, f.child.RemoteSelectors
	if err := f.p.tunnel.data.install(f.p.generation, f.plan, f.peer.LocalAddr().(*net.UDPAddr).AddrPort(), next); err != nil {
		t.Fatal(err)
	}
	if err := f.p.tunnel.data.activate(next.InitiatorSPI); err != nil {
		t.Fatal(err)
	}
	if f.accept(t, old) {
		t.Fatal("old outbound accepted after rekey")
	}
	if !f.submitFromDevice(t, f.packet(true)) {
		t.Fatal("rekey lost learned route")
	}
	if !f.accept(t, f.businessCompletion(t)) {
		t.Fatal("rekey completion refused")
	}
	// Both authenticated inbound CHILDs remain usable during the overlap.
	if !f.inbound(t, f.packet(false)) {
		t.Fatal("old inbound overlap rejected")
	}
	f.sender, _ = esp.NewSender(next.InitiatorSPI, next.Keys.ResponderToInitiator)
	if !f.inbound(t, f.packet(false)) {
		t.Fatal("new inbound overlap rejected")
	}
	dropped := false
	for range 256 {
		if !f.submitFromDevice(t, f.packet(true)) {
			dropped = true
		}
	}
	if !dropped {
		t.Fatal("unconsumed crypto queue did not apply backpressure")
	}
	f.p.tunnel.data.reset(f.p.generation + 1)
	// Failed gates invalidate learned candidates before any later reattachment.
	if f.p.SubmitPacket(f.config, f.view, f.plan, f.now, f.packet(true)) || f.p.leaf != nil {
		t.Fatal("generation revocation retained leaf")
	}
}

func TestBabelPipelineBatchesAllLocalOrigins(t *testing.T) {
	f := newPipelineFixture(t)
	old, _ := routing.NormalizeIPAMAssignmentKey("10.9.0.1/32")
	delete(f.view.State.Network.Zones[zone.RootZone].Records, old)
	key, _ := routing.NormalizeIPAMAssignmentKey("10.9.0.0/24")
	f.put(zone.RootZone, key, routing.RecordTypeIPAMAssignment, routing.IPAMAssignmentRecord{Version: 1, Prefix: "10.9.0.0/24", AssignedTo: f.config.ManagedZone, Active: true})
	const count = 80 // exceeds the crypto queue capacity if each origin is a packet
	addresses := make([]netip.Addr, 0, count)
	for i := 1; i <= count; i++ {
		address := netip.AddrFrom4([4]byte{10, 9, 0, byte(i)})
		addresses = append(addresses, address)
		prefix := netip.PrefixFrom(address, 32).String()
		key, _ := routing.NormalizeRouteAnnouncementKey(prefix)
		f.put(f.config.ManagedZone, key, routing.RecordTypeRouteAnnouncement, routing.RouteAnnouncementRecord{Version: 1, Prefix: prefix, Active: true})
	}
	p, err := newGatewayBabelPipeline(f.p.tunnel, f.device, f.p.local, f.p.peer, f.p.routerID, addresses)
	if err != nil {
		t.Fatal(err)
	}
	f.p = p
	f.p.Tick(f.config, f.view, f.plan, f.now)
	seen := map[netip.Prefix]bool{}
	for len(seen) < count {
		completion := dataplaneResult(t, f.p.tunnel.data)
		if !f.accept(t, completion) {
			t.Fatal("current control completion rejected")
		}
		if err := f.peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		wire := make([]byte, 4096)
		n, _, err := f.peer.ReadFromUDP(wire)
		if err != nil {
			t.Fatal(err)
		}
		packet, err := f.receiver.Open(wire[:n])
		if err != nil {
			t.Fatal(err)
		}
		source, payload, err := babel.ParsePacket(packet, f.p.peer)
		if err != nil {
			t.Fatal(err)
		}
		if len(payload) > 1200 {
			t.Fatal("Babel payload exceeds batch budget")
		}
		messages, err := babel.Decode(payload, source)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range messages {
			if m.Type == babel.TLVUpdate && m.Metric == 0 {
				if m.RouterID != f.p.routerID {
					t.Fatal("foreign origin advertised")
				}
				seen[m.Prefix] = true
			}
		}
	}
}
