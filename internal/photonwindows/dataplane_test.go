package photonwindows

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/photonclient/esp"
	"github.com/HiggsNet/photon/internal/photonclient/ike"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func dataplaneFixture(t *testing.T) (*gatewayDataplane, GatewayPlan, netip.AddrPort, ike.ChildResult) {
	t.Helper()
	d := newGatewayDataplane(context.Background())
	t.Cleanup(d.close)
	d.reset(10)
	plan := GatewayPlan{Selected: &GatewaySelection{Zone: "gateway.test.", Identity: "gateway.test.", PublicKey: bytes.Repeat([]byte{1}, 32), Fingerprint: "pin", Contact: ipsec.ContactPoint{Address: "192.0.2.1", IKEPort: 500, NATTPort: 4500}}}
	endpoint := netip.MustParseAddrPort("192.0.2.1:4500")
	child := dataplaneChild(256)
	if err := d.install(10, plan, endpoint, child); err != nil {
		t.Fatal(err)
	}
	return d, plan, endpoint, child
}

func dataplaneChild(spi uint32) ike.ChildResult {
	key := func(n uint32) []byte {
		b := bytes.Repeat([]byte{byte(n)}, 20)
		binary.BigEndian.PutUint32(b, n)
		return b
	}
	selector := func(address string) []ike.TrafficSelector {
		a := netip.MustParseAddr(address)
		return []ike.TrafficSelector{{StartAddr: a, EndAddr: a, EndPort: 65535}}
	}
	return ike.ChildResult{InitiatorSPI: spi, ResponderSPI: spi + 1000, Keys: ike.ChildKeys{InitiatorToResponder: key(spi * 2), ResponderToInitiator: key(spi*2 + 1)}, LocalSelectors: selector("10.0.0.1"), RemoteSelectors: selector("10.0.0.2")}
}

func dataplanePacket(outbound bool) []byte {
	p := make([]byte, 28)
	p[0], p[8], p[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	copy(p[12:16], []byte{10, 0, 0, 1})
	copy(p[16:20], []byte{10, 0, 0, 2})
	if !outbound {
		p[15], p[19] = 2, 1
	}
	binary.BigEndian.PutUint16(p[20:22], 1234)
	binary.BigEndian.PutUint16(p[22:24], 443)
	binary.BigEndian.PutUint16(p[24:26], 8)
	return p
}

func dataplaneResult(t testing.TB, d *gatewayDataplane) dataplaneCompletion {
	t.Helper()
	select {
	case result := <-d.completed:
		return result
	case <-time.After(3 * time.Second):
		t.Fatal("crypto completion did not arrive")
		return dataplaneCompletion{}
	}
}

func dataplaneAllow([]byte, bool) bool { return true }

func TestDataplaneBidirectionalAndDefaultDeny(t *testing.T) {
	d, plan, endpoint, child := dataplaneFixture(t)
	inner := dataplanePacket(true)
	if d.submitOutbound(10, plan, inner, nil) {
		t.Fatal("missing route policy accepted outbound")
	}
	if !d.submitOutbound(10, plan, inner, dataplaneAllow) {
		t.Fatal("authorized outbound refused")
	}
	out := dataplaneResult(t, d)
	if packet, _, _, accepted := d.accept(out, plan, nil); accepted || packet != nil {
		t.Fatal("missing route policy accepted completion")
	}
	wire, peer, outbound, accepted := d.accept(out, plan, dataplaneAllow)
	if !accepted || !outbound || peer != endpoint {
		t.Fatal("outbound completion refused")
	}
	receiver, _ := esp.NewReceiver(child.ResponderSPI, child.Keys.InitiatorToResponder)
	decrypted, err := receiver.Open(wire)
	if err != nil || !bytes.Equal(decrypted, inner) {
		t.Fatalf("outbound ESP mismatch: %v", err)
	}
	sender, _ := esp.NewSender(child.InitiatorSPI, child.Keys.ResponderToInitiator)
	wire, _ = sender.Seal(dataplanePacket(false))
	if d.submitInbound(10, plan, netip.MustParseAddrPort("192.0.2.2:4500"), wire) {
		t.Fatal("wrong endpoint accepted")
	}
	if !d.submitInbound(10, plan, endpoint, wire) {
		t.Fatal("inbound refused")
	}
	result := dataplaneResult(t, d)
	if packet, _, _, accepted := d.accept(result, plan, nil); accepted || packet != nil {
		t.Fatal("inbound plaintext escaped absent B4 verdict")
	}
	packet, _, outbound, accepted := d.accept(result, plan, dataplaneAllow)
	if !accepted || outbound || !bytes.Equal(packet, dataplanePacket(false)) {
		t.Fatal("authenticated inbound mismatch")
	}
	if !d.submitInbound(10, plan, endpoint, wire) {
		t.Fatal("replay should be examined by bounded crypto")
	}
	if _, _, _, accepted := d.accept(dataplaneResult(t, d), plan, dataplaneAllow); accepted {
		t.Fatal("replay accepted")
	}
}

func TestDataplaneRevocationAndGeneration(t *testing.T) {
	for _, change := range []string{"generation", "rejected", "pin", "endpoint", "retired", "route"} {
		t.Run(change, func(t *testing.T) {
			d, plan, _, child := dataplaneFixture(t)
			if !d.submitOutbound(10, plan, dataplanePacket(true), dataplaneAllow) {
				t.Fatal("submit failed")
			}
			result := dataplaneResult(t, d)
			authorize := dataplaneAllow
			switch change {
			case "generation":
				d.reset(11)
			case "rejected":
				plan.Rejected = "revoked"
			case "pin":
				plan.Selected.PublicKey[0] ^= 1
			case "endpoint":
				plan.Selected.Contact.Address = "192.0.2.2"
			case "retired":
				d.retire(child.InitiatorSPI)
			case "route":
				authorize = func([]byte, bool) bool { return false }
			}
			if packet, _, _, accepted := d.accept(result, plan, authorize); accepted || packet != nil {
				t.Fatal("old completion survived current revocation")
			}
		})
	}
}

func TestDataplaneOverlapAndBoundedShutdown(t *testing.T) {
	d, plan, endpoint, first := dataplaneFixture(t)
	if !d.submitOutbound(10, plan, dataplanePacket(true), dataplaneAllow) {
		t.Fatal("submit failed")
	}
	oldOutbound := dataplaneResult(t, d)
	second := dataplaneChild(257)
	bad := second
	bad.Keys = first.Keys
	if err := d.install(10, plan, endpoint, bad); err == nil {
		t.Fatal("key reuse accepted")
	}
	if err := d.install(10, plan, endpoint, second); err != nil {
		t.Fatal(err)
	}
	if d.active.spi != first.InitiatorSPI {
		t.Fatal("rekey candidate prematurely replaced active outbound")
	}
	if err := d.activate(second.InitiatorSPI); err != nil {
		t.Fatal(err)
	}
	if _, _, _, ok := d.accept(oldOutbound, plan, dataplaneAllow); ok {
		t.Fatal("old outbound completed after active replacement")
	}
	if err := d.install(10, plan, endpoint, dataplaneChild(258)); err != nil {
		t.Fatal(err)
	}
	if err := d.install(10, plan, endpoint, dataplaneChild(259)); err == nil {
		t.Fatal("unbounded SA overlap")
	}
	for _, child := range []ike.ChildResult{first, second} {
		sender, _ := esp.NewSender(child.InitiatorSPI, child.Keys.ResponderToInitiator)
		wire, _ := sender.Seal(dataplanePacket(false))
		if !d.submitInbound(10, plan, endpoint, wire) {
			t.Fatal("overlapping inbound SPI refused")
		}
		if _, _, _, ok := d.accept(dataplaneResult(t, d), plan, dataplaneAllow); !ok {
			t.Fatal("overlapping inbound rejected")
		}
	}
	d.retire(first.InitiatorSPI)
	if err := d.install(10, plan, endpoint, dataplaneChild(259)); err != nil {
		t.Fatal(err)
	}
	dropped := false
	for range 512 {
		if !d.submitOutbound(10, plan, dataplanePacket(true), dataplaneAllow) {
			dropped = true
		}
	}
	if !dropped {
		t.Fatal("unconsumed crypto pipeline did not apply bounded backpressure")
	}
	closed := make(chan struct{})
	go func() { d.close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("full completion queue blocked shutdown")
	}
}

func TestDataplaneNegotiatedSelectors(t *testing.T) {
	d, _, _, _ := dataplaneFixture(t)
	sa := d.active
	packet := dataplanePacket(true)
	if !dataplaneSelectors(sa, packet, true) {
		t.Fatal("valid address selectors refused")
	}
	packet[15] = 3
	if dataplaneSelectors(sa, packet, true) {
		t.Fatal("wrong source accepted")
	}
	packet[15] = 1
	sa.remote[0].Protocol, sa.remote[0].StartPort, sa.remote[0].EndPort = 17, 443, 443
	if !dataplaneSelectors(sa, packet, true) {
		t.Fatal("UDP port selector refused")
	}
	packet[23]++
	if dataplaneSelectors(sa, packet, true) {
		t.Fatal("wrong destination port accepted")
	}
	packet[23]--
	packet[6] = 0x20
	if dataplaneSelectors(sa, packet, true) {
		t.Fatal("fragment accepted under restricted ports")
	}
	packet[6] = 0
	packet[2] = 1
	if dataplaneSelectors(sa, packet, true) {
		t.Fatal("bad packet length accepted")
	}
}
