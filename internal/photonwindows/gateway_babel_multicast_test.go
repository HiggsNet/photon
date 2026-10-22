package photonwindows

import (
	"net/netip"
	"testing"

	"github.com/HiggsNet/photon/internal/photonclient/babel"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

// BIRD sends periodic control traffic to ff02::1:6 even when the leaf sends
// unicast replies. Exercise the original multicast IPv6 frame through real
// ESP completion authorization; never rewrite its destination to local unicast.
func TestBabelPipelineAuthenticatedMulticastControl(t *testing.T) {
	f := newPipelineFixture(t)
	payload, err := babel.Encode([]babel.Message{
		{Type: babel.TLVHello, Seqno: 1, Interval: 400},
		{Type: babel.TLVIHU, Address: f.p.local, Metric: 100, Interval: 400},
		{Type: babel.TLVUpdate, Prefix: netip.MustParsePrefix("10.1.2.0/24"), RouterID: f.remoteID, NextHop: f.p.peer, Seqno: 1, Metric: 10, Interval: 1600},
	})
	if err != nil {
		t.Fatal(err)
	}
	packet, err := babel.BuildPacket(f.p.peer, babel.Multicast, payload)
	if err != nil {
		t.Fatal(err)
	}
	if !f.inbound(t, packet) {
		t.Fatal("authenticated BIRD multicast control refused")
	}
	if len(f.device.written) != 0 {
		t.Fatal("multicast Babel reached host stack")
	}
	if got := f.p.leaf.Candidates(f.now, currentBabelRouteAuthorizer(f.config, f.view, f.now)); len(got) != 1 {
		t.Fatal("multicast update did not learn route", got)
	}
	if !f.submitFromDevice(t, f.packet(true)) || !f.accept(t, f.businessCompletion(t)) {
		t.Fatal("multicast-learned route did not permit authorized business traffic")
	}
	f.receiveBusiness(t)
	// Control is accepted only from the pinned peer and current SA, not from
	// another link-local sender or the local host's packet-device injection.
	foreign, err := babel.BuildPacket(netip.MustParseAddr("fe80::3"), babel.Multicast, payload)
	if err != nil {
		t.Fatal(err)
	}
	if f.inbound(t, foreign) {
		t.Fatal("foreign multicast source accepted")
	}
	host, err := babel.BuildPacket(f.p.local, babel.Multicast, payload)
	if err != nil {
		t.Fatal(err)
	}
	if f.submitFromDevice(t, host) {
		t.Fatal("host multicast control injection accepted")
	}
	completion := f.inboundCompletion(t, packet)
	f.view.State.Network.Zones["node-a.catofes."].Records[ipsec.RecordKeyTransportKey].Signature[0] ^= 1
	if f.accept(t, completion) {
		t.Fatal("revoked SA multicast completion accepted")
	}
}
