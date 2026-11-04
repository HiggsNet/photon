package photonwindows

import (
	"bytes"
	"testing"
)

func TestMeshIKEIgnoresResponseFromCanceledExchange(t *testing.T) {
	p := &meshPeer{tunnel: &gatewayTunnel{phase: 1, generation: 2}}
	currentKey := bytes.Repeat([]byte{3}, 64)
	p.tunnel.private = currentKey
	previousKey := bytes.Repeat([]byte{7}, 64)
	previous := &meshIKEResponse{peer: p, phase: 1, input: ikeHandshakeInput{private: previousKey}}
	p.responding = &meshIKEResponse{peer: p, phase: 1}

	// A late response must be rejected before accessing the current Store or
	// touching the new exchange, even if both exchanges are in the same phase.
	m := &meshRuntime{}
	if err := m.finishIKEResponse(meshIKEResponseResult{request: previous}); err != nil {
		t.Fatal(err)
	}
	if p.tunnel.generation != 2 || p.responding == nil || !bytes.Equal(currentKey, bytes.Repeat([]byte{3}, 64)) {
		t.Fatal("late response affected the current exchange")
	}
	if !bytes.Equal(previousKey, make([]byte, 64)) {
		t.Fatal("discarded response retained its private key")
	}
}

func TestMeshESPContinuesWithLeasedIKE(t *testing.T) {
	m, f := meshRouteFixture(t)
	packet := dataplanePacket(true)
	copy(packet[12:16], []byte{10, 9, 0, 1})
	copy(packet[16:20], []byte{10, 1, 2, 3})
	choice := m.selectRoute(packet, f.view, f.now)
	if choice.peer == nil {
		t.Fatal("fixture has no usable route")
	}
	p := choice.peer
	m.scheduleIKETimer(p, ikeTimerRequest{kind: ikeTimerRekey, session: p.tunnel.session}, f.now)
	if p.responding == nil || !p.tunnel.ikeLeased {
		t.Fatal("fixture failed to leave IKE work pending")
	}
	choice = m.selectRoute(packet, f.view, f.now)
	if choice.peer == nil || choice.peer != p {
		t.Fatal("an in-flight IKE request blocked the installed route")
	}
	data := p.tunnel.data
	result, ok := data.processOwnedOutbound(p.tunnel.generation, choice.facts.plan, packet,
		func(packet []byte, outbound bool) bool {
			return p.leaf.pipeline.authorize(&choice.facts, packet, outbound)
		}, fixturePacketTiming{})
	if !ok || result.err != nil || len(result.packet) == 0 {
		t.Fatalf("ESP did not seal during IKE work: accepted=%t err=%v", ok, result.err)
	}
	m.stopPeer(p, "test revocation while IKE is leased")
	if result.job.ctx.Err() == nil || data.active != nil {
		t.Fatal("revocation left the leased peer's CHILD usable")
	}
}
