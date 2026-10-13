package photonwindows

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/photonclient/esp"
	"github.com/HiggsNet/photon/internal/photonclient/ike"
	"github.com/HiggsNet/photon/pkg/routing"
)

func TestDataplaneOwnedScratchEndsAtDeliveryOrDrop(t *testing.T) {
	d, plan, child, control := serialDataplaneFixture(t)
	peer, err := esp.NewReceiver(child.ResponderSPI, child.Keys.InitiatorToResponder)
	if err != nil {
		t.Fatal(err)
	}
	inner := dataplanePacket(true)
	original := bytes.Clone(inner)
	first, ok := d.processOwnedOutbound(10, plan, inner, dataplaneAllow)
	if !ok || first.err != nil || !bytes.Equal(inner, original) || len(d.outboundScratch) != esp.MaxPacket || cap(d.outboundScratch) != esp.MaxPacket {
		t.Fatal("owned encryption changed its input or lost its bounded workspace", first.err)
	}
	backing := &d.outboundScratch[0]
	if &first.packet[0] != backing || &first.job.packet[0] != &inner[0] || len(d.jobs) != 0 || len(d.completed) != 0 {
		t.Fatal("owned crypto copied plaintext/output or escaped to a queue")
	}
	wire, _, _, accepted := d.accept(first, plan, func(packet []byte, outbound bool) bool {
		return outbound && &packet[0] == &inner[0] && bytes.Equal(packet, original)
	})
	plain, err := peer.Open(wire) // Synchronous delivery ends the first borrow.
	if !accepted || err != nil || !bytes.Equal(plain, original) {
		t.Fatal("owned delivery did not recheck the unchanged original plaintext", err)
	}
	// A queued control result must stay detached when later business turns reuse
	// the workspace. Its sequence is allocated only in this owner turn.
	if !d.submitOutbound(10, plan, control, dataplaneAllow) {
		t.Fatal("control was not queued")
	}
	queued := executeDataplaneJob(<-d.jobs)
	controlWire := bytes.Clone(queued.packet)
	if _, _, _, accepted := d.accept(queued, plan, dataplaneAllow); !accepted {
		t.Fatal("detached control delivery rejected")
	}
	if _, err := peer.Open(queued.packet); err != nil {
		t.Fatal("real peer rejected serial control", err)
	}
	dropped, ok := d.processOwnedOutbound(10, plan, inner, dataplaneAllow)
	if !ok || dropped.err != nil || &dropped.packet[0] != backing {
		t.Fatal("next owner turn failed to reuse its workspace", dropped.err)
	}
	if packet, _, _, accepted := d.accept(dropped, plan, nil); accepted || packet != nil {
		t.Fatal("missing current route delivered borrowed ESP")
	}
	// The rejected turn is finished. Do not inspect its borrowed packet after
	// this next call, which is allowed to overwrite the same storage.
	last, ok := d.processOwnedOutbound(10, plan, inner, dataplaneAllow)
	if !ok || last.err != nil || &last.packet[0] != backing || !bytes.Equal(queued.packet, controlWire) {
		t.Fatal("reuse aliased queued control or lost its bound", last.err)
	}
	wire, _, _, accepted = d.accept(last, plan, dataplaneAllow)
	plain, err = peer.Open(wire)
	if !accepted || err != nil || !bytes.Equal(plain, original) {
		t.Fatal("delivery after a drop failed", err)
	}
	endpoint := d.active.endpoint
	d.reset(11)
	if d.outboundScratch != nil {
		t.Fatal("reset retained the owner workspace")
	}
	if err := d.install(11, plan, endpoint, dataplaneChild(child.InitiatorSPI+1)); err != nil {
		t.Fatal(err)
	}
	if result, ok := d.processOwnedOutbound(11, plan, inner, dataplaneAllow); !ok || result.err != nil {
		t.Fatal("fresh generation could not allocate its bounded workspace", result.err)
	}
	d.close()
	if d.outboundScratch != nil {
		t.Fatal("close retained the owner workspace")
	}
}

func TestDataplaneOwnedScratchCancellationDoesNotAllocate(t *testing.T) {
	d, plan, _, _ := serialDataplaneFixture(t)
	d.cancelGeneration()
	result, ok := d.processOwnedOutbound(10, plan, dataplanePacket(true), dataplaneAllow)
	if !ok || !errors.Is(result.err, context.Canceled) || result.packet != nil || d.outboundScratch != nil {
		t.Fatal("canceled owned crypto allocated output or lost its typed error", result.err)
	}
}

func TestDataplaneOwnedBuffersRealUDPAndDevice(t *testing.T) {
	f := newPipelineFixture(t)
	f.learn(t)
	for range 2 {
		var facts packetAuthorization
		if !f.p.prepareSnapshotInto(f.config, detachedPacketPolicyView(f.view), f.plan, f.now, &facts) {
			t.Fatal("signed outbound preparation rejected")
		}
		inner := f.packet(true)
		original := bytes.Clone(inner)
		result, ok := f.p.tunnel.data.processOwnedOutbound(f.p.generation, facts.plan, inner,
			func(packet []byte, outbound bool) bool { return f.p.authorize(&facts, packet, outbound) })
		if !ok || result.err != nil || !bytes.Equal(inner, original) {
			t.Fatal("owned business ESP failed", result.err)
		}
		if !f.p.prepareSnapshotInto(f.config, detachedPacketPolicyView(f.view), f.plan, f.now, &facts) {
			t.Fatal("fresh delivery preparation rejected")
		}
		f.p.tunnel.observeData(result, facts.plan, f.now)
		if accepted, err := f.p.acceptPrepared(&facts, result); !accepted || err != nil {
			t.Fatal("current real UDP delivery failed", err)
		}
		clear(inner) // Only after synchronous WriteTunnel has returned.
		if got := f.receiveBusiness(t); !bytes.Equal(got, original) {
			t.Fatal("scratch reuse or caller reuse changed the real UDP packet")
		}
	}
	inner := f.packet(false)
	wire, err := f.sender.Seal(inner)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.peer.WriteToUDP(wire, f.p.tunnel.socket.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	select {
	case received := <-f.p.tunnel.socket.espPackets:
		result, ok := f.p.tunnel.data.processOwnedInbound(received.generation, f.plan, received.peer, received.packet)
		if !ok || result.err != nil || result.job.packet != nil || !bytes.Equal(result.packet, inner) || &result.packet[0] != &received.packet[16] || cap(result.packet) != len(result.packet) {
			t.Fatal("queue-owned ingress was copied, retained as ciphertext, or corrupted", result.err)
		}
		var facts packetAuthorization
		if !f.p.prepareSnapshotInto(f.config, detachedPacketPolicyView(f.view), f.plan, f.now, &facts) {
			t.Fatal("fresh inbound preparation rejected")
		}
		f.p.tunnel.observeData(result, facts.plan, f.now)
		if accepted, err := f.p.acceptPrepared(&facts, result); !accepted || err != nil {
			t.Fatal("current owned inbound delivery failed", err)
		}
		if len(f.device.written) != 1 || !bytes.Equal(f.device.written[0], inner) {
			t.Fatal("owned inbound did not reach the device")
		}
	case <-time.After(time.Second):
		t.Fatal("owned UDP demux timeout")
	}
}

func TestDataplaneOwnedInboundSignedWithdrawalAfterAES(t *testing.T) {
	f := newPipelineFixture(t)
	f.learn(t)
	wire, err := f.sender.Seal(f.packet(false))
	if err != nil {
		t.Fatal(err)
	}
	result, ok := f.p.tunnel.data.processOwnedInbound(f.p.generation, f.plan, f.p.tunnel.data.active.endpoint, wire)
	if !ok || result.err != nil {
		t.Fatal("owned inbound AES failed", result.err)
	}
	key, _ := routing.NormalizeRouteAnnouncementKey("10.1.2.0/24")
	f.put(f.config.Gateway.AllowedZones[0], key, routing.RecordTypeRouteAnnouncement,
		routing.RouteAnnouncementRecord{Version: 1, Prefix: "10.1.2.0/24", Active: false})
	var facts packetAuthorization
	view := detachedPacketPolicyView(f.view)
	view.Revision++
	if !f.p.prepareSnapshotInto(f.config, view, f.plan, f.now.Add(time.Nanosecond), &facts) {
		t.Fatal("remote withdrawal incorrectly removed the local attachment")
	}
	if accepted, err := f.p.acceptPrepared(&facts, result); accepted || err != nil || len(f.device.written) != 0 {
		t.Fatal("owned plaintext bypassed the new signed route withdrawal", err)
	}
}

func TestDataplaneOwnedBuffersUseCurrentSAGates(t *testing.T) {
	for _, change := range []string{"generation", "generation cancel", "owner cancel", "selectors", "active CHILD"} {
		t.Run(change, func(t *testing.T) {
			d, plan, child, _ := serialDataplaneFixture(t)
			endpoint := d.active.endpoint
			out, ok := d.processOwnedOutbound(10, plan, dataplanePacket(true), dataplaneAllow)
			if !ok || out.err != nil {
				t.Fatal("owned outbound AES failed", out.err)
			}
			in, ok := d.processOwnedInbound(10, plan, endpoint, directInboundWire(t, child))
			if !ok || in.err != nil {
				t.Fatal("owned inbound AES failed", in.err)
			}
			switch change {
			case "generation":
				d.reset(11)
			case "generation cancel":
				d.cancelGeneration()
			case "owner cancel":
				d.cancel()
			case "selectors":
				address := netip.MustParseAddr("10.99.0.1")
				d.active.local = []ike.TrafficSelector{{StartAddr: address, EndAddr: address, EndPort: 65535}}
			case "active CHILD":
				next := dataplaneChild(child.InitiatorSPI + 1)
				if err := d.install(10, plan, endpoint, next); err != nil {
					t.Fatal(err)
				}
				if err := d.activate(next.InitiatorSPI); err != nil {
					t.Fatal(err)
				}
			}
			if packet, _, _, accepted := d.accept(out, plan, dataplaneAllow); accepted || packet != nil {
				t.Fatal("borrowed outbound survived a changed current SA gate")
			}
			packet, _, _, accepted := d.accept(in, plan, dataplaneAllow)
			if change == "active CHILD" {
				if !accepted || !bytes.Equal(packet, dataplanePacket(false)) {
					t.Fatal("owned decryption lost valid old inbound CHILD overlap")
				}
				d.retire(child.InitiatorSPI)
				if packet, _, _, accepted := d.accept(in, plan, dataplaneAllow); accepted || packet != nil {
					t.Fatal("retired owned inbound CHILD remained deliverable")
				}
			} else if accepted || packet != nil {
				t.Fatal("owned plaintext survived a changed current SA gate")
			}
		})
	}
}

func TestDataplaneOwnedInboundErrorsNeverDeliverOrConsumeReplay(t *testing.T) {
	d, plan, endpoint, child := dataplaneFixture(t)
	wire := directInboundWire(t, child)
	corrupted := bytes.Clone(wire)
	corrupted[len(corrupted)-1] ^= 1
	result, ok := d.processOwnedInbound(10, plan, endpoint, corrupted)
	if !ok || !errors.Is(result.err, esp.ErrAuthentication) || result.packet != nil || result.job.packet != nil {
		t.Fatal("owned authentication failure exposed storage or lost its type", result.err)
	}
	if packet, _, _, accepted := d.accept(result, plan, dataplaneAllow); accepted || packet != nil {
		t.Fatal("owned authentication failure reached delivery")
	}
	result, ok = d.processOwnedInbound(10, plan, endpoint, bytes.Clone(wire))
	if !ok || result.err != nil {
		t.Fatal("failed owned decryption advanced replay", result.err)
	}
	if _, _, _, accepted := d.accept(result, plan, dataplaneAllow); !accepted {
		t.Fatal("fresh valid owned ciphertext did not reach the delivery gate")
	}
	// Every admitted UDP event has its own detached storage. The original
	// consumed ciphertext is never retried, even when checking replay rejection.
	result, ok = d.processOwnedInbound(10, plan, endpoint, bytes.Clone(wire))
	if !ok || !errors.Is(result.err, esp.ErrReplay) || result.packet != nil || result.job.packet != nil {
		t.Fatal("owned replay failure lost its type or exposed data", result.err)
	}
	if packet, _, _, accepted := d.accept(result, plan, dataplaneAllow); accepted || packet != nil {
		t.Fatal("owned replay reached delivery")
	}
}

func TestDataplaneOwnedInboundPreflightPreservesCiphertext(t *testing.T) {
	for _, rejection := range []string{"generation", "endpoint", "unknown SPI", "generation cancel", "owner cancel"} {
		t.Run(rejection, func(t *testing.T) {
			d, plan, endpoint, child := dataplaneFixture(t)
			wire := directInboundWire(t, child)
			original := bytes.Clone(wire)
			generation := uint64(10)
			switch rejection {
			case "generation":
				generation++
			case "endpoint":
				endpoint = netip.MustParseAddrPort("192.0.2.2:4500")
			case "unknown SPI":
				binary.BigEndian.PutUint32(wire[:4], child.InitiatorSPI+99)
			case "generation cancel":
				d.cancelGeneration()
			case "owner cancel":
				d.cancel()
			}
			before := bytes.Clone(wire)
			result, processed := d.processOwnedInbound(generation, plan, endpoint, wire)
			if !bytes.Equal(wire, before) || result.packet != nil || result.job.packet != nil {
				t.Fatal("owned ingress decrypted or retained a denied input")
			}
			if rejection == "generation cancel" {
				if !processed || !errors.Is(result.err, context.Canceled) {
					t.Fatal("canceled generation lost the current typed completion", result.err)
				}
			} else if processed {
				t.Fatal("owned input bypassed preflight", rejection)
			}
			// Use an independent genuine datagram, not consumed storage, to prove
			// the denied attempt did not advance this receiver's replay window.
			plain, err := d.active.receiver.Open(original)
			if err != nil || !bytes.Equal(plain, dataplanePacket(false)) {
				t.Fatal("denied input consumed an authenticated sequence", err)
			}
		})
	}
}
