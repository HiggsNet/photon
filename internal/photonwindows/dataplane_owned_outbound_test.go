package photonwindows

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/photonclient/esp"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/routing"
)

func TestDataplaneOwnedOutboundTransfersPlaintextThroughDelivery(t *testing.T) {
	d, plan, child, _ := serialDataplaneFixture(t)
	packet := dataplanePacket(true)
	original := bytes.Clone(packet)
	result, ok := d.processOwnedOutbound(10, plan, packet, dataplaneAllow)
	if !ok || result.err != nil || !bytes.Equal(packet, original) {
		t.Fatal("owned outbound changed its plaintext or failed AES", result.err)
	}
	if len(d.jobs) != 0 || len(d.completed) != 0 || len(result.job.packet) != len(packet) || &result.job.packet[0] != &packet[0] {
		t.Fatal("owned plaintext was copied or entered an asynchronous queue")
	}
	checked := false
	wire, _, outbound, accepted := d.accept(result, plan, func(inner []byte, outbound bool) bool {
		checked = outbound && &inner[0] == &packet[0] && bytes.Equal(inner, original)
		return checked
	})
	if !accepted || !outbound || !checked {
		t.Fatal("current delivery did not examine the transferred plaintext")
	}
	// Ownership lasts through that gate. Reusing the input afterwards cannot
	// alter the independently owned ciphertext handed to the socket.
	clear(packet)
	receiver, err := esp.NewReceiver(child.ResponderSPI, child.Keys.InitiatorToResponder)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := receiver.Open(wire)
	if err != nil || !bytes.Equal(plain, original) {
		t.Fatal("input reuse after delivery changed the sealed ESP packet", err)
	}
}

func TestDataplaneOwnedOutboundRechecksSignedRoute(t *testing.T) {
	f := newPipelineFixture(t)
	f.learn(t)
	view := detachedPacketPolicyView(f.view)
	var facts packetAuthorization
	if !f.p.prepareSnapshotInto(f.config, view, f.plan, f.now, &facts) {
		t.Fatal("initial signed policy rejected the leaf packet")
	}
	packet := f.packet(true)
	result, ok := f.p.tunnel.data.processOwnedOutbound(f.p.generation, facts.plan, packet,
		func(packet []byte, outbound bool) bool { return f.p.authorize(&facts, packet, outbound) })
	if !ok || result.err != nil {
		t.Fatal("owned signed outbound AES failed", result.err)
	}
	key, _ := routing.NormalizeRouteAnnouncementKey("10.1.2.0/24")
	f.put(f.config.Gateway.AllowedZones[0], key, routing.RecordTypeRouteAnnouncement,
		routing.RouteAnnouncementRecord{Version: 1, Prefix: "10.1.2.0/24", Active: false})
	current := detachedPacketPolicyView(f.view)
	current.Revision++
	if !f.p.prepareSnapshotInto(f.config, current, f.plan, f.now.Add(time.Nanosecond), &facts) {
		t.Fatal("remote route withdrawal incorrectly removed the local attachment")
	}
	if accepted, err := f.p.acceptPrepared(&facts, result); accepted || err != nil {
		t.Fatal("owned AES result bypassed the withdrawn signed route", err)
	}
}

func TestDataplaneOwnedOutboundDenialAndCancellationPreserveSequence(t *testing.T) {
	for _, scenario := range []string{"missing authorization", "stale generation", "owner canceled", "generation canceled"} {
		t.Run(scenario, func(t *testing.T) {
			d, plan, _, _ := serialDataplaneFixture(t)
			generation := uint64(10)
			authorize := dataplaneAllow
			switch scenario {
			case "missing authorization":
				authorize = nil
			case "stale generation":
				generation++
			case "owner canceled":
				d.cancel()
			case "generation canceled":
				d.cancelGeneration()
			}
			result, ok := d.processOwnedOutbound(generation, plan, dataplanePacket(true), authorize)
			if scenario == "generation canceled" {
				if !ok || !errors.Is(result.err, context.Canceled) || result.packet != nil {
					t.Fatal("owned crypto did not observe the canceled generation", ok, result.err)
				}
				if packet, _, _, accepted := d.accept(result, plan, dataplaneAllow); accepted || packet != nil {
					t.Fatal("canceled owned crypto completion exposed data")
				}
			} else if ok {
				t.Fatal("owned processing bypassed current preflight", scenario)
			}
			wire, err := d.active.sender.Seal(dataplanePacket(true))
			if err != nil || binary.BigEndian.Uint32(wire[4:8]) != 1 {
				t.Fatal("denied or canceled owned processing consumed a nonce", err)
			}
		})
	}
}

// The comparison keeps both production-style current gates, genuine signed
// policy, ESP and real shared UDP. Only the OS device is in memory. A packet
// stays exclusive through delivery, then can be reused by the next iteration.
func BenchmarkGatewayPacketOwnedOutbound(b *testing.B) {
	for _, owned := range []bool{false, true} {
		name := "Cloned"
		if owned {
			name = "Owned"
		}
		for _, size := range []int{128, 1200} {
			b.Run(fmt.Sprintf("%s/%d", name, size), func(b *testing.B) {
				f := newPipelineFixture(b)
				f.learn(b)
				f.view.State.ManagedZone = f.config.ManagedZone
				f.view.State.TrustedRootPublicKey = f.config.TrustedRootPublicKey
				store, err := corestate.RestoreStore(&corestate.CommitCandidate{Verified: f.view.State}, f.view.Revision, nil, nil)
				if err != nil {
					b.Fatal(err)
				}
				b.Cleanup(store.Close)
				var reader packetStateView
				if !f.submitFromDevice(b, f.packet(true)) || !f.accept(b, f.businessCompletion(b)) {
					b.Fatal("signed benchmark setup rejected business traffic")
				}
				f.receiveBusiness(b)
				packet := make([]byte, size)
				copy(packet, f.packet(true))
				binary.BigEndian.PutUint16(packet[2:4], uint16(size))
				binary.BigEndian.PutUint16(packet[24:26], uint16(size-20))
				for n := 28; n < len(packet); n++ {
					packet[n] = byte(n)
				}
				buffer := make([]byte, 65536)
				b.SetBytes(int64(size))
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					var facts packetAuthorization
					if !f.p.prepareSnapshotInto(f.config, reader.read(store), f.plan, f.now, &facts) {
						b.Fatal("current signed outbound preparation failed")
					}
					var result dataplaneCompletion
					var processed bool
					if owned {
						result, processed = f.p.tunnel.data.processOwnedOutbound(f.p.generation, facts.plan, packet,
							func(packet []byte, outbound bool) bool { return f.p.authorize(&facts, packet, outbound) })
					} else {
						result, processed = f.p.tunnel.data.processOutbound(f.p.generation, facts.plan, packet,
							func(packet []byte, outbound bool) bool { return f.p.authorize(&facts, packet, outbound) })
					}
					if !processed || result.err != nil {
						b.Fatal("outbound AES failed", result.err)
					}
					if !f.p.prepareSnapshotInto(f.config, reader.read(store), f.plan, f.now, &facts) {
						b.Fatal("fresh signed delivery preparation failed")
					}
					f.p.tunnel.observeData(result, facts.plan, f.now)
					if accepted, err := f.p.acceptPrepared(&facts, result); !accepted || err != nil {
						b.Fatal("current outbound delivery failed", err)
					}
					if err := f.peer.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
						b.Fatal(err)
					}
					n, _, err := f.peer.ReadFromUDP(buffer)
					if err != nil {
						b.Fatal(err)
					}
					plain, err := f.receiver.Open(buffer[:n])
					if err != nil || !bytes.Equal(plain, packet) {
						b.Fatal("owned outbound ESP roundtrip changed the packet", err)
					}
				}
			})
		}
	}
}
