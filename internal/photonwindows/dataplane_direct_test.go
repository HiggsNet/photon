package photonwindows

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/photonclient/esp"
	"github.com/HiggsNet/photon/internal/photonclient/ike"
	"github.com/HiggsNet/photon/pkg/routing"
)

func directInboundWire(t *testing.T, child ike.ChildResult) []byte {
	t.Helper()
	sender, err := esp.NewSender(child.InitiatorSPI, child.Keys.ResponderToInitiator)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := sender.Seal(dataplanePacket(false))
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestDataplaneDirectBidirectionalOwnership(t *testing.T) {
	d, plan, endpoint, child := dataplaneFixture(t)
	inner := dataplanePacket(true)
	original := bytes.Clone(inner)
	out, ok := d.processOutbound(10, plan, inner, dataplaneAllow)
	if !ok || out.err != nil {
		t.Fatal("direct outbound encryption failed", out.err)
	}
	// Device-read buffers may be reused immediately. Delivery selectors must
	// still examine the independently owned packet that was actually sealed.
	inner[15] = 99
	wire, peer, outbound, accepted := d.accept(out, plan, dataplaneAllow)
	if !accepted || !outbound || peer != endpoint {
		t.Fatal("direct outbound lost packet ownership")
	}
	receiver, err := esp.NewReceiver(child.ResponderSPI, child.Keys.InitiatorToResponder)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := receiver.Open(wire)
	if err != nil || !bytes.Equal(plain, original) {
		t.Fatal("direct outbound ESP did not preserve the submitted packet", err)
	}
	wire = directInboundWire(t, child)
	original = bytes.Clone(wire)
	in, ok := d.processInbound(10, plan, endpoint, wire)
	if !ok || in.err != nil {
		t.Fatal("direct inbound decryption failed", in.err)
	}
	if !bytes.Equal(wire, original) || in.job.packet != nil {
		t.Fatal("direct inbound modified or retained its ciphertext input")
	}
	// Reuse the entire ingress buffer after synchronous Open. Only detached
	// authenticated plaintext may reach selectors and delivery afterwards.
	clear(wire)
	plain, peer, outbound, accepted = d.accept(in, plan, dataplaneAllow)
	if !accepted || outbound || peer != endpoint || !bytes.Equal(plain, dataplanePacket(false)) {
		t.Fatal("direct inbound authenticated delivery failed")
	}
}

func TestDataplaneDirectInboundCancellationDoesNotConsumeSequence(t *testing.T) {
	for _, cancelOwner := range []bool{false, true} {
		name := "generation"
		if cancelOwner {
			name = "owner"
		}
		t.Run(name, func(t *testing.T) {
			d, plan, endpoint, child := dataplaneFixture(t)
			wire := directInboundWire(t, child)
			if cancelOwner {
				d.cancel()
			} else {
				d.cancelGeneration()
			}
			result, ok := d.processInbound(10, plan, endpoint, wire)
			wantProcessed := !cancelOwner
			if ok != wantProcessed || result.packet != nil || result.job.packet != nil {
				t.Fatal("cancelled direct inbound retained or exposed packet data")
			}
			if ok {
				if !errors.Is(result.err, context.Canceled) || result.job.sa != d.active || result.job.generation != 10 || result.job.outbound {
					t.Fatal("generation cancellation lost its current completion metadata", result.err)
				}
				if packet, _, _, accepted := d.accept(result, plan, dataplaneAllow); accepted || packet != nil {
					t.Fatal("cancelled direct inbound became deliverable")
				}
			}
			// Cancellation must stop before Open updates the replay window.
			packet, err := d.active.receiver.Open(wire)
			if err != nil || !bytes.Equal(packet, dataplanePacket(false)) {
				t.Fatal("cancelled direct inbound consumed an authenticated sequence", err)
			}
		})
	}
}

func TestDataplaneDirectPreflight(t *testing.T) {
	for _, inbound := range []bool{false, true} {
		for _, scenario := range []string{"generation", "gateway", "endpoint", "selector", "missing route", "unknown SPI", "truncated ESP", "oversized ESP"} {
			if inbound && (scenario == "selector" || scenario == "missing route") {
				continue // inbound selectors/routes can only gate authenticated plaintext
			}
			if !inbound && (scenario == "unknown SPI" || scenario == "truncated ESP" || scenario == "oversized ESP") {
				continue
			}
			t.Run(map[bool]string{false: "outbound", true: "inbound"}[inbound]+"/"+scenario, func(t *testing.T) {
				d, plan, endpoint, child := dataplaneFixture(t)
				generation := uint64(10)
				packet := dataplanePacket(true)
				authorize := dataplaneAllow
				if inbound {
					packet = directInboundWire(t, child)
				}
				switch scenario {
				case "generation":
					generation++
				case "gateway":
					plan.Rejected = "revoked"
				case "endpoint":
					if inbound {
						endpoint = netip.MustParseAddrPort("192.0.2.2:4500")
					} else {
						plan.Selected.Contact.Address = "192.0.2.2"
					}
				case "selector":
					packet[15] = 99
				case "missing route":
					authorize = nil
				case "unknown SPI":
					packet[0] ^= 1
				case "truncated ESP":
					packet = packet[:3]
				case "oversized ESP":
					packet = append(packet[:4], make([]byte, esp.MaxPacket-3)...)
				}
				var ok bool
				if inbound {
					_, ok = d.processInbound(generation, plan, endpoint, packet)
				} else {
					_, ok = d.processOutbound(generation, plan, packet, authorize)
				}
				if ok {
					t.Fatal("direct processing bypassed current preflight", inbound, scenario)
				}
			})
		}
	}
}

func TestDataplaneDirectDeliveryRevalidation(t *testing.T) {
	for _, scenario := range []string{"revocation", "route", "missing route", "generation", "generation cancel", "owner cancel", "SA ownership", "selectors", "active CHILD"} {
		t.Run(scenario, func(t *testing.T) {
			d, plan, endpoint, child := dataplaneFixture(t)
			out, ok := d.processOutbound(10, plan, dataplanePacket(true), dataplaneAllow)
			if !ok || out.err != nil {
				t.Fatal("initial direct outbound failed", out.err)
			}
			in, ok := d.processInbound(10, plan, endpoint, directInboundWire(t, child))
			if !ok || in.err != nil {
				t.Fatal("initial direct inbound failed", in.err)
			}
			authorize := dataplaneAllow
			switch scenario {
			case "revocation":
				plan.Rejected = "revoked"
			case "route":
				authorize = func([]byte, bool) bool { return false }
			case "missing route":
				authorize = nil
			case "generation":
				d.reset(11)
			case "generation cancel":
				d.cancelGeneration()
			case "owner cancel":
				d.cancel()
			case "SA ownership":
				// Equal material at the same SPI is not the accepted SA owner.
				replacement := *d.active
				d.sas[child.InitiatorSPI], d.active = &replacement, &replacement
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
			if packet, _, _, accepted := d.accept(out, plan, authorize); accepted || packet != nil {
				t.Fatal("direct outbound survived a changed current delivery gate")
			}
			packet, _, _, accepted := d.accept(in, plan, authorize)
			if scenario == "active CHILD" {
				if !accepted || !bytes.Equal(packet, dataplanePacket(false)) {
					t.Fatal("direct processing broke valid old inbound CHILD overlap")
				}
				d.retire(child.InitiatorSPI)
				if packet, _, _, accepted := d.accept(in, plan, authorize); accepted || packet != nil {
					t.Fatal("retired direct inbound CHILD remained deliverable")
				}
			} else if accepted || packet != nil {
				t.Fatal("direct inbound survived a changed current delivery gate")
			}
		})
	}
}

func TestDataplaneDirectCryptoErrorsRemainUndeliverable(t *testing.T) {
	d, plan, endpoint, child := dataplaneFixture(t)
	wire := directInboundWire(t, child)
	corrupted := bytes.Clone(wire)
	corrupted[len(corrupted)-1] ^= 1
	result, ok := d.processInbound(10, plan, endpoint, corrupted)
	if !ok || result.err == nil || result.packet != nil || result.job.packet != nil {
		t.Fatal("direct integrity error was lost or exposed plaintext", result.err)
	}
	if packet, _, _, accepted := d.accept(result, plan, dataplaneAllow); accepted || packet != nil {
		t.Fatal("integrity failure became deliverable")
	}
	// An unauthenticated packet must not consume the genuine sequence number.
	result, ok = d.processInbound(10, plan, endpoint, wire)
	if !ok || result.err != nil {
		t.Fatal("integrity failure consumed a valid inbound sequence", result.err)
	}
	if _, _, _, accepted := d.accept(result, plan, dataplaneAllow); !accepted {
		t.Fatal("valid direct inbound packet was rejected")
	}
	result, ok = d.processInbound(10, plan, endpoint, wire)
	if !ok || result.err == nil || result.packet != nil || result.job.packet != nil {
		t.Fatal("direct replay error was lost or exposed plaintext", result.err)
	}
	if packet, _, _, accepted := d.accept(result, plan, dataplaneAllow); accepted || packet != nil {
		t.Fatal("direct replay became deliverable")
	}
}

func TestDataplaneDirectSignedWithdrawalBeforeDelivery(t *testing.T) {
	for _, direction := range []string{"outbound", "inbound"} {
		t.Run(direction, func(t *testing.T) {
			f := newPipelineFixture(t)
			f.learn(t)
			view := detachedPacketPolicyView(f.view)
			facts, ok := f.p.prepareSnapshot(f.config, view, f.plan, f.now)
			if !ok {
				t.Fatal("signed pipeline authorization failed")
			}
			var result dataplaneCompletion
			if direction == "outbound" {
				result, ok = f.p.tunnel.data.processOutbound(f.p.generation, facts.plan, f.packet(true), func(packet []byte, outbound bool) bool { return f.p.authorize(facts, packet, outbound) })
			} else {
				result = f.directInboundCompletion(t, f.packet(false))
			}
			if !ok || result.err != nil {
				t.Fatal("signed direct ESP processing failed", result.err)
			}
			key, _ := routing.NormalizeRouteAnnouncementKey("10.1.2.0/24")
			f.put(f.config.Gateway.AllowedZones[0], key, routing.RecordTypeRouteAnnouncement, routing.RouteAnnouncementRecord{Version: 1, Prefix: "10.1.2.0/24", Active: false})
			view = detachedPacketPolicyView(f.view)
			view.Revision++
			facts, ok = f.p.prepareSnapshot(f.config, view, f.plan, f.now.Add(time.Nanosecond))
			if !ok {
				t.Fatal("remote route withdrawal incorrectly removed the local attachment")
			}
			if accepted, err := f.p.acceptPrepared(facts, result); accepted || err != nil || len(f.device.written) != 0 {
				t.Fatal("direct AES was mistaken for delivery authorization after signed withdrawal", err)
			}
		})
	}
}
