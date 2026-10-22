//go:build photon_profile

package photonwindows

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/photonclient/babel"
	"github.com/HiggsNet/photon/internal/photonclient/ike"
	"github.com/HiggsNet/photon/pkg/routing"
)

type fixtureTimingWriteFailure struct{ err error }

func (d fixtureTimingWriteFailure) Write([]byte) error { return d.err }

func startConsumerTiming(t *testing.T) {
	t.Helper()
	if err := StartFixturePacketTiming(true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { StopFixturePacketTiming() })
}

func assertConsumerTimingFinished(t *testing.T, report FixturePacketTiming, direction fixturePacketTimingDirection, class fixturePacketTimingClass, outcomes FixturePacketTimingOutcomes, aes, delivery bool) {
	t.Helper()
	d := report.Directions[direction]
	c := d.Classes[class]
	if report.ClockErrors != 0 || report.InvalidSamples != 0 || d.Selected != 1 || d.Finished != 1 || d.Unfinished != 0 || c.Outcomes != outcomes {
		t.Fatalf("sample lifecycle/classification mismatch: report=%+v", report)
	}
	stages := c.Stages
	if stages.QueueWait.Count != 1 || stages.Precheck.Count != 1 || stages.OwnerTotal.Count != 1 ||
		(stages.AES.Count == 1) != aes || (stages.FreshGate.Count == 1) != aes || (stages.Delivery.Count == 1) != delivery {
		t.Fatalf("sample did not retain its actual stage boundaries: %+v", stages)
	}
	for i, other := range d.Classes {
		if i != int(class) && other.Outcomes != (FixturePacketTimingOutcomes{}) {
			t.Fatal("sample was counted in more than one class")
		}
	}
}

func TestPacketTimingConsumerFreshGatesAndDelivery(t *testing.T) {
	for _, scenario := range []string{"outbound", "inbound", "Babel control", "authentication failure", "device write failure", "signed withdrawal", "selectors changed", "cancel after AES"} {
		t.Run(scenario, func(t *testing.T) {
			f := newPipelineFixture(t)
			f.learn(t)
			var facts packetAuthorization
			if !f.p.prepareSnapshotInto(f.config, detachedPacketPolicyView(f.view), f.plan, f.now, &facts) {
				t.Fatal("initial signed policy rejected")
			}
			startConsumerTiming(t)
			direction, class := fixturePacketTimingInbound, fixturePacketTimingBusiness
			var result dataplaneCompletion
			var processed bool
			if scenario == "outbound" || scenario == "signed withdrawal" || scenario == "selectors changed" || scenario == "cancel after AES" {
				direction = fixturePacketTimingOutbound
				trace := beginFixturePacketTimingQueue(direction)
				trace.Dequeue()
				trace.Classify(class)
				result, processed = f.p.tunnel.data.processOwnedOutbound(f.p.generation, facts.plan, f.packet(true),
					func(packet []byte, outbound bool) bool { return f.p.authorize(&facts, packet, outbound) }, trace)
			} else {
				inner := f.packet(false)
				if scenario == "Babel control" {
					payload, err := babel.Encode([]babel.Message{{Type: babel.TLVHello, Seqno: 2, Interval: 400}})
					if err != nil {
						t.Fatal(err)
					}
					inner, err = babel.BuildPacket(f.p.peer, f.p.local, payload)
					if err != nil {
						t.Fatal(err)
					}
					class = fixturePacketTimingControl
				}
				wire, err := f.sender.Seal(inner)
				if err != nil {
					t.Fatal(err)
				}
				if scenario == "authentication failure" {
					wire[len(wire)-1] ^= 1
					class = fixturePacketTimingUnknown
				}
				// Exercise the actual UDP reader/demux admission and detached
				// ownership before the same core used by the daemon consumer.
				if _, err := f.peer.WriteToUDP(wire, f.p.tunnel.socket.LocalAddr()); err != nil {
					t.Fatal(err)
				}
				select {
				case event := <-f.p.tunnel.socket.espPackets:
					if !event.timing.Sampled() || &event.packet[0] == &wire[0] {
						t.Fatal("real demux omitted the probe or lost detached ownership")
					}
					event.timing.Dequeue()
					result, processed = f.p.tunnel.data.processOwnedInbound(event.generation, f.plan, event.peer, event.packet, event.timing)
				case <-time.After(time.Second):
					t.Fatal("real ESP admission timed out")
				}
			}
			if !processed || (result.err != nil && scenario != "authentication failure") {
				t.Fatal("owned AES failed before the intended gate", result.err)
			}
			writeErr := errors.New("timing fixture write failure")
			if scenario == "device write failure" {
				f.p.device = fixtureTimingWriteFailure{writeErr}
			}
			if scenario == "signed withdrawal" {
				key, _ := routing.NormalizeRouteAnnouncementKey("10.1.2.0/24")
				f.put(f.config.Gateway.AllowedZones[0], key, routing.RecordTypeRouteAnnouncement,
					routing.RouteAnnouncementRecord{Version: 1, Prefix: "10.1.2.0/24", Active: false})
			}
			if !f.p.prepareSnapshotInto(f.config, detachedPacketPolicyView(f.view), f.plan, f.now.Add(time.Nanosecond), &facts) {
				t.Fatal("fresh policy rejected before the intended delivery gate")
			}
			if scenario == "cancel after AES" {
				f.p.tunnel.data.cancelGeneration()
			}
			if scenario == "selectors changed" {
				address := netip.MustParseAddr("10.99.0.1")
				f.p.tunnel.data.active.local = []ike.TrafficSelector{{StartAddr: address, EndAddr: address, EndPort: 65535}}
			}
			accepted, err := f.p.acceptPrepared(&facts, result)
			outcomes := FixturePacketTimingOutcomes{Delivered: 1}
			delivery := true
			switch scenario {
			case "authentication failure":
				outcomes, delivery = FixturePacketTimingOutcomes{CryptoError: 1}, false
			case "signed withdrawal", "selectors changed":
				outcomes, delivery = FixturePacketTimingOutcomes{Rejected: 1}, false
			case "cancel after AES":
				outcomes, delivery = FixturePacketTimingOutcomes{Canceled: 1}, false
			case "device write failure":
				outcomes = FixturePacketTimingOutcomes{DeliveryError: 1}
			case "Babel control":
				delivery = false
			}
			if accepted != (outcomes.Delivered == 1 || outcomes.DeliveryError == 1) || (err != nil) != (scenario == "device write failure") || (err != nil && !errors.Is(err, writeErr)) {
				t.Fatal("timing changed delivery/error semantics", accepted, err)
			}
			if direction == fixturePacketTimingInbound && scenario == "inbound" {
				if len(f.device.written) != 1 || !bytes.Equal(f.device.written[0], f.packet(false)) {
					t.Fatal("sampled owned plaintext did not reach the device intact")
				}
			} else if len(f.device.written) != 0 {
				t.Fatal("denied or control packet reached the host device")
			}
			if scenario == "outbound" && !bytes.Equal(f.receiveBusiness(t), f.packet(true)) {
				t.Fatal("sampled outbound delivery changed the real UDP packet")
			}
			report := StopFixturePacketTiming()
			assertConsumerTimingFinished(t, report, direction, class, outcomes, true, delivery)
			for _, histogram := range report.Directions[direction].Classes[class].UDPDelivery.histograms() {
				var want uint64
				if scenario == "outbound" {
					want = 1
				}
				assertPacketTimingHist(t, *histogram, want)
			}
		})
	}
}

func TestPacketTimingQueueAdmissionAndStop(t *testing.T) {
	t.Run("ESP full and non-ESP excluded", func(t *testing.T) {
		s := &packetSockets{ikePackets: make(chan tunnelDatagram, 16), espPackets: make(chan tunnelDatagram, 64)}
		peer := netip.MustParseAddrPort("192.0.2.1:4500")
		s.SelectTunnel(netip.AddrPort{}, peer)
		for range cap(s.espPackets) {
			s.espPackets <- tunnelDatagram{}
		}
		startConsumerTiming(t)
		if !s.demuxLocked([]byte{255}, peer) || s.demuxLocked([]byte("gossip"), netip.MustParseAddrPort("192.0.2.2:4500")) {
			t.Fatal("keepalive or foreign behavior changed")
		}
		initiator, err := ike.NewInitiator()
		if err != nil {
			t.Fatal(err)
		}
		request, err := ike.EncapsulateIKE(initiator.Request())
		if err != nil {
			t.Fatal(err)
		}
		if !s.demuxLocked(request, peer) || !s.demuxLocked([]byte{1, 2, 3, 4, 0, 0, 0, 1}, peer) {
			t.Fatal("selected tunnel datagrams bypassed demux")
		}
		report := StopFixturePacketTiming()
		d := report.Directions[fixturePacketTimingInbound]
		c := d.Classes[fixturePacketTimingUnknown]
		if d.Selected != 1 || d.Finished != 1 || d.Unfinished != 0 || c.Outcomes.QueueRejected != 1 || c.Stages != (FixturePacketTimingStages{}) || len(s.espPackets) != 64 || len(s.ikePackets) != 1 {
			t.Fatal("queue rejection was timed as an admitted packet or IKE was sampled", d)
		}
	})
	t.Run("leaf canceled before dequeue", func(t *testing.T) {
		f := runtimeFixture(t)
		device := &fixtureDropDevice{runtimePacketDevice: newRuntimeDevice(), reading: make(chan struct{}), input: make(chan leafDevicePacket)}
		r := newLeafRuntime(func(context.Context, string, []netip.Prefix, []netip.Prefix, uint32, uint32) (ownedPacketDevice, error) {
			return device, nil
		})
		t.Cleanup(func() { r.close() })
		if err := r.reconcile(t.Context(), f.config, f.view, f.plan, f.p.tunnel, f.p.routerID, f.now); err != nil {
			t.Fatal(err)
		}
		if err := r.complete(t.Context(), f.config, f.view, f.plan, f.p.tunnel, f.p.routerID, f.now, runtimeOpenResult(t, r)); err != nil {
			t.Fatal(err)
		}
		fixtureDropReaderReady(t, device)
		startConsumerTiming(t)
		fixtureDropReadResult(t, device, leafDevicePacket{packet: f.packet(true)})
		fixtureDropReaderReady(t, device)
		if len(r.packets) != 1 {
			t.Fatal("leaf admission lost its owned packet")
		}
		if err := r.stop(); err != nil {
			t.Fatal(err)
		}
		d := StopFixturePacketTiming().Directions[fixturePacketTimingOutbound]
		c := d.Classes[fixturePacketTimingUnknown]
		if d.Selected != 1 || d.Finished != 1 || d.Unfinished != 0 || c.Outcomes.Canceled != 1 || c.Stages != (FixturePacketTimingStages{}) {
			t.Fatal("stop created dequeue/owner timing or lost its canceled sample", d)
		}
	})
}

func TestPacketTimingOwnedPreflightRejectEndsSample(t *testing.T) {
	d, plan, _, _ := serialDataplaneFixture(t)
	startConsumerTiming(t)
	trace := beginFixturePacketTimingQueue(fixturePacketTimingOutbound)
	trace.Dequeue()
	trace.Classify(fixturePacketTimingBusiness)
	result, processed := d.processOwnedOutbound(11, plan, dataplanePacket(true), dataplaneAllow, trace)
	if processed || result.packet != nil || result.job.packet != nil || d.outboundScratch != nil {
		t.Fatal("timing changed stale-generation preflight")
	}
	result.timing.Finish(fixturePacketTimingRejected)
	assertConsumerTimingFinished(t, StopFixturePacketTiming(), fixturePacketTimingOutbound, fixturePacketTimingBusiness, FixturePacketTimingOutcomes{Rejected: 1}, false, false)
}
