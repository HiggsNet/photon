//go:build photon_profile

package photonwindows

import (
	"bytes"
	"errors"
	"math"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestFixturePacketTimingUDPWriterBoundaries(t *testing.T) {
	for _, scenario := range []string{"delivered", "stale generation", "closed UDP", "UDP write error"} {
		t.Run(scenario, func(t *testing.T) {
			socket, err := openPacketSockets(t.Context(), "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { socket.Close() })
			peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { peer.Close() })
			endpoint := peer.LocalAddr().(*net.UDPAddr).AddrPort()
			generation := socket.SelectTunnel(netip.AddrPort{}, endpoint)
			packet := []byte{1, 2, 3, 4, 0, 0, 0, 1}
			startPacketTimingTest(t, true)
			// The unchanged public/control path must not select a sample even
			// when the profiling window is enabled.
			if err := socket.WriteTunnel(generation, packet, endpoint); err != nil {
				t.Fatal(err)
			}
			buffer := make([]byte, 64)
			if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			if n, _, err := peer.ReadFromUDP(buffer); err != nil || !bytes.Equal(buffer[:n], packet) {
				t.Fatal("ordinary/control UDP path changed", err)
			}
			trace := beginFixturePacketTimingQueue(fixturePacketTimingOutbound)
			trace.Dequeue()
			trace.MarkAESBegin()
			trace.MarkAESEnd()
			trace.Classify(fixturePacketTimingBusiness)
			switch scenario {
			case "stale generation":
				socket.SelectTunnel(netip.AddrPort{}, endpoint)
			case "closed UDP":
				// Preserve the socket owner fields to reach the real deadline
				// operation's closed-descriptor error before any UDP send.
				if err := socket.udp.Close(); err != nil {
					t.Fatal(err)
				}
			case "UDP write error":
				packet = make([]byte, 65536) // exceeds a real UDP datagram
			}
			trace.MarkDeliveryBegin()
			err = socket.writeTunnel(generation, packet, endpoint, &trace)
			trace.MarkDeliveryEnd()
			outcome := fixturePacketTimingDelivered
			if err != nil {
				outcome = fixturePacketTimingDeliveryError
			}
			trace.Finish(outcome)
			if (err == nil) != (scenario == "delivered") ||
				((scenario == "stale generation" || scenario == "closed UDP") && !errors.Is(err, net.ErrClosed)) {
				t.Fatal("sampled writer changed its real error contract", scenario, err)
			}
			if err == nil {
				if n, from, err := peer.ReadFromUDP(buffer); err != nil || from.String() != socket.LocalAddr().String() || !bytes.Equal(buffer[:n], packet) {
					t.Fatal("sampled UDP delivery changed its payload/source", err)
				}
			}
			report := StopFixturePacketTiming()
			d := report.Directions[fixturePacketTimingOutbound]
			c := d.Classes[fixturePacketTimingBusiness]
			if report.InvalidSamples != 0 || report.ClockErrors != 0 || d.Selected != 1 || d.Finished != 1 || d.Unfinished != 0 || c.Stages.Delivery.Count != 1 || c.Stages.OwnerTotal.Count != 1 {
				t.Fatal("writer sample lifecycle mismatch", d)
			}
			if (c.Outcomes.Delivered == 1) != (err == nil) || (c.Outcomes.DeliveryError == 1) != (err != nil) {
				t.Fatal("writer error was misclassified", c.Outcomes)
			}
			for stage, histogram := range c.UDPDelivery.histograms() {
				want := uint64(1)
				if (scenario == "stale generation" && stage >= fixtureTimingUDPDeadline) || (scenario == "closed UDP" && stage == fixtureTimingUDPWrite) {
					want = 0
				}
				assertPacketTimingHist(t, *histogram, want)
			}
		})
	}
}

func TestFixturePacketTimingUDPStagesLateEpochAndAtomicFailure(t *testing.T) {
	t.Run("late window", func(t *testing.T) {
		startPacketTimingTest(t, true)
		trace := beginFixturePacketTimingQueue(fixturePacketTimingOutbound)
		trace.Dequeue()
		trace.MarkAESBegin()
		trace.MarkAESEnd()
		trace.MarkDeliveryBegin()
		trace.MarkUDPWriterAcquired()
		frozen := StopFixturePacketTiming()
		original := frozen
		if err := StartFixturePacketTiming(true); err != nil {
			t.Fatal(err)
		}
		trace.MarkUDPValidationDone()
		trace.MarkUDPDeadlineDone()
		trace.MarkUDPWriteDone()
		trace.MarkDeliveryEnd()
		trace.Finish(fixturePacketTimingDelivered)
		next := StopFixturePacketTiming()
		if frozen != original || frozen.Directions[0].Unfinished != 1 || next.Directions[0].Selected != 0 || next.InvalidSamples != 0 {
			t.Fatal("late UDP sub-stages changed a frozen or later window")
		}
	})
	for _, failure := range []string{"order", "conversion overflow", "sum overflow"} {
		t.Run(failure, func(t *testing.T) {
			startPacketTimingTest(t, true)
			trace := beginFixturePacketTimingQueue(fixturePacketTimingOutbound)
			trace.Dequeue()
			trace.MarkAESBegin()
			trace.MarkAESEnd()
			trace.MarkDeliveryBegin()
			trace.Classify(fixturePacketTimingBusiness)
			if failure == "order" {
				trace.MarkUDPDeadlineDone()
			} else {
				trace.MarkUDPWriterAcquired()
				trace.MarkUDPValidationDone()
				trace.MarkUDPDeadlineDone()
				trace.MarkUDPWriteDone()
				run := activeFixturePacketTiming.Load()
				if failure == "conversion overflow" {
					trace.udpTicks[fixtureTimingUDPWrite] = math.MaxUint64
					run.clock.frequency = 1
				} else {
					// Force a nonzero child duration independent of QPC resolution.
					trace.udpTicks[fixtureTimingUDPWrite] = run.clock.frequency
					run.report.Directions[0].Classes[fixturePacketTimingBusiness].UDPDelivery.UDPWrite.SumNS = math.MaxUint64
				}
			}
			trace.MarkDeliveryEnd()
			trace.Finish(fixturePacketTimingDelivered)
			report := StopFixturePacketTiming()
			d := report.Directions[0]
			if report.InvalidSamples != 1 || d.Selected != 1 || d.Finished != 0 || d.Unfinished != 1 {
				t.Fatal("invalid UDP sub-stage was partly accepted", d)
			}
			for _, class := range d.Classes {
				if class.Outcomes != (FixturePacketTimingOutcomes{}) {
					t.Fatal("invalid UDP observation recorded an outcome")
				}
				for _, histogram := range class.Stages.histograms() {
					assertPacketTimingHist(t, *histogram, 0)
				}
				for _, histogram := range class.UDPDelivery.histograms() {
					assertPacketTimingHist(t, *histogram, 0)
				}
			}
		})
	}
}

func TestFixturePacketTimingUDPStagesRequireOutboundBusiness(t *testing.T) {
	for _, wrong := range []string{"unknown", "control", "inbound"} {
		t.Run(wrong, func(t *testing.T) {
			startPacketTimingTest(t, true)
			direction, class := fixturePacketTimingOutbound, fixturePacketTimingBusiness
			switch wrong {
			case "unknown":
				class = fixturePacketTimingUnknown
			case "control":
				class = fixturePacketTimingControl
			case "inbound":
				direction = fixturePacketTimingInbound
			}
			trace := beginFixturePacketTimingQueue(direction)
			trace.Dequeue()
			trace.MarkAESBegin()
			trace.MarkAESEnd()
			trace.MarkDeliveryBegin()
			trace.MarkUDPWriterAcquired()
			trace.MarkUDPValidationDone()
			trace.MarkUDPDeadlineDone()
			trace.MarkUDPWriteDone()
			trace.MarkDeliveryEnd()
			trace.Classify(class)
			trace.Finish(fixturePacketTimingDelivered)
			report := StopFixturePacketTiming()
			d := report.Directions[direction]
			if report.InvalidSamples != 1 || d.Selected != 1 || d.Finished != 0 || d.Unfinished != 1 {
				t.Fatal("UDP observations were recorded as inbound, unknown or control", d)
			}
			for _, c := range d.Classes {
				if c.Outcomes != (FixturePacketTimingOutcomes{}) {
					t.Fatal("invalid UDP direction/class recorded an outcome")
				}
				for _, histogram := range c.Stages.histograms() {
					assertPacketTimingHist(t, *histogram, 0)
				}
				for _, histogram := range c.UDPDelivery.histograms() {
					assertPacketTimingHist(t, *histogram, 0)
				}
			}
		})
	}
}

func TestFixturePacketTimingUDPParentDeliveryBudget(t *testing.T) {
	for _, scenario := range []string{"parent clock backwards", "child total above parent", "missing parent delivery", "owner clock backwards", "equal budget"} {
		t.Run(scenario, func(t *testing.T) {
			startPacketTimingTest(t, true)
			trace := beginFixturePacketTimingQueue(fixturePacketTimingOutbound)
			trace.Dequeue()
			trace.MarkAESBegin()
			trace.MarkAESEnd()
			trace.Classify(fixturePacketTimingBusiness)
			if scenario == "missing parent delivery" {
				// An inconsistent child record cannot invent a main delivery
				// interval. It must fail even when the child's duration is zero.
				trace.udpValid = 1 << fixtureTimingUDPWriter
			} else {
				trace.MarkDeliveryBegin()
				trace.MarkUDPWriterAcquired()
				trace.MarkUDPValidationDone()
				trace.MarkUDPDeadlineDone()
				trace.MarkUDPWriteDone()
				trace.MarkDeliveryEnd()
				// Use known scalar tick durations rather than timing-dependent
				// sleeps or a new injectable product clock. Each child is 1s;
				// conversion remains exact with both native QPC and fallback.
				frequency := activeFixturePacketTiming.Load().clock.frequency
				for stage := range trace.udpTicks {
					trace.udpTicks[stage] = frequency
				}
				switch scenario {
				case "parent clock backwards":
					// The stored parent end regressed one tick relative to its
					// last child end, while still being after the parent begin.
					trace.ticks[fixtureTimingDelivery] = 4*frequency - 1
				case "child total above parent":
					trace.ticks[fixtureTimingDelivery] = frequency
				case "equal budget":
					trace.ticks[fixtureTimingDelivery] = 4 * frequency
				case "owner clock backwards":
					trace.ticks[fixtureTimingDelivery] = 4 * frequency
					// The owner end must also be after the last main stage end.
					trace.mark = math.MaxInt64
				}
			}
			trace.Finish(fixturePacketTimingDelivered)
			report := StopFixturePacketTiming()
			d := report.Directions[fixturePacketTimingOutbound]
			if scenario == "equal budget" {
				if report.InvalidSamples != 0 || d.Finished != 1 || d.Unfinished != 0 {
					t.Fatal("exact child budget was incorrectly rejected", d)
				}
				c := d.Classes[fixturePacketTimingBusiness]
				for _, h := range c.UDPDelivery.histograms() {
					assertPacketTimingHist(t, *h, 1)
				}
				if c.Stages.Delivery.SumNS != 4_000_000_000 {
					t.Fatal("equal parent budget changed conversion")
				}
				return
			}
			if report.InvalidSamples != 1 || d.Selected != 1 || d.Finished != 0 || d.Unfinished != 1 {
				t.Fatal("invalid parent/child budget was partly accepted", d)
			}
			for _, c := range d.Classes {
				if c.Outcomes != (FixturePacketTimingOutcomes{}) {
					t.Fatal("invalid parent budget recorded an outcome")
				}
				for _, h := range c.Stages.histograms() {
					assertPacketTimingHist(t, *h, 0)
				}
				for _, h := range c.UDPDelivery.histograms() {
					assertPacketTimingHist(t, *h, 0)
				}
			}
		})
	}
}
