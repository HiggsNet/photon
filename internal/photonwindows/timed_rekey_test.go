package photonwindows

import (
	"context"
	"encoding/binary"
	"testing"
	"time"
)

// Keep the production five-minute deadlines intact. This is an optional real
// elapsed-time test, not a shortened lifetime or a manually triggered rekey.
func verifyMeshTimedRekey(t *testing.T, ctx context.Context, socket *packetSockets, tunnels []*gatewayTunnel) {
	t.Helper()
	type sample struct {
		generation                          uint64
		spi                                 uint32
		ike                                 [2]uint64
		sent, received, duplicates, expired int
		pending                             map[uint16]time.Time
		seen                                map[uint16]bool
		last                                time.Time
		maxGap                              time.Duration
	}
	start := time.Now()
	end := start.Add(5*time.Minute + 20*time.Second)
	samples := make([]sample, len(tunnels))
	for i, tunnel := range tunnels {
		if wait := tunnel.rekeyAt.Sub(start); wait < 5*time.Minute-10*time.Second || wait > 5*time.Minute {
			t.Fatal("production CHILD timer was shortened", wait)
		}
		a, b := tunnel.session.SPIs()
		samples[i] = sample{generation: tunnel.generation, spi: tunnel.child.InitiatorSPI, ike: [2]uint64{a, b}, pending: make(map[uint16]time.Time), seen: make(map[uint16]bool), last: start}
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	progress := time.NewTicker(time.Minute)
	defer progress.Stop()
	sequence := uint16(0)
	allow := func(i int, p []byte, outbound bool) bool {
		if len(p) != 28 || p[0] != 0x45 || p[9] != 1 || p[14] != byte(4+i) || p[18] != byte(4+i) || p[24] != 0 || p[25] != 1 {
			return false
		}
		if outbound {
			return p[15] == 2 && p[19] == 1 && p[20] == 8
		}
		return p[15] == 1 && p[19] == 2 && p[20] == 0
	}
	for time.Now().Before(end) {
		select {
		case packet := <-socket.ikePackets:
			for _, tunnel := range tunnels {
				if packet.generation != tunnel.generation {
					continue
				}
				if err := tunnel.handle(packet, tunnel.plan, time.Now()); err != nil {
					t.Fatal("timed IKE exchange", err)
				}
			}
		case packet := <-socket.espPackets:
			for i, tunnel := range tunnels {
				if packet.generation != tunnel.generation {
					continue
				}
				result, ok := tunnel.data.processOwnedInbound(packet.generation, tunnel.plan, packet.peer, packet.packet, packet.timing)
				if !ok {
					continue
				}
				tunnel.observeData(result, tunnel.plan, time.Now())
				plain, _, outbound, ok := tunnel.data.accept(result, tunnel.plan, func(p []byte, out bool) bool { return allow(i, p, out) })
				if !ok || outbound {
					t.Fatal("timed ESP delivery rejected")
				}
				seq := binary.BigEndian.Uint16(plain[26:28])
				sample := &samples[i]
				if sample.seen[seq] {
					sample.duplicates++
					continue
				}
				if _, sent := sample.pending[seq]; !sent {
					t.Fatal("reply to unsent or expired timed probe", i, seq)
				}
				delete(sample.pending, seq)
				sample.seen[seq] = true
				sample.received++
				now := time.Now()
				sample.maxGap = max(sample.maxGap, now.Sub(sample.last))
				sample.last = now
			}
		case now := <-ticker.C:
			sequence++
			for i, tunnel := range tunnels {
				if err := tunnel.tick(tunnel.plan, now); err != nil {
					t.Fatal("automatic timer failed", i, time.Since(start), err)
				}
				sample := &samples[i]
				for seq, sent := range sample.pending {
					if now.Sub(sent) > 3*time.Second {
						delete(sample.pending, seq)
						sample.expired++
					}
				}
				if now.Sub(sample.last) > 3*time.Second {
					t.Fatal("timed rekey interrupted peer traffic for over three seconds", i, time.Since(start))
				}
				if !now.Before(end.Add(-time.Second)) {
					continue
				}
				packet := meshTimedEcho(i, sequence)
				result, ok := tunnel.data.processOwnedOutbound(tunnel.generation, tunnel.plan, packet, func(p []byte, out bool) bool { return allow(i, p, out) }, fixturePacketTiming{})
				if !ok {
					t.Fatal("timed outbound encryption failed", i)
				}
				wire, endpoint, outbound, ok := tunnel.data.accept(result, tunnel.plan, func(p []byte, out bool) bool { return allow(i, p, out) })
				if !ok || !outbound {
					t.Fatal("timed outbound delivery rejected", i)
				}
				if err := socket.WriteTunnel(tunnel.generation, wire, endpoint); err != nil {
					t.Fatal(err)
				}
				sample.pending[sequence] = now
				sample.sent++
			}
		case <-progress.C:
			for i, tunnel := range tunnels {
				t.Logf("elapsed=%s peer=%d sent=%d received=%d rekeyed=%t", time.Since(start).Round(time.Second), i, samples[i].sent, samples[i].received, tunnel.child.InitiatorSPI != samples[i].spi)
			}
		case <-ctx.Done():
			t.Fatal("real five-minute rekey test timed out")
		}
	}
	for i, tunnel := range tunnels {
		sample := samples[i]
		a, b := tunnel.session.SPIs()
		if tunnel.generation != sample.generation || [2]uint64{a, b} != sample.ike {
			t.Fatal("CHILD rekey recreated the tunnel or IKE SA", i)
		}
		if tunnel.child.InitiatorSPI == sample.spi || tunnel.data.active.spi != tunnel.child.InitiatorSPI || len(tunnel.data.sas) != 1 {
			t.Fatal("timed CHILD did not switch and retire old keys", i)
		}
		if sample.received < 3000 || sample.duplicates != 0 || sample.maxGap > 3*time.Second || time.Since(sample.last) > 2*time.Second {
			t.Fatal("timed traffic continuity gate failed", i, sample.sent, sample.received, sample.maxGap)
		}
		t.Logf("peer=%d sent=%d unique=%d expired=%d outstanding=%d duplicates=%d max_reply_gap=%s generation_preserved=true ike_preserved=true child_replaced=true old_child_retired=true child_ke_group=%d", i, sample.sent, sample.received, sample.expired, len(sample.pending), sample.duplicates, sample.maxGap, tunnel.rekeyGroup)
	}
}

func meshTimedEcho(peer int, sequence uint16) []byte {
	packet := make([]byte, 28)
	packet[0], packet[8], packet[9] = 0x45, 64, 1
	binary.BigEndian.PutUint16(packet[2:4], 28)
	copy(packet[12:16], []byte{10, 55, 4, 2})
	copy(packet[16:20], []byte{10, 55, 4, 1})
	packet[20], packet[25] = 8, 1
	packet[14], packet[18] = byte(4+peer), byte(4+peer)
	binary.BigEndian.PutUint16(packet[26:28], sequence)
	for _, span := range [][2]int{{0, 20}, {20, 28}} {
		offset := span[0] + 2
		if span[0] == 0 {
			offset = 10
		}
		packet[offset], packet[offset+1] = 0, 0
		var sum uint32
		for i := span[0]; i < span[1]; i += 2 {
			sum += uint32(binary.BigEndian.Uint16(packet[i:]))
		}
		for sum>>16 != 0 {
			sum = (sum & 65535) + (sum >> 16)
		}
		binary.BigEndian.PutUint16(packet[offset:offset+2], ^uint16(sum))
	}
	return packet
}
