package photonwindows

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

// These benchmarks use the same signed authorities, IPAM assignments, gateway
// records, authenticated Babel route, installed directional ESP keys and real
// shared UDP sockets as the portable integration tests. Only the OS packet
// device is in memory. No authorization callback is replaced by an allow mock.
// A fixed fixture time isolates CPU/allocation cost from lease expiration.
// This is a serial event-path benchmark, not a network throughput claim.
func BenchmarkGatewayPacketPath(b *testing.B) {
	benchmarkGatewayPacketPath(b, false)
}

// The production serial daemon retains an immutable view for one verified
// revision and reuses successful signed policy only until its exact transition.
// Crypto, current SA/packet gates, real UDP and host delivery are still exercised.
func BenchmarkGatewayPacketSnapshotPath(b *testing.B) {
	benchmarkGatewayPacketPath(b, true)
}

func benchmarkGatewayPacketPath(b *testing.B, snapshot bool) {
	for _, outbound := range []bool{true, false} {
		direction := "Inbound"
		if outbound {
			direction = "Outbound"
		}
		for _, size := range []int{128, 1200} {
			b.Run(fmt.Sprintf("%s/%d", direction, size), func(b *testing.B) {
				f := newPipelineFixture(b)
				f.learn(b)
				f.view.State.ManagedZone = f.config.ManagedZone
				f.view.State.TrustedRootPublicKey = f.config.TrustedRootPublicKey
				store, err := corestate.RestoreStore(&corestate.CommitCandidate{Verified: f.view.State}, f.view.Revision, nil, nil)
				if err != nil {
					b.Fatal(err)
				}
				b.Cleanup(store.Close)
				readView := store.ReadView
				if snapshot {
					var owner packetStateView
					readView = func() corestate.View { return owner.read(store) }
				}
				submit := f.p.SubmitPacket
				accept := func(completion dataplaneCompletion) bool { return f.accept(b, completion) }
				if snapshot {
					submit = f.p.submitSnapshotPacket
					accept = func(completion dataplaneCompletion) bool {
						facts, ok := f.p.prepareSnapshot(f.config, f.view, f.plan, f.now)
						if !ok {
							return false
						}
						accepted, err := f.p.acceptPrepared(facts, completion)
						if err != nil {
							b.Fatal(err)
						}
						return accepted
					}
				}
				packet := make([]byte, size)
				copy(packet, f.packet(outbound))
				binary.BigEndian.PutUint16(packet[2:4], uint16(size))
				binary.BigEndian.PutUint16(packet[24:26], uint16(size-20))
				for n := 28; n < len(packet); n++ {
					packet[n] = byte(n)
				}
				buffer := make([]byte, 65536)
				// Drain setup Babel transmissions with a real business exchange.
				if !f.submitFromDevice(b, f.packet(true)) || !f.accept(b, f.businessCompletion(b)) {
					b.Fatal("benchmark fixture did not authorize business traffic")
				}
				f.receiveBusiness(b)
				b.SetBytes(int64(size))
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					// Each event reads the current verified revision. Snapshot
					// mode keeps one read-only view and exact bounded policy;
					// ordinary mode preserves detached-view semantics.
					f.view = readView()
					if outbound {
						if !submit(f.config, f.view, f.plan, f.now, packet) {
							b.Fatal("outbound rejected")
						}
						completion := dataplaneResult(b, f.p.tunnel.data)
						f.view = readView()
						if !accept(completion) {
							b.Fatal("outbound completion rejected")
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
							b.Fatalf("outbound ESP roundtrip failed: %v", err)
						}
					} else {
						completion := f.inboundCompletion(b, packet)
						f.view = readView()
						if !accept(completion) || len(f.device.written) != 1 || !bytes.Equal(f.device.written[0], packet) {
							b.Fatal("inbound ESP delivery failed")
						}
						f.device.written = f.device.written[:0]
					}
				}
			})
		}
	}
}

// Separate the detached state-copy cost from the verified packet-path profile.
// The small network is deliberately the same realistic signed fixture, not an
// empty Store; larger deployments should additionally profile their own state.
func BenchmarkGatewayPacketReadView(b *testing.B) {
	_, view, _, _ := gatewayPlanFixture(b)
	store := corestate.NewStore(view.State, nil, nil)
	b.Cleanup(store.Close)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if view := store.ReadView(); view.State == nil || len(view.State.Network.Zones) != 3 {
			b.Fatal("lost signed fixture state")
		}
	}
}

// This is the readiness calculation previously called by observeReady after
// every crypto completion, measured separately from packet authorization.
func BenchmarkGatewayPacketReady(b *testing.B) {
	f := newPipelineFixture(b)
	f.learn(b)
	store := corestate.NewStore(f.view.State, nil, nil)
	b.Cleanup(store.Close)
	runtime := &leafRuntime{pipeline: f.p}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if !runtime.ready(f.config, store.ReadView(), f.plan, f.now) {
			b.Fatal("authorized fixture is not ready")
		}
	}
}
