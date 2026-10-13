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
					// Mirror the daemon's detached current view at each event;
					// crypto completion uses a fresh view, never a submission grant.
					f.view = store.ReadView()
					if outbound {
						if !f.p.SubmitPacket(f.config, f.view, f.plan, f.now, packet) {
							b.Fatal("outbound rejected")
						}
						completion := dataplaneResult(b, f.p.tunnel.data)
						f.view = store.ReadView()
						if !f.accept(b, completion) {
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
						f.view = store.ReadView()
						if !f.accept(b, completion) || len(f.device.written) != 1 || !bytes.Equal(f.device.written[0], packet) {
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
