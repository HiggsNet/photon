//go:build photon_profile

package photonwindows

import "sync/atomic"

// FixturePacketDrops contains process totals for only the three bounded packet
// ingress queues. It carries no packets, peer identities or authorization data.
// These diagnostics exist only in the profiling fixture build.
type FixturePacketDrops struct {
	RawIngress  uint64
	LeafIngress uint64
	ESPIngress  uint64
}

var rawIngressDrops atomic.Uint64
var leafIngressDrops atomic.Uint64
var espIngressDrops atomic.Uint64

func recordRawIngressDrop()  { rawIngressDrops.Add(1) }
func recordLeafIngressDrop() { leafIngressDrops.Add(1) }
func recordESPIngressDrop()  { espIngressDrops.Add(1) }

// ReadFixturePacketDrops snapshots cumulative drop counts. Each counter is
// read atomically; callers subtract an earlier snapshot instead of resetting
// counters concurrently with packet readers. ESP counts wire queue rejection
// before authentication, not a loss of already authenticated business traffic.
func ReadFixturePacketDrops() FixturePacketDrops {
	return FixturePacketDrops{
		RawIngress:  rawIngressDrops.Load(),
		LeafIngress: leafIngressDrops.Load(),
		ESPIngress:  espIngressDrops.Load(),
	}
}
