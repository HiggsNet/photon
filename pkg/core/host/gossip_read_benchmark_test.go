package host

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

// Match the existing state benchmark: 26 leaf zones, ten active records and
// eight versions per key. The observed peer has a real signed authority chain
// and endpoint, so the inbound benchmark retains authorization verification.
func gossipReadBenchmarkStore(b *testing.B, now time.Time) *corestate.Store {
	path := zone.ZonePath("peer.catofes.")
	network, _ := signedDiscoveryNetwork(b, path, true, []gossip.EndpointEntry{{
		Address: "203.0.113.1", Port: 33434, LastObserved: now.Unix(),
	}}, now)
	for i := 0; i < 26; i++ {
		p := path
		if i > 0 {
			p = zone.ZonePath(fmt.Sprintf("node-%d.catofes.", i))
			network.Zones[p] = zone.NewZoneState(p, &zone.ZoneAuthority{Zone: p, Epoch: 1, Threshold: 1})
		}
		zs := network.Zones[p]
		for j := 0; j < 10; j++ {
			key := fmt.Sprintf("record-%d", j)
			for v := uint64(1); v <= 8; v++ {
				r := &zone.Record{Zone: p, Key: key, Version: v, Value: make([]byte, 256),
					ValueHash: make([]byte, 32), PrevHash: make([]byte, 32), SignedBy: make([]byte, 32), Signature: make([]byte, 64)}
				zs.RecordHistory[key] = append(zs.RecordHistory[key], r)
				zs.Records[key] = r
			}
		}
	}
	return corestate.NewStore(&corestate.VerifiedState{ManagedZone: "local.catofes.", Network: network}, nil, nil)
}

var gossipReadBenchmarkResult any

func BenchmarkGossipReadPaths(b *testing.B) {
	now := time.Unix(1000, 0)
	store := gossipReadBenchmarkStore(b, now)
	driver := NewGossipDriver(NewClock(func() time.Time { return now }), DefaultEventBuffer, store, GossipDriverConfig{PeerID: "local.catofes."})
	defer driver.Stop()
	path := zone.ZonePath("peer.catofes.")
	transport, err := gossip.NewTransport(gossip.Config{PeerID: "local.catofes.", Clock: func() time.Time { return now }}, &memoryGossipDatagram{})
	if err != nil {
		b.Fatal(err)
	}
	packet := &gossip.Packet{Addr: &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 33434},
		Message: &gossip.Message{PeerID: path.String(), Type: gossip.MessagePing}}
	zoneRequest := &gossip.ObjectPullRequest{Type: gossip.ObjectPullZone, Zone: path}
	recordRequest := &gossip.ObjectPullRequest{Type: gossip.ObjectPullRecord, Zone: path, Key: "record-0", Version: 3}
	cases := []struct {
		name string
		run  func()
	}{
		{"discovery", func() { gossipReadBenchmarkResult = driver.GossipDiscoveryInput(nil) }},
		{"inbound_path", func() { driver.acceptGossipInboundPath(b.Context(), packet, now, nil, transport) }},
		{"tcp_zone", func() { gossipReadBenchmarkResult = driver.GossipObjectPullResponse(zoneRequest, now) }},
		{"tcp_record_history", func() { gossipReadBenchmarkResult = driver.GossipObjectPullResponse(recordRequest, now) }},
		{"udp_zone", func() {
			gossipReadBenchmarkResult = driver.gossipFetchZoneResponse(path, gossip.DefaultDatagramBudget, now)
		}},
	}
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			c.run()
			switch c.name {
			case "discovery":
				input := gossipReadBenchmarkResult.(GossipDiscoveryInput)
				if input.Network == nil || len(input.Network.Zones) != 28 {
					b.Fatal("discovery benchmark did not read the network")
				}
			case "inbound_path":
				if addr := transport.ObservedPeerAddr(path.String()); addr == nil || addr.String() != packet.Addr.String() {
					b.Fatal("inbound benchmark did not validate and publish the peer")
				}
			case "tcp_zone", "tcp_record_history":
				if response := gossipReadBenchmarkResult.(*gossip.ObjectPullResponse); !response.OK {
					b.Fatalf("object benchmark failed: %s", response.Error)
				}
			case "udp_zone":
				if response := gossipReadBenchmarkResult.(gossipFetchZoneResponse); !response.Found || response.Snapshot == nil || len(response.Plan.Announces) == 0 {
					b.Fatal("UDP benchmark did not build the requested object")
				}
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				c.run()
			}
		})
	}
}
