package host

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

type memoryGossipDatagram struct {
	mu         sync.Mutex
	writes     [][]byte
	writeAddrs []*net.UDPAddr
	addr       *net.UDPAddr
}

func (datagram *memoryGossipDatagram) ReadDatagram([]byte) (int, *net.UDPAddr, error) {
	return 0, nil, net.ErrClosed
}

func (datagram *memoryGossipDatagram) WriteDatagram(payload []byte, addr *net.UDPAddr) (int, error) {
	datagram.mu.Lock()
	datagram.writes = append(datagram.writes, append([]byte(nil), payload...))
	datagram.writeAddrs = append(datagram.writeAddrs, appendUDPAddrCopy(addr))
	datagram.mu.Unlock()
	return len(payload), nil
}

func (datagram *memoryGossipDatagram) LocalAddr() *net.UDPAddr { return datagram.addr }
func (*memoryGossipDatagram) SetReadDeadline(time.Time) error  { return nil }
func (*memoryGossipDatagram) Close() error                     { return nil }

func (datagram *memoryGossipDatagram) writeCount() int {
	datagram.mu.Lock()
	defer datagram.mu.Unlock()
	return len(datagram.writes)
}

func (datagram *memoryGossipDatagram) lastWrite() ([]byte, *net.UDPAddr) {
	datagram.mu.Lock()
	defer datagram.mu.Unlock()
	if len(datagram.writes) == 0 {
		return nil, nil
	}
	index := len(datagram.writes) - 1
	return append([]byte(nil), datagram.writes[index]...), appendUDPAddrCopy(datagram.writeAddrs[index])
}

func appendUDPAddrCopy(addr *net.UDPAddr) *net.UDPAddr {
	if addr == nil {
		return nil
	}
	copy := *addr
	copy.IP = append(net.IP(nil), addr.IP...)
	return &copy
}

func bindMemoryGossipTransport(t *testing.T, driver *GossipDriver, peerIDs ...string) (*gossip.Transport, *memoryGossipDatagram) {
	t.Helper()
	datagram := &memoryGossipDatagram{addr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 33434}}
	known := make(map[string]*net.UDPAddr, len(peerIDs))
	for _, peerID := range peerIDs {
		known[peerID] = &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 33435}
	}
	transport, err := gossip.NewTransport(gossip.Config{PeerID: "local.catofes.", KnownPeers: known}, datagram)
	if err != nil {
		t.Fatal(err)
	}
	if err := driver.BindGossipTransport(transport); err != nil {
		t.Fatal(err)
	}
	return transport, datagram
}

func TestGossipDriverRepliesToUnverifiedPeerAtInboundAddress(t *testing.T) {
	now := time.Unix(1000, 0)
	peerID := "unverified.catofes."
	state := &memoryGossipStateStore{views: []corestate.View{loadedGossipState()}}
	driver := NewGossipDriver(newFakeClock(now), 1, state, GossipDriverConfig{PeerID: "local.catofes."})
	defer driver.Stop()
	_, datagram := bindMemoryGossipTransport(t, driver, peerID)
	inboundAddr := &net.UDPAddr{IP: net.ParseIP("198.51.100.20"), Port: 33434}

	result, err := driver.HandleGossipHostEvent(context.Background(), GossipPacketReceived{Packet: &gossip.Packet{
		Message: &gossip.Message{Type: gossip.MessagePing, PeerID: peerID, Ping: &gossip.Ping{}},
		Addr:    inboundAddr,
	}}, now, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Handled {
		t.Fatal("inbound ping was not handled")
	}
	payload, addr := datagram.lastWrite()
	if addr == nil || addr.String() != inboundAddr.String() {
		t.Fatalf("reply addr = %v, want inbound %v", addr, inboundAddr)
	}
	reply, err := gossip.UnmarshalMessage(payload)
	if err != nil {
		t.Fatalf("decode reply: %v", err)
	}
	if reply.Type != gossip.MessagePong || reply.Pong == nil {
		t.Fatalf("reply = %#v, want pong", reply)
	}
}
