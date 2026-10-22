package gossip

import (
	"errors"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/vmihailenco/msgpack/v5"
)

type testUDPDatagram struct {
	conn *net.UDPConn
}

func listenTestTransport(listenAddr string, config Config) (*Transport, error) {
	addr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}
	transport, err := NewTransport(config, &testUDPDatagram{conn: conn})
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return transport, nil
}

func (io *testUDPDatagram) ReadDatagram(buffer []byte) (int, *net.UDPAddr, error) {
	return io.conn.ReadFromUDP(buffer)
}

func (io *testUDPDatagram) WriteDatagram(payload []byte, addr *net.UDPAddr) (int, error) {
	return io.conn.WriteToUDP(payload, addr)
}

func (io *testUDPDatagram) LocalAddr() *net.UDPAddr {
	addr, _ := io.conn.LocalAddr().(*net.UDPAddr)
	return addr
}

func (io *testUDPDatagram) SetReadDeadline(deadline time.Time) error {
	return io.conn.SetReadDeadline(deadline)
}

func (io *testUDPDatagram) Close() error {
	return io.conn.Close()
}

func TestNewTransportRequiresIdentityAndDatagramIO(t *testing.T) {
	if _, err := NewTransport(Config{}, nil); err == nil || err.Error() != "local gossip peer id is empty" {
		t.Fatalf("empty peer error = %v", err)
	}
	if _, err := NewTransport(Config{PeerID: "node-a"}, nil); !errors.Is(err, ErrDatagramIORequired) {
		t.Fatalf("nil datagram error = %v, want %v", err, ErrDatagramIORequired)
	}
}

func TestAddKnownPeerID(t *testing.T) {
	transport, err := listenTestTransport("127.0.0.1:0", Config{
		PeerID: "test-local",
	})
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("Listen: %v", err)
	}
	defer transport.Close()

	transport.AddKnownPeerID("peer-a")

	found := slices.Contains(transport.KnownPeerIDs(), "peer-a")
	if !found {
		t.Fatalf("KnownPeerIDs() does not contain peer-a")
	}

	if transport.PeerAddr("peer-a") != nil {
		t.Fatalf("PeerAddr(peer-a) should be nil when only AddKnownPeerID is used")
	}
}

func TestAddKnownPeerIDDoesNotAffectAddPeer(t *testing.T) {
	transport, err := listenTestTransport("127.0.0.1:0", Config{
		PeerID: "test-local",
	})
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("Listen: %v", err)
	}
	defer transport.Close()

	transport.AddKnownPeerID("peer-a")
	transport.AddPeer("peer-b", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234})

	ids := transport.KnownPeerIDs()
	if len(ids) != 2 {
		t.Fatalf("KnownPeerIDs() = %v, want 2 entries", ids)
	}

	if transport.PeerAddr("peer-a") != nil {
		t.Fatalf("PeerAddr(peer-a) should be nil")
	}
	if transport.PeerAddr("peer-b") == nil {
		t.Fatalf("PeerAddr(peer-b) should not be nil")
	}
}

func TestSendToUsesExplicitReplyAddressOverConfiguredOutbound(t *testing.T) {
	receiver, err := listenTestTransport("127.0.0.1:0", Config{
		PeerID:     "peer-a",
		KnownPeers: map[string]*net.UDPAddr{"peer-b": nil},
	})
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("Listen(receiver): %v", err)
	}
	defer receiver.Close()

	sender, err := listenTestTransport("127.0.0.1:0", Config{
		PeerID: "peer-b",
		KnownPeers: map[string]*net.UDPAddr{
			"peer-a": {IP: net.ParseIP("192.0.2.10"), Port: 33434},
		},
	})
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("Listen(sender): %v", err)
	}
	defer sender.Close()

	if err := sender.SendTo("peer-a", receiver.LocalAddr(), &Message{Type: MessagePing, Ping: &Ping{}}); err != nil {
		t.Fatalf("SendTo: %v", err)
	}
	if err := receiver.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	packet, err := receiver.Receive()
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if packet.Message.Type != MessagePing || packet.Message.PeerID != "peer-b" {
		t.Fatalf("packet = %#v, want ping from peer-b", packet.Message)
	}
}

func TestRemovePeerAddrsKeepsKnownPeerID(t *testing.T) {
	transport := &Transport{}
	transport.SetPeerAddrs("peer-a", []*net.UDPAddr{{IP: net.ParseIP("127.0.0.1"), Port: 1234}})

	transport.RemovePeerAddrs("peer-a")

	if addr := transport.PeerAddr("peer-a"); addr != nil {
		t.Fatalf("PeerAddr(peer-a) = %v, want nil", addr)
	}
	if err := transport.validatePeer("peer-a"); err != nil {
		t.Fatalf("validatePeer(peer-a): %v", err)
	}
}

func TestObservedPeerAddrExpiresAndIsRemovedWithPeer(t *testing.T) {
	now := time.Unix(100, 0)
	transport := &Transport{clock: func() time.Time { return now }}
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}

	transport.SetObservedPeerAddr("peer-a", addr, now.Add(time.Minute), true)
	if got := transport.ObservedPeerAddr("peer-a"); got == nil || got.String() != "127.0.0.1:1234" {
		t.Fatalf("ObservedPeerAddr = %v, want 127.0.0.1:1234", got)
	}
	transport.SetObservedPeerPaths("peer-a", []ObservedPath{
		{Addr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 2000}, Until: now.Add(time.Minute)},
		{Addr: addr, Until: now.Add(30 * time.Second)},
	}, true)
	if got := transport.ObservedPeerAddrs("peer-a"); len(got) != 2 || got[0].String() != "127.0.0.1:2000" || got[1].String() != "127.0.0.1:1234" {
		t.Fatalf("ObservedPeerAddrs = %v, want primary plus grace", got)
	}

	now = now.Add(45 * time.Second)
	if got := transport.ObservedPeerAddrs("peer-a"); len(got) != 1 || got[0].String() != "127.0.0.1:2000" {
		t.Fatalf("ObservedPeerAddrs after grace expiry = %v, want only primary", got)
	}

	now = now.Add(2 * time.Minute)
	if got := transport.ObservedPeerAddr("peer-a"); got != nil {
		t.Fatalf("ObservedPeerAddr after expiry = %v, want nil", got)
	}

	now = time.Unix(100, 0)
	transport.SetObservedPeerAddr("peer-a", addr, now.Add(time.Minute), true)
	transport.RemovePeer("peer-a")
	if got := transport.ObservedPeerAddr("peer-a"); got != nil {
		t.Fatalf("ObservedPeerAddr after RemovePeer = %v, want nil", got)
	}
}

func TestReceiveRejectsMessageTooLarge(t *testing.T) {
	transport, err := listenTestTransport("127.0.0.1:0", Config{
		PeerID:          "node-b",
		MaxMessageBytes: 8,
	})
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("Listen: %v", err)
	}
	defer transport.Close()

	sender, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("ListenUDP(sender): %v", err)
	}
	defer sender.Close()

	if _, err := sender.WriteToUDP([]byte("0123456789"), transport.LocalAddr()); err != nil {
		t.Fatalf("WriteToUDP: %v", err)
	}
	if _, err := transport.Receive(); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("Receive = %v, want ErrMessageTooLarge", err)
	}
}

func TestReceiveRejectsQuotaExceeded(t *testing.T) {
	now := time.Unix(1000, 0)
	var event Event
	transport, err := listenTestTransport("127.0.0.1:0", Config{
		PeerID: "node-b",
		KnownPeers: map[string]*net.UDPAddr{
			"node-a": nil,
		},
		Quotas: NewPeerQuotas(QuotaConfig{
			ByteRate:    1,
			ByteBurst:   1,
			ObjectRate:  1,
			ObjectBurst: 1,
		}),
		Clock: func() time.Time { return now },
		Log: func(e Event) {
			event = e
		},
	})
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("Listen: %v", err)
	}
	defer transport.Close()

	if err := sendRawMessage(transport.LocalAddr(), &Message{
		Version:   WireVersion,
		Type:      MessagePing,
		PeerID:    "node-a",
		Nonce:     1,
		Timestamp: now.Unix(),
		Ping:      &Ping{},
	}); err != nil {
		t.Fatalf("sendRawMessage: %v", err)
	}
	if _, err := transport.Receive(); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("Receive = %v, want ErrQuotaExceeded", err)
	}
	if event.Reason != "quota" || event.QuotaRequestedBytes == 0 || event.QuotaAvailableBytes != 1 || event.QuotaObjectBurst != 1 {
		t.Fatalf("quota event = %#v, want reason and quota diagnostics", event)
	}
}

func TestReceiveRejectsReplay(t *testing.T) {
	now := time.Unix(1000, 0)
	transport, err := listenTestTransport("127.0.0.1:0", Config{
		PeerID: "node-b",
		KnownPeers: map[string]*net.UDPAddr{
			"node-a": nil,
		},
		Replay: NewReplayWindow(time.Minute),
		Clock:  func() time.Time { return now },
	})
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("Listen: %v", err)
	}
	defer transport.Close()

	message := &Message{
		Version:   WireVersion,
		Type:      MessagePing,
		PeerID:    "node-a",
		Nonce:     7,
		Timestamp: now.Unix(),
		Ping:      &Ping{},
	}
	if err := sendRawMessage(transport.LocalAddr(), message); err != nil {
		t.Fatalf("sendRawMessage(first): %v", err)
	}
	if packet, err := transport.Receive(); err != nil || packet.Message.Nonce != 7 {
		t.Fatalf("Receive(first) = packet %#v, err %v; want nonce 7", packet, err)
	}
	if err := sendRawMessage(transport.LocalAddr(), message); err != nil {
		t.Fatalf("sendRawMessage(second): %v", err)
	}
	if _, err := transport.Receive(); !errors.Is(err, ErrReplay) {
		t.Fatalf("Receive(second) = %v, want ErrReplay", err)
	}
}

func TestReceiveRejectsUnsupportedWireVersion(t *testing.T) {
	now := time.Unix(1000, 0)
	transport, err := listenTestTransport("127.0.0.1:0", Config{
		PeerID: "node-b",
		KnownPeers: map[string]*net.UDPAddr{
			"node-a": nil,
		},
		Clock: func() time.Time { return now },
	})
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("Listen: %v", err)
	}
	defer transport.Close()

	data, err := rawWireMessage(&Message{
		Version:   WireVersion + 1,
		Type:      MessagePing,
		PeerID:    "node-a",
		Nonce:     1,
		Timestamp: now.Unix(),
		Ping:      &Ping{},
	})
	if err != nil {
		t.Fatalf("rawWireMessage: %v", err)
	}
	if err := sendRawBytes(transport.LocalAddr(), data); err != nil {
		t.Fatalf("sendRawBytes: %v", err)
	}
	if _, err := transport.Receive(); RejectReason(err) != "unsupported_wire_version" {
		t.Fatalf("Receive = %v, reason %q; want unsupported_wire_version", err, RejectReason(err))
	}
}

func TestRejectReasonCoversAddrMismatch(t *testing.T) {
	if got := RejectReason(ErrAddrMismatch); got != "addr_mismatch" {
		t.Fatalf("RejectReason(ErrAddrMismatch) = %q, want addr_mismatch", got)
	}
}

func sendRawMessage(addr *net.UDPAddr, message *Message) error {
	data, err := MarshalMessage(message)
	if err != nil {
		return err
	}
	return sendRawBytes(addr, data)
}

func sendRawBytes(addr *net.UDPAddr, data []byte) error {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.WriteToUDP(data, addr)
	return err
}

func rawWireMessage(message *Message) ([]byte, error) {
	payload, err := msgpack.Marshal(message)
	if err != nil {
		return nil, err
	}
	data := append([]byte(nil), wireMagicMsgpack...)
	data = append(data, payload...)
	return data, nil
}

func TestReceiveTimeoutIsNotLogged(t *testing.T) {
	var logged bool
	transport, err := listenTestTransport("127.0.0.1:0", Config{
		PeerID: "test-local",
		Log: func(event Event) {
			logged = true
		},
	})
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("Listen: %v", err)
	}
	defer transport.Close()

	if err := transport.SetReadDeadline(time.Now().Add(10 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if _, err := transport.Receive(); err == nil {
		t.Fatalf("Receive should have timed out")
	}
	if logged {
		t.Fatalf("timeout error was logged, want no log")
	}
}

func TestSendPrefersSuccessfulAddrAndDeprioritizesBackoff(t *testing.T) {
	now := time.Unix(1000, 0)
	transport := &Transport{
		clock:           func() time.Time { return now },
		maxMessageBytes: DefaultMaxMessage,
	}
	transport.SetPeerAddrs("peer-a", []*net.UDPAddr{
		{IP: net.ParseIP("203.0.113.10"), Port: 1234},
		{IP: net.ParseIP("127.0.0.1"), Port: 1234},
	})

	// Initially both addresses are unknown; order is preserved.
	addrs := transport.sendAddrsFor("peer-a")
	if len(addrs) != 2 {
		t.Fatalf("sendAddrsFor = %d addrs, want 2", len(addrs))
	}

	// Mark the public address as failing.
	transport.RecordAddrFailure("peer-a", &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 1234})
	transport.RecordAddrFailure("peer-a", &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 1234})

	addrs = transport.sendAddrsFor("peer-a")
	if addrs[0].IP.String() != "127.0.0.1" {
		t.Fatalf("first addr after backoff = %v, want 127.0.0.1", addrs[0])
	}

	// Mark loopback as successful; it should stay at the front.
	transport.RecordAddrSuccess("peer-a", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234})
	addrs = transport.sendAddrsFor("peer-a")
	if addrs[0].IP.String() != "127.0.0.1" {
		t.Fatalf("first addr after success = %v, want 127.0.0.1", addrs[0])
	}

	// After the backoff expires, the public address moves back up.
	now = now.Add(addrFailureBackoffMax).Add(time.Second)
	addrs = transport.sendAddrsFor("peer-a")
	if addrs[0].IP.String() != "127.0.0.1" {
		t.Fatalf("first addr after backoff expiry should still prefer successful addr")
	}
}

func TestSendOrdersByReachabilityRank(t *testing.T) {
	now := time.Unix(1000, 0)
	transport := &Transport{
		clock:           func() time.Time { return now },
		maxMessageBytes: DefaultMaxMessage,
	}
	transport.SetPeerAddrs("peer-a", []*net.UDPAddr{
		{IP: net.ParseIP("127.0.0.1"), Port: 1000},
		{IP: net.ParseIP("127.0.0.1"), Port: 1001},
		{IP: net.ParseIP("127.0.0.1"), Port: 1002},
	})

	addrs := transport.sendAddrsFor("peer-a")
	if len(addrs) != 3 {
		t.Fatalf("sendAddrsFor = %d addrs, want 3", len(addrs))
	}

	// Mark the second address as recently successful; it should move to front.
	transport.RecordAddrSuccess("peer-a", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1001})
	addrs = transport.sendAddrsFor("peer-a")
	if addrs[0].Port != 1001 {
		t.Fatalf("first addr = %v, want port 1001", addrs[0])
	}
}

func TestReceiveRecordsAddrSuccess(t *testing.T) {
	now := time.Unix(1000, 0)
	transport, err := listenTestTransport("127.0.0.1:0", Config{
		PeerID: "node-b",
		KnownPeers: map[string]*net.UDPAddr{
			"node-a": nil,
		},
		Clock: func() time.Time { return now },
	})
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("Listen: %v", err)
	}
	defer transport.Close()

	message := &Message{
		Version:   WireVersion,
		Type:      MessagePing,
		PeerID:    "node-a",
		Nonce:     1,
		Timestamp: now.Unix(),
		Ping:      &Ping{},
	}
	if err := sendRawMessage(transport.LocalAddr(), message); err != nil {
		t.Fatalf("sendRawMessage: %v", err)
	}
	packet, err := transport.Receive()
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if transport.AddrFailureCount("node-a", packet.Addr) != 0 {
		t.Fatalf("failure count after receive = %d, want 0", transport.AddrFailureCount("node-a", packet.Addr))
	}
	transport.SetPeerAddrs("node-a", []*net.UDPAddr{{IP: net.ParseIP("192.0.2.10"), Port: 33434}})
	addrs := transport.sendAddrsFor("node-a")
	if len(addrs) != 2 || addrs[0].String() != packet.Addr.String() {
		t.Fatalf("send addresses after receive = %v, want recent inbound %v first", addrs, packet.Addr)
	}

	now = now.Add(recentInboundPathTTL)
	addrs = transport.sendAddrsFor("node-a")
	if len(addrs) != 1 || addrs[0].String() != "192.0.2.10:33434" {
		t.Fatalf("send addresses after recent path expiry = %v, want configured address", addrs)
	}
}

func TestLastSendAddr(t *testing.T) {
	transportA, err := listenTestTransport("127.0.0.1:0", Config{PeerID: "node-a"})
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("Listen: %v", err)
	}
	defer transportA.Close()
	transportB, err := listenTestTransport("127.0.0.1:0", Config{PeerID: "node-b"})
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("Listen: %v", err)
	}
	defer transportB.Close()

	transportA.SetPeerAddrs("node-b", []*net.UDPAddr{transportB.LocalAddr()})
	if err := transportA.Send("node-b", &Message{Type: MessagePing, Ping: &Ping{}}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if got := transportA.LastSendAddr("node-b"); got == nil || got.String() != transportB.LocalAddr().String() {
		t.Fatalf("LastSendAddr = %v, want %v", got, transportB.LocalAddr())
	}
}

func TestRemovePeerClearsAddrState(t *testing.T) {
	transport := &Transport{clock: time.Now}
	transport.SetPeerAddrs("peer-a", []*net.UDPAddr{{IP: net.ParseIP("127.0.0.1"), Port: 1234}})
	transport.RecordAddrSuccess("peer-a", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234})
	transport.recentInbound = map[string]recentInboundPath{
		"peer-a": {
			Addr:  &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 4321},
			Until: time.Now().Add(time.Minute),
		},
	}
	transport.RemovePeer("peer-a")
	if transport.LastSendAddr("peer-a") != nil {
		t.Fatalf("LastSendAddr after RemovePeer should be nil")
	}
	if transport.activeRecentInboundPath("peer-a") != nil {
		t.Fatalf("recent inbound path after RemovePeer should be nil")
	}
}

type datagramReadResult struct {
	DatagramIO
	n   int
	err error
}

func (d datagramReadResult) ReadDatagram([]byte) (int, *net.UDPAddr, error) {
	return d.n, nil, d.err
}

func TestReceiveClassifiesOversizedDataEvenWithReadError(t *testing.T) {
	readErr := errors.New("datagram was truncated by the socket")
	for _, n := range []int{0, 9} {
		var event Event
		transport, err := NewTransport(Config{PeerID: "node", MaxMessageBytes: 8, Log: func(e Event) { event = e }}, datagramReadResult{n: n, err: readErr})
		if err != nil {
			t.Fatal(err)
		}
		_, err = transport.Receive()
		if n == 0 {
			if !errors.Is(err, readErr) {
				t.Fatalf("ordinary read error changed: %v", err)
			}
		} else if !errors.Is(err, ErrMessageTooLarge) || event.Reason != "message_too_large" || event.Bytes != n {
			t.Fatalf("oversize error/event=%v/%#v", err, event)
		}
	}
}
