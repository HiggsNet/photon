package babel

import (
	"net/netip"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/photonclient/sadr"
)

var neighborLocal = netip.MustParseAddr("fe80::1")
var neighborPeer = netip.MustParseAddr("fe80::2")

func neighborPacket(t *testing.T, m ...Message) []byte {
	t.Helper()
	payload, err := Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := BuildPacket(neighborPeer, neighborLocal, payload)
	if err != nil {
		t.Fatal(err)
	}
	return packet
}
func neighborUp(t *testing.T, l *Leaf, now time.Time) {
	t.Helper()
	_, err := l.Receive(neighborPacket(t, Message{Type: TLVHello, Seqno: 1, Interval: 400}, Message{Type: TLVIHU, Address: neighborLocal, Metric: 100, Interval: 400}), now, allowCandidate)
	if err != nil {
		t.Fatal(err)
	}
}
func allowCandidate(sadr.Route) bool { return true }
func leafForTest(t *testing.T) (*Leaf, time.Time) {
	t.Helper()
	l, err := NewLeaf(neighborLocal, neighborPeer, [8]byte{1}, 100)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(100, 0)
	neighborUp(t, l, now)
	return l, now
}
func remoteUpdate() Message {
	return Message{Type: TLVUpdate, Prefix: netip.MustParsePrefix("2001:db8::/64"), SourcePrefix: netip.MustParsePrefix("2001:db8:1::/64"), RouterID: [8]byte{2}, NextHop: neighborPeer, Seqno: 65535, Metric: 50, Interval: 100}
}
func receiveLeaf(t *testing.T, l *Leaf, now time.Time, m ...Message) []Message {
	t.Helper()
	out, err := l.Receive(neighborPacket(t, m...), now, allowCandidate)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestNeighborLeasesHelloWrapAndUnscheduled(t *testing.T) {
	n, _ := NewNeighbor(neighborLocal, neighborPeer, 100)
	now := time.Unix(100, 0)
	send := func(at time.Time, m ...Message) {
		t.Helper()
		if _, err := n.Receive(neighborPacket(t, m...), at); err != nil {
			t.Fatal(err)
		}
	}
	send(now, Message{Type: TLVHello, Seqno: 65535, Interval: 100}, Message{Type: TLVIHU, Metric: 200, Interval: 100})
	if n.Cost(now) != 200 {
		t.Fatal("bidirectional link missing")
	}
	send(now.Add(time.Second), Message{Type: TLVHello, Seqno: 0, Interval: 100})
	deadline := n.hello[0].expires
	send(now.Add(2*time.Second), Message{Type: TLVHello, Seqno: 0, Interval: 6000}, Message{Type: TLVHello, Seqno: 65535, Interval: 6000})
	if n.hello[0].expires != deadline {
		t.Fatal("old hello refreshed")
	}
	send(now.Add(3*time.Second), Message{Type: TLVHello, Seqno: 1, Interval: 0}, Message{Type: TLVIHU, Metric: 200, Interval: 100})
	if n.hello[0].expires != deadline {
		t.Fatal("unscheduled hello extended promise")
	}
	if n.Cost(deadline) != MetricInfinity {
		t.Fatal("hello boundary not expired")
	}
	send(deadline, Message{Type: TLVHello, Unicast: true, Seqno: 7, Interval: 100})
	if n.Cost(deadline) != 200 {
		t.Fatal("unicast hello did not establish reachability")
	}
	if n.Cost(now.Add(6500*time.Millisecond)) != MetricInfinity {
		t.Fatal("IHU exact deadline retained")
	}
	// An IHU addressed to another peer cannot establish bidirectionality.
	n, _ = NewNeighbor(neighborLocal, neighborPeer, 100)
	send(now, Message{Type: TLVHello, Interval: 100}, Message{Type: TLVIHU, Address: netip.MustParseAddr("fe80::3"), Metric: 100, Interval: 100})
	if n.Cost(now) != MetricInfinity {
		t.Fatal("wrong IHU target accepted")
	}
	if len(n.Tick(now)) == 0 || len(n.Tick(now.Add(time.Second))) != 0 || len(n.Tick(now.Add(time.Hour))) > 3 {
		t.Fatal("periodic burst")
	}
}

func TestNeighborFramingIsAtomicAndAckIsBounded(t *testing.T) {
	l, now := leafForTest(t)
	p := neighborPacket(t, Message{Type: TLVHello, Seqno: 2, Interval: 6000})
	p[len(p)-1] ^= 1
	if _, err := l.Receive(p, now, allowCandidate); err == nil {
		t.Fatal("corrupt packet accepted")
	}
	if l.neighbor.hello[0].seqno != 1 {
		t.Fatal("mutated before checksum validation")
	}
	messages := make([]Message, MaxMessages)
	for i := range messages {
		messages[i] = Message{Type: TLVAckRequest, Opaque: uint16(i), Interval: 1}
	}
	out := receiveLeaf(t, l, now, messages...)
	if len(out) != MaxMessages {
		t.Fatal("not all bounded ACK requests answered", len(out))
	}
	for i, m := range out {
		if m.Type != TLVAck || m.Opaque != uint16(i) {
			t.Fatal(m)
		}
	}
}

func TestLeafRoutesExpiryWithdrawalSequenceAndAuthorization(t *testing.T) {
	l, now := leafForTest(t)
	m := remoteUpdate()
	receiveLeaf(t, l, now, m)
	got := l.Candidates(now, allowCandidate)
	if len(got) != 1 || got[0].Metric != 150 || got[0].Source != m.SourcePrefix {
		t.Fatal(got)
	}
	m.Seqno = 0
	m.Metric = 60
	receiveLeaf(t, l, now.Add(time.Second), m)
	m.Seqno = 65535
	m.Metric = 1
	receiveLeaf(t, l, now.Add(2*time.Second), m)
	if got = l.Candidates(now.Add(2*time.Second), allowCandidate); len(got) != 1 || got[0].Metric != 160 {
		t.Fatal("old sequence replaced wrap", got)
	}
	refresh := l.Tick(now.Add(4 * time.Second))
	found := false
	for _, r := range refresh {
		if r.Type == TLVRouteRequest && r.Prefix == m.Prefix && r.SourcePrefix == m.SourcePrefix {
			found = true
		}
	}
	if !found {
		t.Fatal("missing pre-expiry request")
	}
	if len(l.Candidates(now.Add(4500*time.Millisecond), allowCandidate)) != 0 {
		t.Fatal("exact expiry retained")
	}
	receiveLeaf(t, l, now, m)
	m.Metric = MetricInfinity
	receiveLeaf(t, l, now, m)
	if len(l.Candidates(now, allowCandidate)) != 0 {
		t.Fatal("retraction ignored")
	}
	m.Metric = 50
	receiveLeaf(t, l, now, m)
	receiveLeaf(t, l, now, Message{Type: TLVUpdate, Wildcard: true, Metric: MetricInfinity, Interval: 100})
	if len(l.Candidates(now, allowCandidate)) != 0 {
		t.Fatal("wildcard retraction ignored")
	}
	receiveLeaf(t, l, now, m)
	if len(l.Candidates(now, nil)) != 0 || len(l.Candidates(now, allowCandidate)) != 0 {
		t.Fatal("revoked route revived")
	}
	m.RouterID = l.routerID
	receiveLeaf(t, l, now, m)
	if len(l.Candidates(now, allowCandidate)) != 0 {
		t.Fatal("own origin loop accepted")
	}
}

func TestLeafLocalOnlyRequestsPeriodicAndRetraction(t *testing.T) {
	l, now := leafForTest(t)
	remote := remoteUpdate()
	receiveLeaf(t, l, now, remote)
	o := Origin{Prefix: netip.MustParsePrefix("10.0.0.0/24")}
	changes, err := l.SetLocal([]Origin{o, o})
	if err != nil || len(changes) != 1 {
		t.Fatal(changes, err)
	}
	for _, m := range l.Tick(now) {
		if m.Type == TLVUpdate && m.Prefix != o.Prefix {
			t.Fatal("learned route advertised")
		}
	}
	request := Message{Type: TLVRouteRequest, Wildcard: true}
	out := receiveLeaf(t, l, now, request, request)
	if len(out) != 1 || out[0].Prefix != o.Prefix {
		t.Fatal("dump not local-only/rate-limited", out)
	}
	out = receiveLeaf(t, l, now, Message{Type: TLVRouteRequest, Prefix: remote.Prefix, SourcePrefix: remote.SourcePrefix})
	if len(out) != 1 || out[0].Metric != MetricInfinity {
		t.Fatal("learned request answered with route", out)
	}
	l.seqno = 65535
	out = receiveLeaf(t, l, now, Message{Type: TLVSeqnoRequest, Prefix: o.Prefix, RouterID: l.routerID, Seqno: 50, HopCount: 1})
	if len(out) != 1 || out[0].Seqno != 0 {
		t.Fatal("request did not increment exactly once through wrap", out)
	}
	out = receiveLeaf(t, l, now, Message{Type: TLVSeqnoRequest, Prefix: remote.Prefix, SourcePrefix: remote.SourcePrefix, RouterID: remote.RouterID, Seqno: 5, HopCount: 255})
	if len(out) != 0 {
		t.Fatal("forwarded learned seqno request")
	}
	changes, err = l.SetLocal(nil)
	if err != nil || len(changes) != 1 || changes[0].Metric != MetricInfinity {
		t.Fatal(changes, err)
	}
	for _, m := range l.Tick(now.Add(updateInterval)) {
		if m.Type == TLVUpdate {
			t.Fatal("revoked local prefix re-advertised")
		}
	}
}

func TestLeafBoundsAndSetLocalAtomicity(t *testing.T) {
	l, now := leafForTest(t)
	if _, err := l.SetLocal([]Origin{{Prefix: netip.MustParsePrefix("10.0.0.1/24")}}); err == nil {
		t.Fatal("noncanonical origin")
	}
	if _, err := l.SetLocal(make([]Origin, MaxOrigins+1)); err == nil {
		t.Fatal("unbounded local origins")
	}
	m := remoteUpdate()
	for i := 0; i < sadr.MaxRoutes+1; i++ {
		raw := [16]byte{0x20, 1, 0xd, 0xb8}
		raw[12] = byte(i >> 8)
		raw[13] = byte(i)
		m.Prefix = netip.PrefixFrom(netip.AddrFrom16(raw), 128)
		receiveLeaf(t, l, now, m)
	}
	if len(l.routes) != sadr.MaxRoutes {
		t.Fatal("unbounded route table", len(l.routes))
	}
	if len(l.Candidates(now.Add(14*time.Second), allowCandidate)) != 0 {
		t.Fatal("expired neighbor still usable")
	}
}

func TestLeafRetractionAcrossOriginChangeAndOneWayLink(t *testing.T) {
	l, now := leafForTest(t)
	m := remoteUpdate()
	m.Interval = 10000
	receiveLeaf(t, l, now, m)
	m.RouterID = [8]byte{3}
	receiveLeaf(t, l, now, m)
	// Retractions identify the route by prefix/neighbor, not by origin ID.
	m.RouterID = [8]byte{2}
	m.Metric = MetricInfinity
	receiveLeaf(t, l, now.Add(15*time.Second), m)
	neighborUp(t, l, now.Add(16*time.Second))
	if len(l.Candidates(now.Add(16*time.Second), allowCandidate)) != 0 {
		t.Fatal("withdrawn old route revived after Hello recovery")
	}
}

func TestLeafDeniesUnboundOriginAndAlternateNextHop(t *testing.T) {
	l, now := leafForTest(t)
	m := remoteUpdate()
	if _, err := l.Receive(neighborPacket(t, m), now, func(sadr.Route) bool { return false }); err != nil {
		t.Fatal(err)
	}
	if len(l.routes) != 0 {
		t.Fatal("unauthorized update stored")
	}
	m.NextHop = netip.MustParseAddr("fe80::3")
	receiveLeaf(t, l, now, m)
	if len(l.routes) != 0 {
		t.Fatal("third party next hop accepted")
	}
}
