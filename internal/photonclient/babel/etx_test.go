package babel

import (
	"net/netip"
	"testing"
	"time"
)

func receiveNeighbor(t testing.TB, n *Neighbor, now time.Time, messages ...Message) NeighborBatch {
	t.Helper()
	batch, err := n.Receive(neighborPacket(t, messages...), now)
	if err != nil {
		t.Fatal(err)
	}
	return batch
}

func TestNeighborETXAsymmetricLossWrapAndRecovery(t *testing.T) {
	n, _ := NewNeighbor(neighborLocal, neighborPeer, 100)
	start := time.Unix(100, 0)
	var last time.Time
	var batch NeighborBatch
	// Receive 12 of 16 sequence positions, crossing the 16-bit wrap. The
	// peer's IHU 150 represents a different loss rate in the other direction.
	for i := 0; i < 16; i++ {
		if i%4 == 2 {
			continue
		}
		last = start.Add(time.Duration(i) * time.Second)
		batch = receiveNeighbor(t, n, last,
			Message{Type: TLVHello, Seqno: uint16(65528 + i), Interval: 100},
			Message{Type: TLVIHU, Metric: 150, Interval: 100})
	}
	if got := n.Cost(last); got != 200 {
		t.Fatalf("asymmetric ETX = %d, want 200 (150 / 0.75)", got)
	}
	if len(batch.Replies) != 1 || batch.Replies[0].Type != TLVIHU || batch.Replies[0].Metric != 142 {
		t.Fatalf("IHU must report only local reception loss: %+v", batch.Replies)
	}
	before := n.hello[0]
	receiveNeighbor(t, n, last.Add(time.Millisecond),
		Message{Type: TLVHello, Seqno: before.seqno, Interval: 6000},
		Message{Type: TLVHello, Seqno: before.seqno - 1, Interval: 6000})
	if n.hello[0] != before || n.Cost(last) != 200 {
		t.Fatal("duplicate or old Hello changed loss history or lease")
	}
	for i := 1; i <= 16; i++ {
		last = start.Add(time.Duration(15+i) * time.Second)
		receiveNeighbor(t, n, last,
			Message{Type: TLVHello, Seqno: before.seqno + uint16(i), Interval: 100},
			Message{Type: TLVIHU, Metric: 150, Interval: 100})
	}
	if got := n.Cost(last); got != 150 || n.ihu(last).Metric != 100 {
		t.Fatalf("loss did not age out after 16 good Hellos: cost=%d IHU=%d", got, n.ihu(last).Metric)
	}
}

func TestNeighborETXSilentLossWithoutTickAndLateArrival(t *testing.T) {
	n, _ := NewNeighbor(neighborLocal, neighborPeer, 100)
	start := time.Unix(100, 0)
	for i := 0; i < 16; i++ {
		receiveNeighbor(t, n, start.Add(time.Duration(i)*time.Second),
			Message{Type: TLVHello, Seqno: uint16(i), Interval: 100},
			Message{Type: TLVIHU, Metric: 150, Interval: 100})
	}
	last := start.Add(15 * time.Second)
	for _, tc := range []struct {
		after     time.Duration
		cost, ihu uint16
	}{
		{1500*time.Millisecond - time.Nanosecond, 150, 100},
		{1500 * time.Millisecond, 160, 108},
		{2500 * time.Millisecond, 171, 118},
		{3500 * time.Millisecond, MetricInfinity, MetricInfinity},
	} {
		at := last.Add(tc.after)
		if got := n.Cost(at); got != tc.cost || n.ihu(at).Metric != tc.ihu {
			t.Fatalf("after %v: cost=%d IHU=%d, want %d/%d", tc.after, got, n.ihu(at).Metric, tc.cost, tc.ihu)
		}
	}
	// A delayed next sequence repairs projected timer loss. It must not add
	// another hole or forget real historical losses; lookups above are pure.
	receiveNeighbor(t, n, last.Add(2600*time.Millisecond), Message{Type: TLVHello, Seqno: 16, Interval: 200})
	if got := n.Cost(last.Add(2600 * time.Millisecond)); got != 150 {
		t.Fatalf("late Hello double-counted timer loss: %d", got)
	}
	// A later gap of two sequence positions represents exactly one lost Hello.
	last = last.Add(3 * time.Second)
	receiveNeighbor(t, n, last, Message{Type: TLVHello, Seqno: 18, Interval: 100}, Message{Type: TLVIHU, Metric: 150, Interval: 100})
	if n.Cost(last) != 160 || n.ihu(last).Metric != 108 {
		t.Fatalf("sequence gap counted incorrectly: cost=%d IHU=%d", n.Cost(last), n.ihu(last).Metric)
	}
	// Tick uses the same aged reception estimate in its actual outgoing IHU.
	for _, m := range n.Tick(last.Add(1500 * time.Millisecond)) {
		if m.Type == TLVIHU && m.Metric == 118 {
			return
		}
	}
	t.Fatal("periodic IHU did not advertise silent loss")
}

func TestNeighborETXUnicastDoesNotMaskMulticastLoss(t *testing.T) {
	n, _ := NewNeighbor(neighborLocal, neighborPeer, 100)
	now := time.Unix(100, 0)
	receiveNeighbor(t, n, now, Message{Type: TLVHello, Seqno: 1, Interval: 100}, Message{Type: TLVIHU, Metric: 100, Interval: 400})
	receiveNeighbor(t, n, now.Add(2*time.Second), Message{Type: TLVHello, Seqno: 100, Unicast: true, Interval: 400})
	if n.Cost(now.Add(2*time.Second)) != 228 {
		t.Fatal("unicast Hello hid multicast loss")
	}
	if n.Cost(now.Add(3500*time.Millisecond)) != MetricInfinity {
		t.Fatal("unicast Hello revived expired multicast history")
	}
	// A unicast-only peer still has an independent loss estimate and lease.
	n, _ = NewNeighbor(neighborLocal, neighborPeer, 100)
	receiveNeighbor(t, n, now, Message{Type: TLVHello, Seqno: 1, Unicast: true, Interval: 100}, Message{Type: TLVIHU, Metric: 100, Interval: 400})
	receiveNeighbor(t, n, now.Add(2*time.Second), Message{Type: TLVHello, Seqno: 3, Unicast: true, Interval: 100})
	if n.Cost(now.Add(2*time.Second)) != 164 || n.ihu(now.Add(2*time.Second)).Metric != 164 {
		t.Fatal("unicast-only peer did not track its own sequence history")
	}
}

func TestNeighborETXBoundsRestartAndDirectionalCost(t *testing.T) {
	start := time.Unix(100, 0)
	for _, tc := range []struct {
		name                          string
		base, peer, wantIHU, wantCost uint16
	}{
		{"bounded gap", 100, 100, 2020, 2020},
		{"low base", 32, 32, 1952, 1952},
		{"saturation", 5000, 5000, MetricInfinity, MetricInfinity},
		{"directional", 5000, 10, MetricInfinity, 1930},
		{"positive", 100, 0, 2020, 1921},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n, _ := NewNeighbor(neighborLocal, neighborPeer, tc.base)
			receiveNeighbor(t, n, start, Message{Type: TLVHello, Seqno: 1, Interval: 100}, Message{Type: TLVIHU, Metric: tc.peer, Interval: 400})
			// A large forward gap cannot overflow the window or reset to perfect quality.
			now := start.Add(time.Second)
			receiveNeighbor(t, n, now, Message{Type: TLVHello, Seqno: 30000, Interval: 100})
			if n.Cost(now) != tc.wantCost || n.ihu(now).Metric != tc.wantIHU {
				t.Fatalf("large gap: cost=%d IHU=%d, want %d/%d", n.Cost(now), n.ihu(now).Metric, tc.wantCost, tc.wantIHU)
			}
			// A genuinely expired session may restart with a new sequence space.
			now = now.Add(3500 * time.Millisecond)
			receiveNeighbor(t, n, now, Message{Type: TLVHello, Seqno: 5, Interval: 100})
			if n.ihu(now).Metric != tc.base || n.Cost(now) != max(1, tc.peer) {
				t.Fatalf("restart retained stale loss: cost=%d IHU=%d", n.Cost(now), n.ihu(now).Metric)
			}
		})
	}
}

func TestLeafETXChangesInstalledRouteWithoutUpdate(t *testing.T) {
	l, now := leafForTest(t)
	m := remoteUpdate()
	m.Interval = 10000 // Keep the original route alive throughout loss and recovery.
	receiveLeaf(t, l, now, m)
	source, destination := netip.MustParseAddr("2001:db8:1::1"), netip.MustParseAddr("2001:db8::1")
	check := func(at time.Time, want uint16) {
		t.Helper()
		got, ok := l.LookupInstalledRoute(source, destination, at)
		candidates := l.Candidates(at, allowCandidate)
		if !ok || got.Metric != want || len(candidates) != 1 || candidates[0].Metric != want {
			t.Fatalf("route cost: installed=%+v candidates=%+v, want %d", got, candidates, want)
		}
	}
	check(now, 150)
	check(now.Add(6*time.Second), 278) // One silent loss, beta=1/2.
	receiveLeaf(t, l, now.Add(8*time.Second), Message{Type: TLVHello, Seqno: 3, Interval: 400})
	check(now.Add(8*time.Second), 214) // Two received out of three.
	last := now.Add(8 * time.Second)
	for i := 4; i <= 19; i++ {
		last = now.Add(time.Duration(i-1) * helloInterval)
		receiveLeaf(t, l, last, Message{Type: TLVHello, Seqno: uint16(i), Interval: 400}, Message{Type: TLVIHU, Metric: 100, Interval: 400})
	}
	check(last, 150)
}

func TestLeafRouteIdentityTracksContinuousAvailability(t *testing.T) {
	l, now := leafForTest(t)
	update := remoteUpdate()
	update.Interval = 1600
	origin := Origin{Prefix: update.Prefix, SourcePrefix: update.SourcePrefix}
	receiveLeaf(t, l, now, update)
	initial := l.RouteIdentity(origin)
	update.Metric++
	receiveLeaf(t, l, now.Add(time.Second), update)
	if l.RouteIdentity(origin) != initial {
		t.Fatal("metric and lease refresh changed route continuity")
	}
	retract := update
	retract.Metric = MetricInfinity
	receiveLeaf(t, l, now.Add(2*time.Second), retract, update)
	relearned := l.RouteIdentity(origin)
	if relearned == initial {
		t.Fatal("relearned route inherited continuity after withdrawal")
	}
	receiveLeaf(t, l, now.Add(14*time.Second), Message{Type: TLVHello, Seqno: 2, Interval: 400}, Message{Type: TLVIHU, Metric: 100, Interval: 400})
	if l.RouteIdentity(origin) == relearned {
		t.Fatal("route inherited continuity after neighbor expiry")
	}
}
