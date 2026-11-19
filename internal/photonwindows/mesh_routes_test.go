package photonwindows

import (
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/photonclient/babel"
)

func TestMeshRouteHysteresisOnControlUpdates(t *testing.T) {
	m, f := meshRouteFixture(t)
	a, b := m.ordered()[0], m.ordered()[1]
	packet := dataplanePacket(true)
	copy(packet[12:16], []byte{10, 9, 0, 1})
	copy(packet[16:20], []byte{10, 1, 2, 3})
	const prefix = "10.1.0.0/16"
	seqno := uint16(1)
	at := func(after time.Duration) time.Time {
		now := f.now.Add(after)
		// The detached test fixture supplies fresh planner hints at each event.
		a.plan.EvaluatedAt, b.plan.EvaluatedAt = now, now
		return now
	}
	update := func(after time.Duration, metric uint16) {
		t.Helper()
		now := at(after)
		seqno++
		meshLearnWithHello(t, a, f.view, now, prefix, 80, seqno, 6000)
		meshLearnWithHello(t, b, f.view, now, prefix, metric, seqno, 6000)
		m.refreshRouteSelections(f.view, now)
	}
	check := func(after time.Duration, want *meshPeer, metric uint16) {
		t.Helper()
		choice := m.selectRoute(packet, f.view, at(after))
		if choice.peer != want || choice.route.Metric != metric {
			t.Fatalf("after %s: peer=%p metric=%d, want %p/%d", after, choice.peer, choice.route.Metric, want, metric)
		}
	}
	update(0, 100)
	check(0, a, 180)
	update(time.Second, 57) // A 23-point advantage does not start a timer.
	for _, selection := range m.routeSelections {
		if len(selection.better) != 0 {
			t.Fatal("a 23-point advantage started a timer")
		}
	}
	update(2*time.Second, 56)
	update(10*time.Second, 57) // A brief recovery cancels the first timer.
	update(11*time.Second, 56)
	update(40*time.Second, 56) // Repeating the metric does not restart the timer.
	check(41*time.Second-time.Nanosecond, a, 180)
	// The control timer elects B even if no host packet arrives at the deadline.
	m.refreshRouteSelections(f.view, at(41*time.Second))
	if len(m.routeSelections) != 1 {
		t.Fatal("control timer discarded the active prefix")
	}
	for _, choice := range m.routeSelections {
		if choice.current.leaf != b.leaf.pipeline.leaf {
			t.Fatal("control timer retained the old route")
		}
	}
	check(41*time.Second, b, 156)
	meshLearnWithHello(t, b, f.view, at(42*time.Second), prefix, babel.MetricInfinity, seqno+1, 6000)
	check(42*time.Second, a, 180) // Retraction fails over without a timer tick.
}

func TestMeshRouteHysteresisUsesIndependentChallengerTimers(t *testing.T) {
	a, b, c := new(babel.Leaf), new(babel.Leaf), new(babel.Leaf)
	paths := []meshRouteCandidate{
		{path: meshRoutePath{leaf: a}, metric: 200},
		{path: meshRoutePath{leaf: b}, metric: 175},
		{path: meshRoutePath{leaf: c}, metric: 180},
	}
	var selection meshRouteSelection
	now := time.Unix(100, 0)
	selection.selectMetric(paths[:1], now)
	selection.selectMetric(paths, now)
	paths[2].metric = 110
	selection.selectMetric(paths, now.Add(20*time.Second))
	if got := selection.selectMetric(paths, now.Add(30*time.Second)); got != 175 {
		t.Fatalf("mature challenger was displaced by a recent challenger: %d", got)
	}
	paths[2].path.routerID[0]++
	if got := selection.selectMetric(paths, now.Add(60*time.Second)); got != 175 {
		t.Fatalf("replacement inherited the prior route's timer: %d", got)
	}
	if got := selection.selectMetric(paths, now.Add(90*time.Second)); got != 110 {
		t.Fatalf("replacement did not switch after its own timer: %d", got)
	}
	if got := selection.selectMetric(paths[:2], now.Add(91*time.Second)); got != 175 {
		t.Fatalf("lost incumbent did not fail over immediately: %d", got)
	}
}
