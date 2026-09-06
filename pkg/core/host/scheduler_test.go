package host

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
)

type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*fakeTimer
}

func newFakeClock(now time.Time) *fakeClock { return &fakeClock{now: now} }

func (clock *fakeClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *fakeClock) NewTimer(after time.Duration) EventTimer {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	timer := &fakeTimer{
		clock: clock,
		when:  clock.now.Add(after),
		c:     make(chan time.Time, 1),
	}
	clock.timers = append(clock.timers, timer)
	return timer
}

func (clock *fakeClock) Advance(after time.Duration) {
	clock.mu.Lock()
	clock.now = clock.now.Add(after)
	var fired []*fakeTimer
	remaining := clock.timers[:0]
	for _, timer := range clock.timers {
		if !timer.when.After(clock.now) && !timer.stopped {
			fired = append(fired, timer)
		} else {
			remaining = append(remaining, timer)
		}
	}
	clock.timers = remaining
	clock.mu.Unlock()
	for _, timer := range fired {
		select {
		case timer.c <- clock.Now():
		default:
		}
	}
}

type fakeTimer struct {
	clock   *fakeClock
	when    time.Time
	c       chan time.Time
	stopped bool
}

func (timer *fakeTimer) C() <-chan time.Time { return timer.c }

func (timer *fakeTimer) Stop() bool {
	timer.clock.mu.Lock()
	defer timer.clock.mu.Unlock()
	if timer.stopped {
		return false
	}
	timer.stopped = true
	return true
}

func (timer *fakeTimer) Reset(after time.Duration) bool {
	timer.clock.mu.Lock()
	defer timer.clock.mu.Unlock()
	active := !timer.stopped
	timer.stopped = false
	timer.when = timer.clock.now.Add(after)
	return active
}

func receiveTimer(t *testing.T, events <-chan Event) TimerFired {
	t.Helper()
	select {
	case event := <-events:
		fired, ok := event.(TimerFired)
		if !ok {
			t.Fatalf("event = %T, want TimerFired", event)
		}
		return fired
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for timer")
		return TimerFired{}
	}
}

func requireSchedulerStops(t *testing.T, scheduler *Scheduler) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		scheduler.Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Scheduler.Stop did not stop the wakeup loop")
	}
}

func TestSchedulerPostsNamespacedTimer(t *testing.T) {
	clock := newFakeClock(time.Unix(1000, 0))
	events := make(chan Event, 1)
	scheduler := NewScheduler(clock, events)
	id := TimerID{Namespace: GossipTimerNamespace, Owner: "peer-a", Key: gossip.TimerKindRound}
	deadline := clock.Now().Add(5 * time.Second)
	generation, err := scheduler.Schedule(id, deadline)
	if err != nil {
		t.Fatalf("Schedule: %v", err)
	}
	clock.Advance(5 * time.Second)
	fired := receiveTimer(t, events)
	if fired.ID != id || fired.Generation != generation || !fired.Deadline.Equal(deadline) {
		t.Fatalf("fired = %#v", fired)
	}
	if !scheduler.Accept(fired) || scheduler.Accept(fired) {
		t.Fatal("fired generation was not accepted exactly once")
	}
	requireSchedulerStops(t, scheduler)
}

func TestSchedulerCancelPreventsEvent(t *testing.T) {
	clock := newFakeClock(time.Unix(1000, 0))
	events := make(chan Event, 1)
	scheduler := NewScheduler(clock, events)
	id := TimerID{Namespace: "controller", Owner: "firewall", Key: "debounce"}
	_, _ = scheduler.Schedule(id, clock.Now().Add(time.Second))
	scheduler.Cancel(id)
	clock.Advance(time.Second)
	select {
	case event := <-events:
		t.Fatalf("cancelled timer posted %T", event)
	case <-time.After(50 * time.Millisecond):
	}
	requireSchedulerStops(t, scheduler)
}

func TestSchedulerReplacementRejectsQueuedStaleGeneration(t *testing.T) {
	clock := newFakeClock(time.Unix(1000, 0))
	events := make(chan Event, 2)
	scheduler := NewScheduler(clock, events)
	id := TimerID{Namespace: GossipTimerNamespace, Owner: "peer-a", Key: gossip.TimerKindRound}
	firstGeneration, _ := scheduler.Schedule(id, clock.Now().Add(time.Second))
	clock.Advance(time.Second)
	first := receiveTimer(t, events)
	secondGeneration, _ := scheduler.Schedule(id, clock.Now().Add(time.Second))
	if first.Generation != firstGeneration || secondGeneration <= firstGeneration {
		t.Fatalf("generations first=%d second=%d fired=%d", firstGeneration, secondGeneration, first.Generation)
	}
	if scheduler.Accept(first) {
		t.Fatal("queued generation remained current after replacement")
	}
	clock.Advance(time.Second)
	second := receiveTimer(t, events)
	if second.Generation != secondGeneration || !scheduler.Accept(second) {
		t.Fatalf("replacement fire = %#v", second)
	}
	requireSchedulerStops(t, scheduler)
}

func TestSchedulerSameDeadlineUsesScheduleOrder(t *testing.T) {
	clock := newFakeClock(time.Unix(1000, 0))
	events := make(chan Event, 3)
	scheduler := NewScheduler(clock, events)
	deadline := clock.Now().Add(time.Second)
	for _, owner := range []string{"peer-b", "peer-a", "peer-c"} {
		_, _ = scheduler.Schedule(TimerID{Namespace: GossipTimerNamespace, Owner: owner, Key: gossip.TimerKindRound}, deadline)
	}
	clock.Advance(time.Second)
	for _, want := range []string{"peer-b", "peer-a", "peer-c"} {
		if got := receiveTimer(t, events).ID.Owner; got != want {
			t.Fatalf("owner = %q, want %q", got, want)
		}
	}
	requireSchedulerStops(t, scheduler)
}

func TestSchedulerCancelOwnerIsNamespaceScoped(t *testing.T) {
	clock := newFakeClock(time.Unix(1000, 0))
	events := make(chan Event, 2)
	scheduler := NewScheduler(clock, events)
	deadline := clock.Now().Add(time.Second)
	_, _ = scheduler.Schedule(TimerID{Namespace: GossipTimerNamespace, Owner: "peer-a", Key: gossip.TimerKindRound}, deadline)
	_, _ = scheduler.Schedule(TimerID{Namespace: "controller", Owner: "peer-a", Key: "refresh"}, deadline)
	scheduler.CancelOwner(GossipTimerNamespace, "peer-a")
	clock.Advance(time.Second)
	if fired := receiveTimer(t, events); fired.ID.Namespace != "controller" {
		t.Fatalf("unexpected fire = %#v", fired)
	}
	select {
	case event := <-events:
		t.Fatalf("cancelled namespace posted %T", event)
	case <-time.After(50 * time.Millisecond):
	}
	requireSchedulerStops(t, scheduler)
}

func TestSchedulerQueueBackpressureDoesNotDropTimeout(t *testing.T) {
	clock := newFakeClock(time.Unix(1000, 0))
	events := make(chan Event, 1)
	events <- GossipEvent{Value: &gossip.SyncTimerEvent{PeerID: "occupy"}}
	scheduler := NewScheduler(clock, events)
	id := TimerID{Namespace: GossipTimerNamespace, Owner: "peer-a", Key: gossip.TimerKindRound}
	_, _ = scheduler.Schedule(id, clock.Now().Add(time.Second))
	clock.Advance(time.Second)
	time.Sleep(10 * time.Millisecond)
	<-events
	if fired := receiveTimer(t, events); fired.ID != id {
		t.Fatalf("fired = %#v", fired)
	}
	requireSchedulerStops(t, scheduler)
}

func TestSchedulerStopAndValidation(t *testing.T) {
	clock := newFakeClock(time.Unix(1000, 0))
	scheduler := NewScheduler(clock, make(chan Event))
	if _, err := scheduler.Schedule(TimerID{}, clock.Now()); !errors.Is(err, ErrInvalidTimerID) {
		t.Fatalf("invalid id error = %v", err)
	}
	_, _ = scheduler.Schedule(TimerID{Namespace: "test", Owner: "owner", Key: "key"}, clock.Now().Add(time.Hour))
	requireSchedulerStops(t, scheduler)
	requireSchedulerStops(t, scheduler)
	if _, err := scheduler.Schedule(TimerID{Namespace: "test", Owner: "owner", Key: "key"}, clock.Now()); !errors.Is(err, ErrSchedulerStopped) {
		t.Fatalf("schedule after stop error = %v", err)
	}
}

func TestGossipDriverOwnsQueueSchedulerAndPureGossipEngine(t *testing.T) {
	clock := newFakeClock(time.Unix(1000, 0))
	driver := NewGossipDriver(clock, 1, nil, GossipDriverConfig{})
	defer driver.Stop()
	external := &gossip.SyncTimerEvent{PeerID: "peer-a"}
	if err := driver.PostGossip(external); err != nil {
		t.Fatalf("PostGossip: %v", err)
	}
	if err := driver.PostGossip(external); !errors.Is(err, ErrGossipEventQueueFull) {
		t.Fatalf("full queue error = %v", err)
	}
	if event, ok := driver.GossipSessionEventFor(<-driver.Events()); !ok || event != external {
		t.Fatalf("external event = %T ok=%v", event, ok)
	}
	deadline := clock.Now().Add(time.Second)
	if handled, err := driver.ApplyGossipTimerAction(gossip.StartTimerAction{PeerID: "peer-a", Kind: gossip.TimerKindRound, Deadline: deadline}); !handled || err != nil {
		t.Fatalf("timer action handled=%v err=%v", handled, err)
	}
	clock.Advance(time.Second)
	event, ok := driver.GossipSessionEventFor(<-driver.Events())
	if !ok {
		t.Fatal("timer fire was not accepted")
	}
	if timeout, ok := event.(*gossip.RoundTimeoutEvent); !ok || timeout.PeerID != "peer-a" {
		t.Fatalf("timer event = %#v", event)
	}
}
