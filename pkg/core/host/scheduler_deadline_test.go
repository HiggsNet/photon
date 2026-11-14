package host

import (
	"sync"
	"testing"
	"time"
)

type pausedArmClock struct {
	*fakeClock
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (clock *pausedArmClock) NewTimer(after time.Duration) EventTimer {
	clock.once.Do(func() {
		close(clock.started)
		<-clock.release
	})
	return clock.fakeClock.NewTimer(after)
}

func TestSchedulerDeadlinePassedWhileArming(t *testing.T) {
	clock := &pausedArmClock{fakeClock: newFakeClock(time.Unix(100, 0)), started: make(chan struct{}), release: make(chan struct{})}
	events := make(chan Event, 1)
	scheduler := NewScheduler(clock, events)
	defer scheduler.Stop()
	var release sync.Once
	defer release.Do(func() { close(clock.release) })
	id := TimerID{Namespace: "test", Owner: "peer", Key: "round"}
	if _, err := scheduler.Schedule(id, clock.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-clock.started:
	case <-time.After(time.Second):
		t.Fatal("scheduler never attempted to arm its timer")
	}
	// Remove the schedule wakeup, so it cannot hide a timer armed relative
	// to a later clock value than the one used to calculate its duration.
	select {
	case <-scheduler.wake:
	default:
	}
	clock.Advance(time.Second)
	release.Do(func() { close(clock.release) })
	fired := receiveTimer(t, events)
	if fired.ID != id || !scheduler.Accept(fired) {
		t.Fatalf("deadline did not fire exactly once: %#v", fired)
	}
}
