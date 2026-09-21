package main

import (
	"sync"
	"time"

	corehost "github.com/HiggsNet/photon/pkg/core/host"
)

// fakeClock is the deterministic clock used by daemon and gossip scheduler
// integration tests. Scheduler behavior itself is tested in pkg/core/host.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*fakeGossipTimer
}

func newFakeClock(now time.Time) *fakeClock { return &fakeClock{now: now} }

func (clock *fakeClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *fakeClock) NewTimer(after time.Duration) corehost.EventTimer {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	timer := &fakeGossipTimer{clock: clock, when: clock.now.Add(after), channel: make(chan time.Time, 1)}
	clock.timers = append(clock.timers, timer)
	return timer
}

func (clock *fakeClock) Advance(after time.Duration) {
	clock.mu.Lock()
	clock.now = clock.now.Add(after)
	now := clock.now
	var fired []*fakeGossipTimer
	var waiting []*fakeGossipTimer
	for _, timer := range clock.timers {
		if !timer.stopped && !timer.when.After(now) {
			fired = append(fired, timer)
		} else {
			waiting = append(waiting, timer)
		}
	}
	clock.timers = waiting
	clock.mu.Unlock()
	for _, timer := range fired {
		select {
		case timer.channel <- now:
		default:
		}
	}
}

type fakeGossipTimer struct {
	clock   *fakeClock
	when    time.Time
	channel chan time.Time
	stopped bool
}

func (timer *fakeGossipTimer) C() <-chan time.Time { return timer.channel }

func (timer *fakeGossipTimer) Stop() bool {
	timer.clock.mu.Lock()
	defer timer.clock.mu.Unlock()
	active := !timer.stopped
	timer.stopped = true
	return active
}
