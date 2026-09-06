package host

import (
	"container/heap"
	"errors"
	"sync"
	"time"
)

const maxTimerDrainBatch = 64

var (
	ErrInvalidTimerID   = errors.New("invalid timer id")
	ErrSchedulerStopped = errors.New("scheduler stopped")
)

// EventTimer is the clock timer resource used by Scheduler.
type EventTimer interface {
	C() <-chan time.Time
	Stop() bool
	Reset(time.Duration) bool
}

// Clock makes Scheduler timing deterministic in tests.
type Clock interface {
	Now() time.Time
	NewTimer(time.Duration) EventTimer
}

type systemClock struct {
	now func() time.Time
}

func (clock *systemClock) Now() time.Time { return clock.now() }

func (*systemClock) NewTimer(after time.Duration) EventTimer {
	return &systemEventTimer{Timer: time.NewTimer(after)}
}

type systemEventTimer struct{ *time.Timer }

func (timer *systemEventTimer) C() <-chan time.Time { return timer.Timer.C }

// TimerID is stable protocol/controller timer identity. Namespace separates
// independent owners while Owner and Key identify replacement/cancellation.
type TimerID struct {
	Namespace string
	Owner     string
	Key       string
}

// TimerFired is queued by Scheduler. Generation is validated only when the
// single-writer event loop consumes it.
type TimerFired struct {
	ID         TimerID
	Generation uint64
	Deadline   time.Time
}

func (TimerFired) isHostEvent() {}

type scheduledTimer struct {
	id         TimerID
	generation uint64
	deadline   time.Time
	sequence   uint64
	index      int
}

type timerHeap []*scheduledTimer

func (items timerHeap) Len() int { return len(items) }

func (items timerHeap) Less(i, j int) bool {
	if items[i].deadline.Equal(items[j].deadline) {
		return items[i].sequence < items[j].sequence
	}
	return items[i].deadline.Before(items[j].deadline)
}

func (items timerHeap) Swap(i, j int) {
	items[i], items[j] = items[j], items[i]
	items[i].index = i
	items[j].index = j
}

func (items *timerHeap) Push(value any) {
	entry := value.(*scheduledTimer)
	entry.index = len(*items)
	*items = append(*items, entry)
}

func (items *timerHeap) Pop() any {
	old := *items
	last := len(old) - 1
	entry := old[last]
	old[last] = nil
	entry.index = -1
	*items = old[:last]
	return entry
}

// Scheduler owns one deadline heap and one wakeup loop for all namespaces.
// Scheduling methods are concurrency-safe; the owning single-writer event
// loop accepts fired generations.
type Scheduler struct {
	clock  Clock
	events chan<- Event

	mu             sync.Mutex
	timers         timerHeap
	active         map[TimerID]uint64
	lastGeneration map[TimerID]uint64
	sequence       uint64
	stopped        bool

	wake     chan struct{}
	done     chan struct{}
	stopDone chan struct{}
}

func NewScheduler(clock Clock, events chan<- Event) *Scheduler {
	if clock == nil {
		clock = NewClock(nil)
	}
	scheduler := &Scheduler{
		clock:          clock,
		events:         events,
		active:         make(map[TimerID]uint64),
		lastGeneration: make(map[TimerID]uint64),
		wake:           make(chan struct{}, 1),
		done:           make(chan struct{}),
		stopDone:       make(chan struct{}),
	}
	heap.Init(&scheduler.timers)
	go scheduler.run()
	return scheduler
}

func (scheduler *Scheduler) Schedule(id TimerID, deadline time.Time) (uint64, error) {
	if id.Namespace == "" || id.Owner == "" || id.Key == "" {
		return 0, ErrInvalidTimerID
	}
	scheduler.mu.Lock()
	if scheduler.stopped {
		scheduler.mu.Unlock()
		return 0, ErrSchedulerStopped
	}
	generation := scheduler.lastGeneration[id] + 1
	scheduler.lastGeneration[id] = generation
	scheduler.active[id] = generation
	scheduler.sequence++
	heap.Push(&scheduler.timers, &scheduledTimer{
		id:         id,
		generation: generation,
		deadline:   deadline,
		sequence:   scheduler.sequence,
	})
	scheduler.mu.Unlock()
	scheduler.signalWake()
	return generation, nil
}

func (scheduler *Scheduler) Cancel(id TimerID) {
	scheduler.mu.Lock()
	delete(scheduler.active, id)
	scheduler.mu.Unlock()
	scheduler.signalWake()
}

func (scheduler *Scheduler) CancelOwner(namespace, owner string) {
	scheduler.mu.Lock()
	for id := range scheduler.active {
		if id.Namespace == namespace && id.Owner == owner {
			delete(scheduler.active, id)
		}
	}
	scheduler.mu.Unlock()
	scheduler.signalWake()
}

// Accept validates and consumes a fired generation. A cancel or replacement
// between queue delivery and event handling makes the old fire stale.
func (scheduler *Scheduler) Accept(fired TimerFired) bool {
	if scheduler == nil {
		return false
	}
	scheduler.mu.Lock()
	defer scheduler.mu.Unlock()
	if scheduler.stopped || scheduler.active[fired.ID] != fired.Generation {
		return false
	}
	delete(scheduler.active, fired.ID)
	return true
}

func (scheduler *Scheduler) Stop() {
	if scheduler == nil {
		return
	}
	scheduler.mu.Lock()
	if scheduler.stopped {
		stopDone := scheduler.stopDone
		scheduler.mu.Unlock()
		<-stopDone
		return
	}
	scheduler.stopped = true
	scheduler.active = make(map[TimerID]uint64)
	close(scheduler.done)
	scheduler.mu.Unlock()
	<-scheduler.stopDone
}

func (scheduler *Scheduler) run() {
	defer close(scheduler.stopDone)
	for {
		due, next, ok := scheduler.takeDue()
		for _, fired := range due {
			select {
			case scheduler.events <- fired:
			case <-scheduler.done:
				return
			}
		}
		if len(due) == maxTimerDrainBatch {
			continue
		}
		if !ok {
			select {
			case <-scheduler.wake:
				continue
			case <-scheduler.done:
				return
			}
		}
		after := max(next.Sub(scheduler.clock.Now()), 0)
		timer := scheduler.clock.NewTimer(after)
		select {
		case <-timer.C():
		case <-scheduler.wake:
			timer.Stop()
		case <-scheduler.done:
			timer.Stop()
			return
		}
	}
}

func (scheduler *Scheduler) takeDue() ([]TimerFired, time.Time, bool) {
	now := scheduler.clock.Now()
	scheduler.mu.Lock()
	defer scheduler.mu.Unlock()
	due := make([]TimerFired, 0, maxTimerDrainBatch)
	for scheduler.timers.Len() > 0 {
		entry := scheduler.timers[0]
		if scheduler.active[entry.id] != entry.generation {
			heap.Pop(&scheduler.timers)
			continue
		}
		if entry.deadline.After(now) || len(due) == maxTimerDrainBatch {
			return due, entry.deadline, true
		}
		heap.Pop(&scheduler.timers)
		due = append(due, TimerFired{
			ID:         entry.id,
			Generation: entry.generation,
			Deadline:   entry.deadline,
		})
	}
	return due, time.Time{}, false
}

func (scheduler *Scheduler) signalWake() {
	select {
	case scheduler.wake <- struct{}{}:
	default:
	}
}
