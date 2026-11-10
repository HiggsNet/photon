package host

import (
	"log/slog"
	"time"
)

const (
	slowGossipOperationThreshold = 100 * time.Millisecond
	slowGossipOperationInterval  = 30 * time.Second
)

type slowGossipOperation struct {
	lastLog    time.Time
	suppressed int
	maxElapsed time.Duration
	maxQueue   int
}

// LogSlowOperation measures synchronous work that can delay the gossip consumer.
// Call with defer, passing time.Now() and PendingEventCount() as arguments.
// Component and operation must be fixed names. Each pair has its own rate limit.
// Queue lengths are boundary samples, not a continuously measured high-water mark.
// Fast calls do no allocation, formatting, locking, or logging.
func (driver *GossipDriver) LogSlowOperation(component, operation string, started time.Time, queueBefore int) {
	if driver == nil {
		return
	}
	elapsed := time.Since(started)
	if elapsed < slowGossipOperationThreshold {
		return
	}
	driver.logSlowOperation(component, operation, elapsed, started.Add(elapsed), queueBefore)
}

func (driver *GossipDriver) logSlowOperation(component, operation string, elapsed time.Duration, now time.Time, queueBefore int) {
	queueAfter := driver.PendingEventCount()
	driver.mu.Lock()
	log := driver.gossipConfig.Log
	if log == nil {
		driver.mu.Unlock()
		return
	}
	if driver.slowOperations == nil {
		driver.slowOperations = make(map[[2]string]slowGossipOperation)
	}
	key := [2]string{component, operation}
	state := driver.slowOperations[key]
	state.maxElapsed = max(state.maxElapsed, elapsed)
	state.maxQueue = max(state.maxQueue, queueBefore, queueAfter)
	if !state.lastLog.IsZero() && now.Sub(state.lastLog) < slowGossipOperationInterval {
		state.suppressed++
		driver.slowOperations[key] = state
		driver.mu.Unlock()
		return
	}
	driver.slowOperations[key] = slowGossipOperation{lastLog: now}
	driver.mu.Unlock()
	// Invoke the logger outside the driver lock. Only emitted slow samples
	// construct fields; suppressed samples retain counters for the next log.
	driver.logRecord(component, slog.LevelWarn, "slow_operation", "", operation, nil, map[string]any{
		"elapsed_ms": elapsed.Milliseconds(), "max_elapsed_ms": state.maxElapsed.Milliseconds(),
		"queue_before": queueBefore, "queue_after": queueAfter, "queue_capacity": cap(driver.events) + cap(driver.completions),
		"input_queue_after": len(driver.events), "completion_queue_after": len(driver.completions),
		"internal_pending": driver.internalPending.Load(), "datagram_drops": driver.datagramDrops.Load(),
		"max_sampled_queue": state.maxQueue, "suppressed": state.suppressed,
	})
}
