package host

import "time"

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
// Operation must be a fixed stage name, never a peer ID or other unbounded value.
// Queue lengths are boundary samples, not a continuously measured high-water mark.
// Fast calls do no allocation, formatting, locking, or logging.
func (driver *GossipDriver) LogSlowOperation(operation string, started time.Time, queueBefore int) {
	if driver == nil {
		return
	}
	elapsed := time.Since(started)
	if elapsed < slowGossipOperationThreshold {
		return
	}
	driver.logSlowOperation(operation, elapsed, started.Add(elapsed), queueBefore)
}

func (driver *GossipDriver) logSlowOperation(operation string, elapsed time.Duration, now time.Time, queueBefore int) {
	queueAfter := driver.PendingEventCount()
	driver.mu.Lock()
	log := driver.gossipConfig.Log
	if log == nil {
		driver.mu.Unlock()
		return
	}
	if driver.slowOperations == nil {
		driver.slowOperations = make(map[string]slowGossipOperation)
	}
	state := driver.slowOperations[operation]
	state.maxElapsed = max(state.maxElapsed, elapsed)
	state.maxQueue = max(state.maxQueue, queueBefore, queueAfter)
	if !state.lastLog.IsZero() && now.Sub(state.lastLog) < slowGossipOperationInterval {
		state.suppressed++
		driver.slowOperations[operation] = state
		driver.mu.Unlock()
		return
	}
	driver.slowOperations[operation] = slowGossipOperation{lastLog: now}
	driver.mu.Unlock()
	// Invoke the logger outside the driver lock. Only emitted slow samples
	// construct fields; suppressed samples retain counters for the next log.
	log(GossipDriverLog{Level: "warn", Event: "slow_operation", Phase: operation, Fields: map[string]any{
		"elapsed_ms": elapsed.Milliseconds(), "max_elapsed_ms": state.maxElapsed.Milliseconds(),
		"queue_before": queueBefore, "queue_after": queueAfter, "queue_capacity": cap(driver.events),
		"max_sampled_queue": state.maxQueue, "suppressed": state.suppressed,
	}})
}
