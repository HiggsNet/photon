package host

import (
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
)

const maxGossipEventBatch = 16

// gossipContinue is a wakeup only; pending results stay owned by the consumer.
type gossipContinue struct{}

func (gossipContinue) isHostEvent() {}

// Completions delivers worker results and timer generations. Producers may
// wait for capacity, with cancellation; the consumer never sends to this queue.
// Select it alongside Events and Continuations, handling one event at a time.
func (driver *GossipDriver) Completions() <-chan Event {
	if driver == nil {
		return nil
	}
	return driver.completions
}

// Continuations wakes the consumer after an internal batch yields. While ready
// internal work remains, Events pauses new input admission. Async I/O still in
// flight does not pause admission, and Completions remains available throughout.
func (driver *GossipDriver) Continuations() <-chan Event {
	if driver == nil {
		return nil
	}
	return driver.internalReady
}

func (driver *GossipDriver) appendGossipInternal(events []gossip.SyncEvent) {
	if len(events) == 0 {
		return
	}
	driver.mu.Lock()
	defer driver.mu.Unlock()
	if driver.stopped {
		return
	}
	for _, event := range events {
		if event != nil {
			driver.internalEvents = append(driver.internalEvents, event)
			driver.internalPending.Add(1)
		}
	}
}

func (driver *GossipDriver) takeGossipInternal() gossip.SyncEvent {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	if driver.internalHead == len(driver.internalEvents) {
		return nil
	}
	event := driver.internalEvents[driver.internalHead]
	driver.internalEvents[driver.internalHead] = nil
	driver.internalHead++
	driver.internalPending.Add(-1)
	if driver.internalHead == len(driver.internalEvents) {
		driver.internalEvents = driver.internalEvents[:0]
		driver.internalHead = 0
	}
	return event
}

func (driver *GossipDriver) wakeGossipInternal() {
	if driver.internalPending.Load() == 0 {
		return
	}
	select {
	case driver.internalReady <- gossipContinue{}:
	default:
	}
}

// Only dropped inputs are counted here. A full input queue never drops an I/O
// result, and a receive burst must not turn into one warning per packet.
func (driver *GossipDriver) recordGossipDatagramDrop(packet *gossip.Packet) {
	dropped := driver.datagramDrops.Add(1)
	now := time.Now().UnixNano()
	next := driver.nextDropLog.Load()
	if now < next || !driver.nextDropLog.CompareAndSwap(next, now+int64(slowGossipOperationInterval)) {
		return
	}
	peerID := ""
	if packet != nil && packet.Message != nil {
		peerID = packet.Message.PeerID
	}
	driver.logGossip("warn", "packet_dropped", peerID, GossipPhaseInbound, ErrGossipEventQueueFull, map[string]any{
		"reason": "input_queue_full", "dropped_total": dropped, "queue_capacity": cap(driver.events),
	})
}
