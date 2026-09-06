// Package host owns the platform-neutral driver resources shared by Photon
// hosts. Protocol packages describe policy and actions; GossipDriver owns the
// bounded queue and scheduling mechanism used to execute those actions.
package host

import (
	"context"
	"encoding/hex"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	"github.com/HiggsNet/photon/pkg/core/observability"
)

const (
	DefaultEventBuffer            = 64
	GossipTimerNamespace          = "gossip"
	DefaultPeerObservabilityLimit = 2048
	DefaultPeerObservabilityTTL   = 24 * time.Hour
)

var (
	ErrGossipEventQueueFull = errors.New("gossip driver event queue full")
	ErrGossipDriverStopped  = errors.New("gossip driver stopped")
)

// Event is delivered to the single-writer GossipDriver event loop.
type Event interface {
	isHostEvent()
}

// GossipEvent carries an externally produced gossip protocol event.
type GossipEvent struct {
	Value gossip.SyncEvent
}

func (GossipEvent) isHostEvent() {}

// GossipPacketReceived carries one packet accepted by the injected datagram
// receiver. Packets and protocol timer/completion events share the same
// bounded driver queue, preserving one backpressure and ordering boundary.
type GossipPacketReceived struct {
	Packet *gossip.Packet
}

func (GossipPacketReceived) isHostEvent() {}

// GossipDriver owns the common gossip engine, bounded event queue and scheduler.
// Platform composition roots inject datagram I/O around this object;
// they do not create a second protocol queue or timer manager.
type GossipDriver struct {
	Gossip        *gossip.Engine
	Observability *observability.PeerObservabilityStore

	gossipState  GossipStateStore
	gossipConfig GossipDriverConfig

	events chan Event

	mu                       sync.RWMutex
	scheduler                *Scheduler
	objectPullCancel         context.CancelFunc
	objectPullJobs           chan gossip.StartObjectPullAction
	objectPullWG             sync.WaitGroup
	objectPullPending        atomic.Int64
	objectPullServerCancel   context.CancelFunc
	objectPullServerListener net.Listener
	objectPullServerWG       sync.WaitGroup
	gossipChunks             *gossip.ChunkAssemblyStore
	gossipSentChunks         *gossip.SentChunkCache
	gossipTransport          *gossip.Transport
	datagramReceiver         datagramReceiver
	datagramCancel           context.CancelFunc
	datagramWG               sync.WaitGroup
	stopped                  bool
}

func NewGossipDriver(clock Clock, eventBuffer int, gossipState GossipStateStore, gossipConfig GossipDriverConfig) *GossipDriver {
	if eventBuffer <= 0 {
		eventBuffer = DefaultEventBuffer
	}
	driver := &GossipDriver{
		Gossip:           gossip.NewEngine(),
		Observability:    observability.NewPeerObservabilityStore(DefaultPeerObservabilityLimit, DefaultPeerObservabilityTTL),
		gossipState:      gossipState,
		gossipConfig:     cloneGossipDriverConfig(gossipConfig),
		events:           make(chan Event, eventBuffer),
		gossipChunks:     gossip.NewChunkAssemblyStore(),
		gossipSentChunks: gossip.NewSentChunkCache(),
	}
	driver.scheduler = NewScheduler(clock, driver.events)
	return driver
}

func (driver *GossipDriver) Events() <-chan Event {
	if driver == nil {
		return nil
	}
	return driver.events
}

func (driver *GossipDriver) PendingEventCount() int {
	if driver == nil {
		return 0
	}
	return len(driver.events)
}

// GossipConfig returns a detached snapshot of the protocol configuration
// currently owned by GossipDriver.
func (driver *GossipDriver) GossipConfig() GossipDriverConfig {
	if driver == nil {
		return GossipDriverConfig{}
	}
	driver.mu.RLock()
	defer driver.mu.RUnlock()
	return cloneGossipDriverConfig(driver.gossipConfig)
}

// ReplaceGossipConfig atomically replaces protocol/discovery configuration
// during a daemon-controlled reload.
func (driver *GossipDriver) ReplaceGossipConfig(config GossipDriverConfig) error {
	if driver == nil {
		return ErrGossipDriverStopped
	}
	driver.mu.Lock()
	defer driver.mu.Unlock()
	if driver.stopped {
		return ErrGossipDriverStopped
	}
	driver.gossipConfig = cloneGossipDriverConfig(config)
	return nil
}

// PostGossip enqueues an external protocol event without blocking. Producers
// receive explicit backpressure; scheduler delivery uses its own blocking,
// shutdown-aware path so timeouts are never silently dropped.
func (driver *GossipDriver) PostGossip(event gossip.SyncEvent) error {
	if driver == nil || event == nil {
		return nil
	}
	driver.mu.RLock()
	stopped := driver.stopped
	driver.mu.RUnlock()
	if stopped {
		return ErrGossipDriverStopped
	}
	select {
	case driver.events <- GossipEvent{Value: event}:
		return nil
	default:
		return ErrGossipEventQueueFull
	}
}

// GossipSessionEventFor converts a host event into one session-FSM event. Timer
// generations are accepted here, at the single-writer boundary, so a queued
// timeout made stale by cancel/replace cannot advance a session.
func (driver *GossipDriver) GossipSessionEventFor(event Event) (gossip.SyncEvent, bool) {
	if driver == nil || event == nil {
		return nil, false
	}
	switch typed := event.(type) {
	case GossipEvent:
		return typed.Value, typed.Value != nil
	case TimerFired:
		if typed.ID.Namespace != GossipTimerNamespace && typed.ID.Namespace != GossipChunkRepairNamespace {
			return nil, false
		}
		if !driver.schedulerForRead().Accept(typed) {
			return nil, false
		}
		if typed.ID.Namespace == GossipChunkRepairNamespace {
			transferID, err := hex.DecodeString(typed.ID.Key)
			if err != nil {
				return nil, false
			}
			return &gossip.ChunkRepairTimeoutEvent{PeerID: typed.ID.Owner, TransferID: transferID}, true
		}
		if typed.ID.Namespace != GossipTimerNamespace {
			return nil, false
		}
		switch typed.ID.Key {
		case gossip.TimerKindRound:
			return &gossip.RoundTimeoutEvent{PeerID: typed.ID.Owner}, true
		case gossip.TimerKindCatalogPage:
			return &gossip.CatalogPageTimeoutEvent{PeerID: typed.ID.Owner}, true
		default:
			return nil, false
		}
	default:
		return nil, false
	}
}

// ApplyGossipTimerAction executes the scheduling subset of gossip actions.
// Deadline choice remains in the protocol FSM; only timer resources live here.
func (driver *GossipDriver) ApplyGossipTimerAction(action gossip.SyncAction) (bool, error) {
	if driver == nil {
		return false, ErrGossipDriverStopped
	}
	switch typed := action.(type) {
	case gossip.StartTimerAction:
		_, err := driver.schedulerForRead().Schedule(TimerID{
			Namespace: GossipTimerNamespace,
			Owner:     typed.PeerID,
			Key:       typed.Kind,
		}, typed.Deadline)
		return true, err
	case gossip.CancelTimerAction:
		driver.schedulerForRead().Cancel(TimerID{
			Namespace: GossipTimerNamespace,
			Owner:     typed.PeerID,
			Key:       typed.Kind,
		})
		return true, nil
	default:
		return false, nil
	}
}

func (driver *GossipDriver) CancelGossipTimers(peerID string) {
	if driver == nil || peerID == "" {
		return
	}
	driver.schedulerForRead().CancelOwner(GossipTimerNamespace, peerID)
}

// ResetScheduler replaces only the driver scheduling resource. It is used by
// deterministic tests before the event loop starts; protocol sessions remain
// owned by the same gossip Engine.
func (driver *GossipDriver) ResetScheduler(clock Clock) {
	if driver == nil {
		return
	}
	driver.mu.Lock()
	if driver.stopped {
		driver.mu.Unlock()
		return
	}
	old := driver.scheduler
	driver.scheduler = NewScheduler(clock, driver.events)
	driver.mu.Unlock()
	old.Stop()
}

func (driver *GossipDriver) Stop() {
	if driver == nil {
		return
	}
	driver.mu.Lock()
	if driver.stopped {
		driver.mu.Unlock()
		return
	}
	driver.stopped = true
	scheduler := driver.scheduler
	objectPullCancel := driver.objectPullCancel
	objectPullServerCancel := driver.objectPullServerCancel
	objectPullServerListener := driver.objectPullServerListener
	datagramCancel := driver.datagramCancel
	driver.mu.Unlock()
	if datagramCancel != nil {
		datagramCancel()
	}
	if objectPullCancel != nil {
		objectPullCancel()
	}
	if objectPullServerCancel != nil {
		objectPullServerCancel()
	}
	if objectPullServerListener != nil {
		_ = objectPullServerListener.Close()
	}
	scheduler.Stop()
	driver.datagramWG.Wait()
	driver.objectPullWG.Wait()
	driver.objectPullServerWG.Wait()
	driver.objectPullPending.Store(0)
	if driver.gossipChunks != nil {
		driver.gossipChunks.Close()
	}
}

func (driver *GossipDriver) schedulerForRead() *Scheduler {
	driver.mu.RLock()
	defer driver.mu.RUnlock()
	return driver.scheduler
}

// Clock returns the standard driver clock. A custom now function is useful
// when protocol deadlines and scheduler time must share a deterministic base.
func NewClock(now func() time.Time) Clock {
	if now == nil {
		now = time.Now
	}
	return &systemClock{now: now}
}
