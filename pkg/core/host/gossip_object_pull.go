package host

import (
	"context"
	"errors"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

const (
	DefaultGossipObjectPullWorkers = 4
	DefaultGossipObjectPullBuffer  = 64
)

var (
	ErrGossipObjectPullExecutorRequired = errors.New("gossip object-pull executor is required")
	ErrGossipObjectPullAlreadyStarted   = errors.New("gossip object-pull workers already started")
	ErrGossipObjectPullQueueFull        = errors.New("gossip object-pull queue full")
)

// GossipObjectPullCompletion is the platform-neutral result returned by an
// object-pull controller. GossipDriver owns its conversion to an FSM event and the
// queue backpressure contract.
type GossipObjectPullCompletion struct {
	PeerID      string
	Zone        zone.ZonePath
	Addr        string
	Bytes       int
	Unreachable bool
	Snapshot    *corestate.ZoneSnapshot
	Err         error
}

// StartGossipObjectPullWorkers starts GossipDriver's only object-pull worker group.
// Platform composition supplies the TCP I/O capability, not another queue.
func (driver *GossipDriver) StartGossipObjectPullWorkers(ctx context.Context, executor *GossipObjectPullExecutor, workers, buffer int) error {
	if driver == nil {
		return ErrGossipDriverStopped
	}
	if executor == nil {
		return ErrGossipObjectPullExecutorRequired
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if workers <= 0 {
		workers = DefaultGossipObjectPullWorkers
	}
	if buffer <= 0 {
		buffer = DefaultGossipObjectPullBuffer
	}
	driver.mu.Lock()
	if driver.stopped {
		driver.mu.Unlock()
		return ErrGossipDriverStopped
	}
	if driver.objectPullJobs != nil {
		driver.mu.Unlock()
		return ErrGossipObjectPullAlreadyStarted
	}
	workerCtx, cancel := context.WithCancel(ctx)
	driver.objectPullCancel = cancel
	driver.objectPullJobs = make(chan gossip.StartObjectPullAction, buffer)
	jobs := driver.objectPullJobs
	driver.mu.Unlock()

	for range workers {
		driver.objectPullWG.Add(1)
		go driver.runGossipObjectPullWorker(workerCtx, jobs, executor)
	}
	return nil
}

// SubmitGossipObjectPull never blocks the single-writer event loop.
func (driver *GossipDriver) SubmitGossipObjectPull(action gossip.StartObjectPullAction) error {
	if driver == nil {
		return ErrGossipDriverStopped
	}
	driver.mu.RLock()
	stopped := driver.stopped
	jobs := driver.objectPullJobs
	driver.mu.RUnlock()
	if stopped {
		return ErrGossipDriverStopped
	}
	if jobs == nil {
		return ErrGossipObjectPullExecutorRequired
	}
	driver.objectPullPending.Add(1)
	select {
	case jobs <- action:
		return nil
	default:
		driver.objectPullPending.Add(-1)
		return ErrGossipObjectPullQueueFull
	}
}

func (driver *GossipDriver) PendingGossipObjectPullCount() int {
	if driver == nil {
		return 0
	}
	return int(driver.objectPullPending.Load())
}

func (driver *GossipDriver) runGossipObjectPullWorker(ctx context.Context, jobs <-chan gossip.StartObjectPullAction, executor *GossipObjectPullExecutor) {
	defer driver.objectPullWG.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case action := <-jobs:
			now := driver.schedulerForRead().clock.Now()
			driver.observeObjectPullAttempt(action.PeerID, action.Zone, now)
			driver.logGossip("debug", "worker_start", action.PeerID, GossipPhaseObjectPull, nil, map[string]any{"zone": action.Zone})
			completion := executor.PullGossipObject(ctx, action)
			if completion.PeerID == "" {
				completion.PeerID = action.PeerID
			}
			if !completion.Zone.Valid() {
				completion.Zone = action.Zone
			}
			driver.observeObjectPullResult(completion, driver.schedulerForRead().clock.Now())
			driver.logGossip("debug", "worker_done", completion.PeerID, GossipPhaseObjectPull, completion.Err, map[string]any{
				"zone": completion.Zone, "bytes": completion.Bytes, "ok": completion.Err == nil,
			})
			event := GossipEvent{Value: &gossip.ObjectPullResultEvent{
				PeerID: completion.PeerID, Zone: completion.Zone,
				Snapshot: completion.Snapshot, Err: completion.Err,
			}}
			select {
			case driver.events <- event:
				driver.objectPullPending.Add(-1)
			case <-ctx.Done():
				driver.objectPullPending.Add(-1)
				return
			}
		}
	}
}
