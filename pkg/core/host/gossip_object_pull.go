package host

import (
	"context"
	"errors"
	"sync"

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

type gossipObjectPullRound struct {
	session *gossip.SyncSession
	ctx     context.Context
	cancel  context.CancelFunc
	mu      sync.Mutex // serializes admission with round cancellation
	running int
}

func (round *gossipObjectPullRound) begin() bool {
	round.mu.Lock()
	defer round.mu.Unlock()
	if round.ctx.Err() != nil {
		return false
	}
	round.running++
	return true
}

func (round *gossipObjectPullRound) end() {
	round.mu.Lock()
	defer round.mu.Unlock()
	round.running--
}

func (round *gossipObjectPullRound) stop() (drained bool) {
	round.mu.Lock()
	defer round.mu.Unlock()
	round.cancel()
	return round.running == 0
}

type gossipObjectPullJob struct {
	action gossip.StartObjectPullAction
	round  *gossipObjectPullRound
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
	driver.objectPullContext = workerCtx
	driver.objectPullCancel = cancel
	driver.objectPullJobs = make(chan gossipObjectPullJob, buffer)
	jobs := driver.objectPullJobs
	driver.objectPullWG.Add(workers)
	driver.mu.Unlock()

	for range workers {
		go driver.runGossipObjectPullWorker(workerCtx, jobs, executor)
	}
	return nil
}

// SubmitGossipObjectPull never blocks the single-writer event loop.
func (driver *GossipDriver) SubmitGossipObjectPull(action gossip.StartObjectPullAction) error {
	return driver.submitGossipObjectPull(nil, action)
}

func (driver *GossipDriver) submitGossipObjectPull(session *gossip.SyncSession, action gossip.StartObjectPullAction) error {
	if driver == nil {
		return ErrGossipDriverStopped
	}
	driver.mu.RLock()
	defer driver.mu.RUnlock()
	jobs := driver.objectPullJobs
	if driver.stopped {
		return ErrGossipDriverStopped
	}
	if jobs == nil {
		return ErrGossipObjectPullExecutorRequired
	}
	var round *gossipObjectPullRound
	if session != nil {
		round = driver.objectPullRounds[action.PeerID]
		if round == nil {
			ctx, cancel := context.WithCancel(driver.objectPullContext)
			round = &gossipObjectPullRound{session: session, ctx: ctx, cancel: cancel}
			if driver.objectPullRounds == nil {
				driver.objectPullRounds = make(map[string]*gossipObjectPullRound)
			}
			driver.objectPullRounds[action.PeerID] = round
		}
	}
	select {
	case jobs <- gossipObjectPullJob{action: action, round: round}:
		return nil
	default:
		return ErrGossipObjectPullQueueFull
	}
}

func (driver *GossipDriver) gossipObjectPullDraining(peerID string) bool {
	round := driver.objectPullRounds[peerID]
	return round != nil && round.ctx.Err() != nil
}

// completeGossipObjectPull runs on the event loop after the worker releases
// its TCP slot. Stale results only acknowledge that a job has drained.
func (driver *GossipDriver) completeGossipObjectPull(round *gossipObjectPullRound) bool {
	peerID := round.session.PeerID
	if driver.objectPullRounds[peerID] != round {
		return false
	}
	if round.ctx.Err() != nil {
		round.mu.Lock()
		drained := round.running == 0
		round.mu.Unlock()
		if drained {
			delete(driver.objectPullRounds, peerID)
			driver.startDeferredGossipSession(peerID)
		}
		return false
	}
	return driver.Gossip.Session(peerID) == round.session
}

func (driver *GossipDriver) runGossipObjectPullWorker(ctx context.Context, jobs <-chan gossipObjectPullJob, executor *GossipObjectPullExecutor) {
	defer driver.objectPullWG.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case job := <-jobs:
			action := job.action
			pullCtx := ctx
			if job.round != nil {
				if !job.round.begin() {
					continue
				}
				pullCtx = job.round.ctx
			}
			now := driver.schedulerForRead().clock.Now()
			driver.observeObjectPullAttempt(action.PeerID, action.Zone, now)
			driver.logGossip("debug", "worker_start", action.PeerID, GossipPhaseObjectPull, nil, map[string]any{"zone": action.Zone})
			completion := executor.PullGossipObject(pullCtx, action)
			if job.round != nil {
				job.round.end()
			}
			if pullCtx.Err() == nil {
				driver.observeObjectPullResult(completion, driver.schedulerForRead().clock.Now())
			}
			driver.logGossip("debug", "worker_done", completion.PeerID, GossipPhaseObjectPull, completion.Err, map[string]any{
				"zone": completion.Zone, "addr": completion.Addr, "bytes": completion.Bytes, "ok": completion.Err == nil,
			})
			event := GossipEvent{Value: &gossip.ObjectPullResultEvent{
				PeerID: completion.PeerID, Zone: completion.Zone,
				Snapshot: completion.Snapshot, Err: completion.Err,
				Unreachable: completion.Unreachable,
			}, pullRound: job.round}
			select {
			case driver.completions <- event:
			case <-ctx.Done():
				return
			}
		}
	}
}
