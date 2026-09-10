package main

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"time"

	"github.com/HiggsNet/photon/internal/photonlinux"
	photonstate "github.com/HiggsNet/photon/internal/state"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

var errDaemonStateRevisionStale = corestate.ErrVerifiedRevisionStale

type DaemonStateStore struct {
	writeMu       sync.Mutex
	mu            sync.RWMutex
	common        *corestate.Store
	runtime       *linuxRuntimeState
	commitRuntime func(corestate.VerifiedRevision, *linuxRuntimeState) error
}

type protocolPublishResult struct {
	RuntimeCommitted bool
	Common           corestate.LocalIntentBatchResult
}

func newPersistedDaemonStateStore(common *corestate.Store, runtime *linuxRuntimeState, boltStore *corestate.BoltStore) (*DaemonStateStore, error) {
	if boltStore == nil {
		return nil, errors.New("bbolt state store is nil")
	}
	return newDaemonStateStore(common, runtime, func(revision corestate.VerifiedRevision, candidate *linuxRuntimeState) error {
		return photonlinux.CommitRuntimeState(boltStore, revision, candidate)
	})
}

func newDaemonStateStore(common *corestate.Store, runtime *linuxRuntimeState, commitRuntime func(corestate.VerifiedRevision, *linuxRuntimeState) error) (*DaemonStateStore, error) {
	if common == nil {
		return nil, errors.New("common state store is nil")
	}
	store := &DaemonStateStore{
		common:        common,
		runtime:       photonlinux.CloneRuntimeState(runtime),
		commitRuntime: commitRuntime,
	}
	return store, nil
}

// publishLocalProtocols commits private/platform runtime before publishing
// public records that may reference it. Both commits are serialized against
// one verified revision and use the same process-wide BoltStore handle.
func (s *DaemonStateStore) publishLocalProtocols(ctx context.Context, sourceRevision uint64, intents []corestate.LocalIntent, runtime *linuxRuntimeState, now time.Time) (protocolPublishResult, error) {
	var out protocolPublishResult
	if s == nil || s.common == nil {
		return out, errors.New("daemon common state store is not initialized")
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	currentRevision := uint64(s.common.VerifiedRevision())
	s.mu.RLock()
	currentRuntime := photonlinux.CloneRuntimeState(s.runtime)
	s.mu.RUnlock()
	if currentRevision != sourceRevision {
		return out, errDaemonStateRevisionStale
	}
	if runtime != nil && !reflect.DeepEqual(currentRuntime, runtime) {
		if s.commitRuntime != nil {
			if err := s.commitRuntime(corestate.VerifiedRevision(sourceRevision), photonlinux.CloneRuntimeState(runtime)); err != nil {
				return out, err
			}
		}
		s.mu.Lock()
		s.runtime = photonlinux.CloneRuntimeState(runtime)
		s.mu.Unlock()
		out.RuntimeCommitted = true
	}
	if len(intents) > 0 {
		result, err := s.common.ApplyLocalIntentsAtRevision(ctx, intents, now, corestate.VerifiedRevision(sourceRevision))
		if err != nil {
			return out, err
		}
		out.Common = result
	}
	return out, nil
}

func (s *DaemonStateStore) commitRuntimeIfRevision(sourceRevision uint64, mutate func(*linuxRuntimeState)) (uint64, bool, error) {
	if s == nil || s.common == nil {
		return 0, false, errors.New("daemon composed state is not initialized")
	}
	if mutate == nil {
		return sourceRevision, false, errors.New("linux runtime mutation is nil")
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	currentRevision := uint64(s.common.VerifiedRevision())
	s.mu.RLock()
	baseRuntime := photonlinux.CloneRuntimeState(s.runtime)
	s.mu.RUnlock()
	if currentRevision != sourceRevision {
		return currentRevision, false, nil
	}
	candidate := photonlinux.CloneRuntimeState(baseRuntime)
	mutate(candidate)
	if reflect.DeepEqual(baseRuntime, candidate) {
		return sourceRevision, false, nil
	}
	if s.commitRuntime != nil {
		if err := s.commitRuntime(corestate.VerifiedRevision(sourceRevision), photonlinux.CloneRuntimeState(candidate)); err != nil {
			return sourceRevision, false, err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.runtime = candidate
	return sourceRevision, true, nil
}

func (s *DaemonStateStore) commitEndpointACLsIfRevision(revision uint64, endpointACLs map[string]endpointACL) (uint64, bool, error) {
	return s.commitRuntimeIfRevision(revision, func(runtime *linuxRuntimeState) {
		runtime.EndpointACLs = photonstate.CloneEndpointACLs(endpointACLs)
	})
}

func (s *DaemonStateStore) readLinuxState() *linuxRuntimeState {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	runtime := photonlinux.CloneRuntimeState(s.runtime)
	s.mu.RUnlock()
	return runtime
}
