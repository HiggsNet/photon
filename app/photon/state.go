package main

import (
	"errors"
	"reflect"
	"sync"

	"github.com/HiggsNet/photon/internal/photonlinux"
	photonstate "github.com/HiggsNet/photon/internal/state"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

// State is the process-local persistent state owner. It owns the single
// bbolt handle and keeps common and Linux state as separate typed partitions.
type State struct {
	db         *corestate.BoltStore
	Common     *corestate.Store
	linuxMu    sync.RWMutex
	linuxState *photonlinux.LinuxState
}

func newState(db *corestate.BoltStore, common *corestate.Store, linuxState *photonlinux.LinuxState) *State {
	return &State{
		db:         db,
		Common:     common,
		linuxState: photonlinux.CloneLinuxState(linuxState),
	}
}

func (state *State) Close() error {
	if state == nil {
		return nil
	}
	if state.Common != nil {
		state.Common.Close()
	}
	if state.db != nil {
		return state.db.Close()
	}
	return nil
}

func (state *State) ReadLinux() *photonlinux.LinuxState {
	if state == nil {
		return nil
	}
	state.linuxMu.RLock()
	linux := photonlinux.CloneLinuxState(state.linuxState)
	state.linuxMu.RUnlock()
	return linux
}

func (state *State) ReplaceIPsecTransportKeyIfRevision(sourceRevision corestate.VerifiedRevision, key *photonstate.IPsecTransportKeyState) (bool, error) {
	return state.updateLinuxStateIfRevision(sourceRevision, func(candidate *photonlinux.LinuxState) {
		candidate.IPsecTransportKey = photonstate.CloneIPsecTransportKeyState(key)
	})
}

func (state *State) ReplaceEndpointACLsIfRevision(sourceRevision corestate.VerifiedRevision, endpointACLs map[string]photonstate.EndpointACL) (bool, error) {
	return state.updateLinuxStateIfRevision(sourceRevision, func(candidate *photonlinux.LinuxState) {
		candidate.EndpointACLs = photonstate.CloneEndpointACLs(endpointACLs)
	})
}

func (state *State) updateLinuxStateIfRevision(sourceRevision corestate.VerifiedRevision, update func(*photonlinux.LinuxState)) (bool, error) {
	if state == nil || state.Common == nil {
		return false, errors.New("state is not initialized")
	}
	if update == nil {
		return false, errors.New("linux state update is nil")
	}
	state.linuxMu.Lock()
	defer state.linuxMu.Unlock()
	if state.Common.VerifiedRevision() != sourceRevision {
		return false, corestate.ErrVerifiedRevisionStale
	}
	candidate := photonlinux.CloneLinuxState(state.linuxState)
	update(candidate)
	if reflect.DeepEqual(state.linuxState, candidate) {
		return false, nil
	}
	if state.db != nil {
		if err := photonlinux.CommitLinuxState(state.db, sourceRevision, candidate); err != nil {
			return false, err
		}
	}
	state.linuxState = candidate
	return true, nil
}
