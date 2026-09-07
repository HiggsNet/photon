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
	"github.com/HiggsNet/photon/pkg/core/zone"
)

var errDaemonStateRevisionStale = corestate.ErrVerifiedRevisionStale

type daemonDirtyFlags struct {
	IPsec    bool `json:"ipsec,omitempty"`
	Routing  bool `json:"routing,omitempty"`
	Firewall bool `json:"firewall,omitempty"`
}

type daemonReconcileStatus struct {
	IPsec    bool `json:"ipsec,omitempty"`
	Routing  bool `json:"routing,omitempty"`
	Firewall bool `json:"firewall,omitempty"`
}

type daemonStateStoreMeta struct {
	Revision          uint64
	Dirty             daemonDirtyFlags
	ReconcileProgress daemonReconcileStatus
}

type DaemonStateStore struct {
	writeMu           sync.Mutex
	mu                sync.RWMutex
	common            *corestate.Store
	runtime           *linuxRuntimeState
	commitRuntime     func(corestate.VerifiedRevision, *linuxRuntimeState) error
	dirty             daemonDirtyFlags
	reconcileProgress daemonReconcileStatus
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

// ApplyCommonLocalIntent validates, signs and persists through the common
// owner while sharing the ordering lock used by Linux runtime completions.
func (s *DaemonStateStore) ApplyCommonLocalIntent(ctx context.Context, intent corestate.LocalIntent, dryRun bool, now time.Time) (corestate.LocalIntentResult, error) {
	if s == nil || s.common == nil {
		return corestate.LocalIntentResult{}, errors.New("daemon common state store is not initialized")
	}
	if dryRun {
		return s.common.PreviewLocalIntent(intent, now)
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.common.ApplyLocalIntent(ctx, intent, now)
}

func (s *DaemonStateStore) ApplyCommonLocalIntents(ctx context.Context, intents []corestate.LocalIntent, now time.Time) (corestate.LocalIntentBatchResult, error) {
	if s == nil || s.common == nil {
		return corestate.LocalIntentBatchResult{}, errors.New("daemon common state store is not initialized")
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.common.ApplyLocalIntents(ctx, intents, now)
}

func (s *DaemonStateStore) InstallCommonIdentity(ctx context.Context, install corestate.IdentityInstall, now time.Time) (corestate.CommitResult, error) {
	if s == nil || s.common == nil {
		return corestate.CommitResult{}, errors.New("daemon common state store is not initialized")
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.common.InstallIdentity(ctx, install, now)
}

func (s *DaemonStateStore) RefreshCommonManagedAuthority(ctx context.Context, now time.Time) (corestate.CommitResult, corestate.ManagedAuthorityResult, error) {
	if s == nil || s.common == nil {
		return corestate.CommitResult{}, corestate.ManagedAuthorityResult{}, errors.New("daemon common state store is not initialized")
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.common.RefreshManagedAuthority(ctx, now)
}

func (s *DaemonStateStore) ImportCommonRecovery(ctx context.Context, input corestate.RecoveryImport, now time.Time) (corestate.RecoveryImportResult, error) {
	if s == nil || s.common == nil {
		return corestate.RecoveryImportResult{}, errors.New("daemon common state store is not initialized")
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.common.ImportRecoverySnapshot(ctx, input, now)
}

func (s *DaemonStateStore) PlanCommonPurge(now time.Time, target zone.ZonePath) (corestate.PurgeRevokedPlan, error) {
	if s == nil || s.common == nil {
		return corestate.PurgeRevokedPlan{}, errors.New("daemon common state store is not initialized")
	}
	return s.common.PlanPurgeRevoked(now, target)
}

func (s *DaemonStateStore) PurgeCommon(ctx context.Context, now time.Time, target zone.ZonePath) (corestate.PurgeRevokedResult, error) {
	if s == nil || s.common == nil {
		return corestate.PurgeRevokedResult{}, errors.New("daemon common state store is not initialized")
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.common.PurgeRevoked(ctx, now, target)
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

func (s *DaemonStateStore) commitRoutingIfRevision(revision uint64, birdInstances map[string]*BirdInstanceState, reconcile *routingReconcileState) (uint64, bool, error) {
	return s.commitRuntimeIfRevision(revision, func(runtime *linuxRuntimeState) {
		runtime.BirdInstances = photonstate.CloneBirdInstances(birdInstances)
		runtime.RoutingReconcile = photonstate.CloneRoutingReconcileState(reconcile)
	})
}

func (s *DaemonStateStore) commitIPsecIfRevision(revision uint64, transportKey *ipsecTransportKeyState, linkInstances map[string]linkInstanceState, reconcile *ipsecReconcileState) (uint64, bool, error) {
	return s.commitRuntimeIfRevision(revision, func(runtime *linuxRuntimeState) {
		runtime.IPsecTransportKey = photonstate.CloneIPsecTransportKeyState(transportKey)
		runtime.LinkInstances = photonstate.CloneLinkInstances(linkInstances)
		runtime.IPsecReconcile = photonstate.CloneIPsecReconcileState(reconcile)
	})
}

func (s *DaemonStateStore) commitFirewallIfRevision(revision uint64, endpointACLs map[string]endpointACL, reconcile *firewallReconcileState) (uint64, bool, error) {
	return s.commitRuntimeIfRevision(revision, func(runtime *linuxRuntimeState) {
		runtime.EndpointACLs = photonstate.CloneEndpointACLs(endpointACLs)
		runtime.FirewallReconcile = photonstate.CloneFirewallReconcileState(reconcile)
	})
}

// readCommonAndRuntime returns detached snapshots of the two actual state
// owners at one serialized revision.
func (s *DaemonStateStore) readCommonAndRuntime() (corestate.View, *linuxRuntimeState) {
	if s == nil || s.common == nil {
		return corestate.View{}, nil
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	common := s.common.ReadView()
	s.mu.RLock()
	runtime := photonlinux.CloneRuntimeState(s.runtime)
	s.mu.RUnlock()
	return common, runtime
}

func (s *DaemonStateStore) metaLocked() daemonStateStoreMeta {
	return daemonStateStoreMeta{
		Dirty:             s.dirty,
		ReconcileProgress: s.reconcileProgress,
	}
}

func (s *DaemonStateStore) Meta() daemonStateStoreMeta {
	if s == nil {
		return daemonStateStoreMeta{}
	}
	s.mu.RLock()
	meta := s.metaLocked()
	s.mu.RUnlock()
	if s.common != nil {
		meta.Revision = uint64(s.common.VerifiedRevision())
	}
	return meta
}

func (s *DaemonStateStore) SetDirty(flags daemonDirtyFlags) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dirty = flags
}

func (s *DaemonStateStore) SetReconcileProgress(status daemonReconcileStatus) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reconcileProgress = status
}
