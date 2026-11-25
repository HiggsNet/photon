package ipsec

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

const (
	LinkStatePending        = "pending"
	LinkStateConfiguring    = "configuring"
	LinkStateConnecting     = "connecting"
	LinkStateWaitingInbound = "waiting_inbound"
	LinkStateUp             = "up"
	LinkStateDegraded       = "degraded"
	LinkStateStale          = "stale"
	LinkStateRemoving       = "removing"
	LinkStateDown           = "down"
	LinkStateError          = "error"

	ReconcileActionAdopt              = "adopt"
	ReconcileActionCreate             = "create"
	ReconcileActionUpdate             = "update"
	ReconcileActionRepair             = "repair"
	ReconcileActionTeardown           = "teardown"
	ReconcileActionNoop               = "noop"
	ReconcileActionPrepareRotate      = "prepare_rotate"
	ReconcileActionInitiateRotate     = "initiate_rotate"
	ReconcileActionCommitRotate       = "commit_rotate"
	ReconcileActionCleanupRotate      = "cleanup_rotate"
	ReconcileActionCleanupDuplicateSA = "cleanup_duplicate_sa"
	ReconcileActionPrepareStandby     = "prepare_standby"

	RotatePhaseIdle        = ""
	RotatePhasePreparing   = "preparing"
	RotatePhaseTestingNew  = "testing_new"
	RotatePhaseDualRunning = "dual_running"
	RotatePhaseDraining    = "draining"
	RotatePhaseCutover     = "cutover"
	RotatePhaseCleanup     = "cleanup"

	TakeoverPhaseIdle     = ""
	TakeoverPhaseDelay    = "delay"
	TakeoverPhaseActive   = "active"
	TakeoverPhaseCooldown = "cooldown"

	defaultLinkEstablishGrace    = 3 * time.Minute
	maxStagedInitiateAttempts    = 5
	initialStagedInitiateBackoff = 5 * time.Second
	maximumStagedInitiateBackoff = 30 * time.Second
)

type LinkInstance struct {
	ID                    string
	GroupID               string
	PeerZone              zone.ZonePath
	TransportKind         string
	LinkID                string
	PathKey               string
	TransportID           string
	DesiredSpecHash       string
	ActualState           string
	InterfaceName         string
	XFRMIfID              uint32
	LocalTunnelAddr       netip.Addr
	PeerTunnelAddr        netip.Addr
	IKEName               string
	ChildSAName           string
	Endpoint              string
	SelectedContact       ContactPoint
	RemoteGeneration      uint64
	StagedGeneration      uint64
	StagedSpecHash        string
	RotatePhase           string
	StagedIKEName         string
	StagedChildSAName     string
	StagedInterfaceName   string
	StagedXFRMIfID        uint32
	StagedLocalTunnelAddr netip.Addr
	StagedPeerTunnelAddr  netip.Addr
	RotateDeadline        int64
	StagedAttemptCount    int
	StagedNextAttempt     int64
	LastFailure           error
	FailureCount          int
	BackoffUntil          int64
	LastTransition        int64
	Owner                 ResourceOwner

	// Bidirectional takeover state (Phase 4.5).
	InitiatorRole       string
	TakeoverPhase       string
	TakeoverStartedAt   int64
	TakeoverUntil       int64
	LastTakeoverFailure error
	ObservedInitiator   string
	SAAbsentSince       int64
	SAAbsentCount       int
}

type ResourceOwner struct {
	Manager     string
	GroupID     string
	InstanceID  string
	LinkID      string
	TransportID string
	Token       string
}

type ReconcileInputs struct {
	Desired               []TransportLinkSpec
	Instances             map[string]LinkInstance
	Connections           []ConnectionState
	SAs                   []SAState
	MissingXFRMLinks      map[string]TransportLinkSpec
	MissingDesiredXFRM    map[string]bool
	Now                   time.Time
	Revoked               map[zone.ZonePath]bool
	Roles                 map[string]string
	GroupSpecs            map[string]LinkGroupSpec
	GroupBackoff          map[string]BackoffPolicy
	GroupRotateRetention  map[string]int
	RotateActivationReady map[string]bool
	RotateCutoverReady    map[string]bool
	PrepareStandby        bool
	TakeoverNotBefore     time.Time
	ForceUpdates          map[string]string
}

type ReconcileResult struct {
	Actions   []ReconcileAction
	Instances map[string]LinkInstance
	Err       error
}

type ReconcileAction struct {
	Action     string
	Spec       *TransportLinkSpec
	Instance   *LinkInstance
	Reason     string
	SAUniqueID uint64
}

func NewLinkInstance(spec TransportLinkSpec, state string, now time.Time) LinkInstance {
	if state == "" {
		state = LinkStatePending
	}
	inst := LinkInstance{
		ID:               LinkInstanceID(spec),
		GroupID:          spec.OverlayID,
		PeerZone:         spec.PeerZone,
		TransportKind:    spec.Provider,
		LinkID:           LinkInstanceID(spec),
		PathKey:          spec.PathKey,
		TransportID:      spec.TransportID,
		DesiredSpecHash:  TransportLinkSpecHash(spec),
		ActualState:      state,
		InterfaceName:    spec.InterfaceName,
		XFRMIfID:         spec.XFRMIfID,
		LocalTunnelAddr:  spec.LocalTunnelAddr,
		PeerTunnelAddr:   spec.PeerTunnelAddr,
		IKEName:          spec.TransportID,
		ChildSAName:      ChildSAName(spec),
		Endpoint:         endpointForSpec(spec),
		RemoteGeneration: spec.Generation,
		LastTransition:   now.Unix(),
		InitiatorRole:    spec.InitiatorRole,
		Owner: ResourceOwner{
			Manager:     "photon",
			GroupID:     spec.OverlayID,
			InstanceID:  LinkInstanceID(spec),
			LinkID:      LinkInstanceID(spec),
			TransportID: spec.TransportID,
			Token:       ResourceOwnerToken(LinkInstanceID(spec), spec.TransportID),
		},
	}
	if point, ok := firstContactPoint(spec.ContactPoints); ok {
		inst.SelectedContact = point
		inst.RemoteGeneration = point.Generation
		inst.Endpoint = contactEndpoint(point)
	}
	return inst
}

func LinkInstanceID(spec TransportLinkSpec) string {
	if spec.LinkID != "" {
		return spec.LinkID
	}
	if spec.TransportID != "" {
		return spec.TransportID
	}
	pathKey := spec.PathKey
	if pathKey == "" {
		pathKey = DefaultPathKey
	}
	return StableLinkID(spec.LocalZone, spec.PeerZone, spec.OverlayID, pathKey)
}

func findMigratableLinkInstance(instances map[string]LinkInstance, spec TransportLinkSpec) (LinkInstance, bool) {
	legacyIDs := []string{
		spec.TransportID,
		LegacyStableTransportID(spec.LocalZone, spec.PeerZone, spec.OverlayID),
	}
	if spec.PathKey != "" && strings.HasPrefix(spec.PathKey, "family:") {
		legacyIDs = append(legacyIDs, LegacyStableTransportID(spec.LocalZone, spec.PeerZone, spec.OverlayID, strings.TrimPrefix(spec.PathKey, "family:")))
	}
	for _, id := range legacyIDs {
		if id == "" || id == LinkInstanceID(spec) {
			continue
		}
		if inst, ok := instances[id]; ok && migratableInstanceMatches(inst, spec) {
			return inst, true
		}
	}
	for _, inst := range instances {
		if migratableInstanceMatches(inst, spec) {
			return inst, true
		}
	}
	return LinkInstance{}, false
}

func migratableInstanceMatches(inst LinkInstance, spec TransportLinkSpec) bool {
	if inst.LinkID != "" && inst.LinkID != LinkInstanceID(spec) {
		return false
	}
	if inst.GroupID != "" && inst.GroupID != spec.OverlayID {
		return false
	}
	if inst.PeerZone != "" && inst.PeerZone != spec.PeerZone {
		return false
	}
	if inst.TransportKind != "" && inst.TransportKind != spec.Provider {
		return false
	}
	return inst.TransportID == spec.TransportID ||
		inst.TransportID == LegacyStableTransportID(spec.LocalZone, spec.PeerZone, spec.OverlayID) ||
		(strings.HasPrefix(spec.PathKey, "family:") && inst.TransportID == LegacyStableTransportID(spec.LocalZone, spec.PeerZone, spec.OverlayID, strings.TrimPrefix(spec.PathKey, "family:")))
}

func TransportLinkSpecHash(spec TransportLinkSpec) string {
	// Runtime metadata must not change the desired spec hash; otherwise
	// standby -> takeover -> converged transitions and per-address
	// success/failure/backoff fluctuations would emit unnecessary update
	// actions for an otherwise identical StrongSwan configuration.
	spec.InitiatorRole = ""
	for i := range spec.ContactPoints {
		cp := &spec.ContactPoints[i]
		cp.Successes = 0
		cp.Failures = 0
		cp.BackoffUntil = time.Time{}
		cp.RankReason = ""
	}
	data, err := json.Marshal(spec)
	if err != nil {
		panic(fmt.Sprintf("marshal transport link spec: %v", err))
	}
	sum := photoncrypto.Hash(data)
	return hex.EncodeToString(sum[:])
}

func ResourceOwnerToken(linkID, runtimeConnectionID string) string {
	sum := photoncrypto.Hash([]byte("photon.ipsec.owner.v2"), []byte{0}, []byte(linkID), []byte{0}, []byte(runtimeConnectionID), []byte{0}, []byte("owner-token"))
	return hex.EncodeToString(sum[:8])
}

func LegacyResourceOwnerToken(groupID, instanceID, transportID string) string {
	sum := photoncrypto.Hash([]byte("photon.ipsec.owner.v1"), []byte{0}, []byte(groupID), []byte{0}, []byte(instanceID), []byte{0}, []byte(transportID))
	return hex.EncodeToString(sum[:8])
}

func (o ResourceOwner) Validate(instance LinkInstance) error {
	if o.Manager != "photon" {
		return fmt.Errorf("resource is not managed by photon")
	}
	if o.GroupID == "" || o.InstanceID == "" || o.TransportID == "" {
		return fmt.Errorf("resource owner is incomplete")
	}
	if o.GroupID != instance.GroupID {
		return fmt.Errorf("owner group %q does not match instance group %q", o.GroupID, instance.GroupID)
	}
	if o.InstanceID != instance.ID {
		return fmt.Errorf("owner instance %q does not match instance %q", o.InstanceID, instance.ID)
	}
	if o.TransportID != instance.TransportID {
		return fmt.Errorf("owner transport %q does not match instance transport %q", o.TransportID, instance.TransportID)
	}
	if o.LinkID != "" && instance.LinkID != "" && o.LinkID != instance.LinkID {
		return fmt.Errorf("owner link %q does not match instance link %q", o.LinkID, instance.LinkID)
	}
	wantToken := ResourceOwnerToken(firstNonEmptyString(instance.LinkID, o.InstanceID), o.TransportID)
	legacyToken := LegacyResourceOwnerToken(o.GroupID, o.InstanceID, o.TransportID)
	if o.Token != "" && o.Token != wantToken && o.Token != legacyToken {
		return fmt.Errorf("resource owner token mismatch")
	}
	if instance.TransportID != "" && !strings.HasPrefix(instance.TransportID, "ipsec-") {
		return fmt.Errorf("transport id %q does not use photon ipsec naming", instance.TransportID)
	}
	if instance.InterfaceName != "" && !strings.HasPrefix(instance.InterfaceName, "phx") {
		return fmt.Errorf("interface %q does not use photon naming", instance.InterfaceName)
	}
	return nil
}

func contactGeneration(spec TransportLinkSpec) uint64 {
	if spec.Generation != 0 {
		return spec.Generation
	}
	point, ok := firstContactPoint(spec.ContactPoints)
	if !ok {
		return 0
	}
	return point.Generation
}

func groupSpecForSpec(spec TransportLinkSpec, groups map[string]LinkGroupSpec) LinkGroupSpec {
	if len(groups) == 0 {
		return LinkGroupSpec{}
	}
	return groups[spec.OverlayID]
}

func findStagedSA(states []SAState, inst LinkInstance) SAState {
	if inst.StagedIKEName == "" {
		return SAState{}
	}
	var best SAState
	bestMatches := false
	for _, state := range states {
		if !saMatchesPathKey(state, inst.PathKey) {
			continue
		}
		if !saIdentityMatchesInstance(state, inst) {
			continue
		}
		if state.Name == inst.StagedIKEName || state.ChildSA == inst.StagedChildSAName {
			matches := inst.StagedXFRMIfID == 0 || state.XFRMIfID == inst.StagedXFRMIfID
			if preferObservedSA(state, best, matches, bestMatches) {
				best, bestMatches = state, matches
			}
		}
	}
	return best
}

func rotateTimeout() time.Duration {
	return 2 * time.Minute
}

func stagedInitiateBackoff(attemptCount int) time.Duration {
	if attemptCount < 1 {
		attemptCount = 1
	}
	delay := initialStagedInitiateBackoff
	for i := 1; i < attemptCount; i++ {
		delay *= 2
		if delay >= maximumStagedInitiateBackoff {
			return maximumStagedInitiateBackoff
		}
	}
	return delay
}

func ReconcileLinkInstances(in ReconcileInputs) ReconcileResult {
	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}
	result := ReconcileResult{Instances: map[string]LinkInstance{}}
	maps.Copy(result.Instances, in.Instances)
	desiredByID := map[string]TransportLinkSpec{}
	for _, spec := range in.Desired {
		desiredByID[LinkInstanceID(spec)] = spec
	}
	connectionsByName := make(map[string]ConnectionState, len(in.Connections))
	for _, conn := range in.Connections {
		connectionsByName[conn.Name] = conn
	}
	for id, spec := range desiredByID {
		existing, exists := result.Instances[id]
		if !exists {
			existing, exists = findMigratableLinkInstance(result.Instances, spec)
			if exists {
				delete(result.Instances, existing.ID)
				existing.ID = id
				existing.LinkID = id
				existing.PathKey = spec.PathKey
				existing.Owner.InstanceID = id
				existing.Owner.LinkID = id
				existing.Owner.TransportID = existing.TransportID
				existing.Owner.Token = ResourceOwnerToken(id, existing.TransportID)
				result.Instances[id] = existing
			}
		}
		if in.Revoked[spec.PeerZone] {
			inst := existing
			if !exists {
				inst = NewLinkInstance(spec, LinkStateRemoving, now)
			}
			inst.ActualState = LinkStateRemoving
			inst.LastTransition = now.Unix()
			result.Instances[id] = inst
			result.add(ReconcileActionTeardown, nil, &inst, "peer revoked")
			continue
		}
		role := roleForSpec(id, spec, in.Roles)
		if role == InitiatorRoleSecondaryStandby {
			sa := findInstanceSA(in.SAs, existing)
			if !sa.Established {
				sa = findMatchingSA(in.SAs, spec)
			}
			if sa.Established && !saIdentityMatchesSpec(sa, spec) {
				sa = SAState{}
			}
			result.reconcileSecondaryStandby(id, spec, existing, exists, sa, in, now)
			if result.Err != nil {
				return result
			}
			continue
		}
		desiredGen := contactGeneration(spec)
		connection := connectionsByName[spec.TransportID]
		loaded := connectionMatchesSpec(connection, spec)
		_, xfrmMissing := in.MissingXFRMLinks[id]
		if !exists {
			sa := findMatchingSA(in.SAs, spec)
			inst := NewLinkInstance(spec, LinkStatePending, now)
			if sa.Established {
				inst.ActualState = LinkStateUp
				inst.Endpoint = sa.Endpoint
				result.add(ReconcileActionAdopt, &spec, &inst, "driver state already exists")
			} else if role == "" && loaded && !xfrmMissing && connection.DPDDelay == mobikeDPDDelay(spec) {
				inst.ActualState = LinkStateWaitingInbound
				result.add(ReconcileActionAdopt, &spec, &inst, "responder configuration already loaded")
			} else if role == "" && loaded {
				inst.ActualState = LinkStateDegraded
				result.add(ReconcileActionRepair, &spec, &inst, "responder local configuration incomplete")
			} else if loaded {
				inst.ActualState = LinkStateDegraded
				result.add(ReconcileActionRepair, &spec, &inst, "loaded connection has no established sa")
			} else {
				inst.ActualState = LinkStateConfiguring
				result.add(ReconcileActionCreate, &spec, &inst, "missing instance")
			}
			result.Instances[id] = inst
			continue
		}
		if existing.RemoteGeneration == 0 {
			existing.RemoteGeneration = desiredGen
		}
		if existing.RemoteGeneration != desiredGen {
			result.handleRotate(id, spec, existing, in, now, role)
			if result.Err != nil {
				return result
			}
			continue
		}
		rotateActive := existing.StagedGeneration != 0 || existing.RotatePhase != RotatePhaseIdle
		existing = result.clearStagedIfIdle(existing, in.SAs, now)
		if existing.StagedGeneration == 0 && existing.RemoteGeneration == desiredGen {
			existing = syncInstanceDesiredRuntime(existing, spec)
			result.Instances[id] = existing
		}
		sa := findInstanceSA(in.SAs, existing)
		if reason := in.ForceUpdates[id]; reason != "" && sa.Established && !rotateActive {
			if inLinkBackoff(existing, now) {
				result.add(ReconcileActionNoop, &spec, &existing, "apply backoff active")
				continue
			}
			inst := NewLinkInstance(spec, LinkStateConfiguring, now)
			inst.FailureCount = existing.FailureCount
			inst.BackoffUntil = existing.BackoffUntil
			inst.LastFailure = existing.LastFailure
			result.Instances[id] = inst
			result.add(ReconcileActionUpdate, &spec, &inst, reason)
			continue
		}
		specHash := TransportLinkSpecHash(spec)
		// VICI reports DPD but not MOBIKE in list-conns. They are set together
		// for managed connections, so a restart can detect an old policy.
		observedConn, observed := connectionsByName[existing.IKEName]
		if existing.DesiredSpecHash != specHash || !rotateActive && observed && observedConn.DPDDelay != mobikeDPDDelay(spec) {
			if inLinkBackoff(existing, now) {
				result.add(ReconcileActionNoop, &spec, &existing, "apply backoff active")
				continue
			}
			inst := NewLinkInstance(spec, LinkStateConfiguring, now)
			inst.FailureCount = existing.FailureCount
			inst.BackoffUntil = existing.BackoffUntil
			inst.LastFailure = existing.LastFailure
			result.Instances[id] = inst
			result.add(ReconcileActionUpdate, &spec, &inst, "desired spec changed")
			if existing.IKEName != "" && existing.IKEName != spec.TransportID {
				oldSpec := TransportLinkSpec{
					PeerZone:      existing.PeerZone,
					TransportID:   existing.IKEName,
					InterfaceName: existing.InterfaceName,
					XFRMIfID:      existing.XFRMIfID,
				}
				result.add(ReconcileActionCleanupRotate, &oldSpec, &inst, "old rotated connection after spec update")
			}
			continue
		}
		if sa.Established && !saIdentityMatchesSpec(sa, spec) {
			if inLinkBackoff(existing, now) {
				result.add(ReconcileActionNoop, &spec, &existing, "apply backoff active")
				continue
			}
			inst := NewLinkInstance(spec, LinkStateConfiguring, now)
			inst.FailureCount = existing.FailureCount
			inst.BackoffUntil = existing.BackoffUntil
			inst.LastFailure = existing.LastFailure
			result.Instances[id] = inst
			result.add(ReconcileActionUpdate, &spec, &inst, "driver identity mismatch")
			continue
		}
		if sa.Established && !saEndpointMatchesSpec(sa, spec) {
			if inLinkBackoff(existing, now) {
				result.add(ReconcileActionNoop, &spec, &existing, "apply backoff active")
				continue
			}
			inst := NewLinkInstance(spec, LinkStateConfiguring, now)
			inst.FailureCount = existing.FailureCount
			inst.BackoffUntil = existing.BackoffUntil
			inst.LastFailure = existing.LastFailure
			result.Instances[id] = inst
			// A peer can reach the old responder config from a new/NAT port
			// before its port record arrives. Never terminate every SA sharing
			// that config name because one observed endpoint differs.
			result.add(ReconcileActionRepair, &spec, &inst, "driver endpoint mismatch")
			result.Actions[len(result.Actions)-1].SAUniqueID = sa.UniqueID
			continue
		}
		if sa.Established && existing.ActualState != LinkStateUp {
			inst := existing
			inst = syncInstanceRuntimeFromSA(inst, sa)
			inst.ActualState = LinkStateUp
			inst.FailureCount = 0
			inst.BackoffUntil = 0
			inst.LastFailure = nil
			inst.LastTransition = now.Unix()
			result.Instances[id] = inst
			result.add(ReconcileActionAdopt, &spec, &inst, "driver state recovered")
			continue
		}
		if sa.Established {
			inst := syncInstanceRuntimeFromSA(existing, sa)
			if instanceRuntimeChanged(existing, inst) {
				inst.LastTransition = now.Unix()
				result.Instances[id] = inst
				result.add(ReconcileActionAdopt, &spec, &inst, "driver runtime metadata recovered")
				continue
			}
		}
		if inLinkBackoff(existing, now) {
			result.add(ReconcileActionNoop, &spec, &existing, "apply backoff active")
			continue
		}
		if role == "" && !sa.Established {
			// An idle responder is healthy as long as its local configuration
			// is loaded and its XFRM interface is intact.
			inst := existing
			if loaded && !xfrmMissing {
				if inst.ActualState != LinkStateWaitingInbound {
					inst = MarkLinkApplySuccess(inst, now)
					inst.ActualState = LinkStateWaitingInbound
					inst.Endpoint = ""
				}
				result.add(ReconcileActionNoop, &spec, &inst, "awaiting inbound negotiation")
			} else {
				inst.ActualState = LinkStateDegraded
				inst.LastTransition = now.Unix()
				reason := "responder connection configuration missing or mismatched"
				if xfrmMissing {
					reason = "responder xfrm interface missing or mismatched"
				}
				result.add(ReconcileActionRepair, &spec, &inst, reason)
			}
			result.Instances[id] = inst
			continue
		}
		if (existing.ActualState == LinkStateConfiguring || existing.ActualState == LinkStateConnecting) && !sa.Established {
			if saObserved(sa) {
				if !linkEstablishing(existing, now) {
					inst := MarkLinkApplyFailure(existing, groupBackoffForSpec(spec, in.GroupBackoff), now, &ContactAttemptError{Err: fmt.Errorf("waiting for in-progress SA")})
					result.Instances[id] = inst
					result.add(ReconcileActionNoop, &spec, &inst, "awaiting in-progress sa")
					continue
				}
				result.add(ReconcileActionNoop, &spec, &existing, "awaiting in-progress sa")
				continue
			}
			if linkAutostartEstablishing(existing, groupBackoffForSpec(spec, in.GroupBackoff), now) {
				result.add(ReconcileActionNoop, &spec, &existing, "awaiting established sa")
				continue
			}
			inst := MarkLinkApplyFailure(existing, groupBackoffForSpec(spec, in.GroupBackoff), now, &ContactAttemptError{Err: fmt.Errorf("waiting for established SA")})
			result.Instances[id] = inst
			result.add(ReconcileActionNoop, &spec, &inst, "awaiting established sa")
			continue
		}
		if (existing.ActualState == LinkStateError || existing.ActualState == LinkStateDegraded) && !sa.Established {
			inst := existing
			inst.ActualState = LinkStateDegraded
			inst.LastTransition = now.Unix()
			result.Instances[id] = inst
			result.add(ReconcileActionRepair, &spec, &inst, "previous apply failed")
			continue
		}
		if existing.ActualState == LinkStateUp && !sa.Established {
			inst := existing
			inst.ActualState = LinkStateDegraded
			inst.LastTransition = now.Unix()
			result.Instances[id] = inst
			result.add(ReconcileActionRepair, &spec, &inst, "driver state missing")
			continue
		}
		inst := existing
		result.add(ReconcileActionNoop, &spec, &inst, "")
	}
	for id, inst := range result.Instances {
		if _, ok := desiredByID[id]; ok {
			continue
		}
		if err := inst.Owner.Validate(inst); err != nil {
			result.add(ReconcileActionNoop, nil, &inst, "unmanaged resource retained: "+err.Error())
			continue
		}
		inst.ActualState = LinkStateRemoving
		inst.LastTransition = now.Unix()
		result.Instances[id] = inst
		result.add(ReconcileActionTeardown, nil, &inst, "no longer desired")
	}
	return result
}

func (r *ReconcileResult) reconcileSecondaryStandby(id string, spec TransportLinkSpec, existing LinkInstance, exists bool, sa SAState, in ReconcileInputs, now time.Time) {
	policy := groupBackoffForSpec(spec, in.GroupBackoff)
	if exists {
		desiredGen := contactGeneration(spec)
		if existing.RemoteGeneration == 0 {
			existing.RemoteGeneration = desiredGen
		}
		if existing.RemoteGeneration != desiredGen && (sa.Established || existing.StagedGeneration != 0 || existing.RotatePhase != RotatePhaseIdle) {
			rotateRole := InitiatorRoleSecondaryStandby
			if (sa.InitiatorKnown && sa.Initiator) || (!sa.InitiatorKnown && existing.InitiatorRole == InitiatorRoleSecondaryTakeover) {
				rotateRole = InitiatorRoleSecondaryTakeover
			}
			r.handleRotate(id, spec, existing, in, now, rotateRole)
			return
		}
	}
	if sa.Established {
		if exists {
			desiredGen := contactGeneration(spec)
			if existing.RemoteGeneration == 0 {
				existing.RemoteGeneration = desiredGen
			}
		}
		inst := existing
		if !exists {
			inst = NewLinkInstance(spec, LinkStateUp, now)
		}
		inst = syncInstanceRuntimeFromSA(inst, sa)
		inst = syncInstanceDesiredRuntime(inst, spec)
		inst.ActualState = LinkStateUp
		inst.DesiredSpecHash = TransportLinkSpecHash(spec)
		if sa.InitiatorKnown && sa.Initiator {
			inst.InitiatorRole = InitiatorRoleSecondaryTakeover
			inst.TakeoverPhase = TakeoverPhaseActive
			if in.PrepareStandby || inst.TakeoverStartedAt == 0 {
				inst.TakeoverStartedAt = now.Unix()
			}
			if in.PrepareStandby || inst.TakeoverUntil == 0 {
				inst.TakeoverUntil = now.Add(TakeoverLeaseDuration(policy)).Unix()
			}
		} else {
			inst.InitiatorRole = InitiatorRoleConverged
			inst.TakeoverPhase = TakeoverPhaseIdle
			inst.TakeoverStartedAt = 0
			inst.TakeoverUntil = 0
		}
		inst.LastTakeoverFailure = nil
		inst.SAAbsentSince = 0
		inst.SAAbsentCount = 0
		inst.LastTransition = now.Unix()
		r.Instances[id] = inst
		r.add(ReconcileActionAdopt, &spec, &inst, "driver state already exists")
		return
	}
	if !exists {
		inst := NewLinkInstance(spec, LinkStateConfiguring, now)
		inst.InitiatorRole = InitiatorRoleSecondaryStandby
		inst.SAAbsentSince = now.Unix()
		inst.SAAbsentCount = 1
		r.Instances[id] = inst
		r.add(ReconcileActionPrepareStandby, &spec, &inst, "standby_responder_prepare")
		return
	}
	inst := existing
	if in.PrepareStandby {
		inst.InitiatorRole = InitiatorRoleSecondaryStandby
		inst.TakeoverPhase = TakeoverPhaseIdle
		inst.TakeoverStartedAt = 0
		inst.TakeoverUntil = 0
		inst.SAAbsentSince = now.Unix()
		inst.SAAbsentCount = 1
		inst.ActualState = LinkStateConfiguring
		inst.LastTransition = now.Unix()
		r.Instances[id] = inst
		r.add(ReconcileActionPrepareStandby, &spec, &inst, "startup_standby_responder_prepare")
		return
	}
	switch inst.InitiatorRole {
	case InitiatorRoleSecondaryTakeover:
		if inLinkBackoff(inst, now) {
			r.add(ReconcileActionNoop, &spec, &inst, "apply backoff active")
			return
		}
		if inst.TakeoverPhase == TakeoverPhaseCooldown && now.Before(time.Unix(inst.TakeoverUntil, 0)) {
			r.add(ReconcileActionNoop, &spec, &inst, "takeover_cooldown_active")
			return
		}
		lease := TakeoverLeaseDuration(policy)
		if (inst.ActualState == LinkStateConfiguring || inst.ActualState == LinkStateConnecting) &&
			now.After(time.Unix(inst.TakeoverStartedAt, 0).Add(lease)) {
			inst.ActualState = LinkStateError
			inst.LastFailure = errors.New("secondary takeover timed out waiting for SA")
			inst.LastTransition = now.Unix()
			inst.TakeoverPhase = TakeoverPhaseCooldown
			inst.TakeoverUntil = now.Add(TakeoverCooldownDuration(policy)).Unix()
			inst.LastTakeoverFailure = inst.LastFailure
			r.Instances[id] = inst
			r.add(ReconcileActionRepair, &spec, &inst, "secondary_takeover_timeout")
			return
		}
		if inst.ActualState == LinkStateError || inst.ActualState == LinkStateDegraded {
			inst.ActualState = LinkStateDegraded
			inst.LastTransition = now.Unix()
			r.Instances[id] = inst
			r.add(ReconcileActionRepair, &spec, &inst, "secondary_takeover_retry")
			return
		}
		if inst.ActualState == LinkStateConfiguring || inst.ActualState == LinkStateConnecting {
			r.add(ReconcileActionNoop, &spec, &inst, "secondary_takeover_pending")
			return
		}
	case InitiatorRoleConverged:
		if inLinkBackoff(inst, now) {
			r.add(ReconcileActionNoop, &spec, &inst, "apply backoff active")
			return
		}
		// A secondary records Converged after adopting an SA initiated by its
		// primary peer. If that SA disappears, repair the responder state once,
		// then return to standby so the normal takeover delay can eventually
		// promote this side. Keeping Converged here would select this repair
		// branch forever and prevent shouldSecondaryTakeover from running.
		inst.InitiatorRole = InitiatorRoleSecondaryStandby
		inst.ActualState = LinkStateDegraded
		inst.SAAbsentSince = now.Unix()
		inst.SAAbsentCount = 1
		inst.LastTransition = now.Unix()
		r.Instances[id] = inst
		r.add(ReconcileActionRepair, &spec, &inst, "driver state missing after convergence")
		return
	}
	if inst.ActualState == LinkStateError || inst.ActualState == LinkStateDegraded {
		if inLinkBackoff(inst, now) {
			r.add(ReconcileActionNoop, &spec, &inst, "apply backoff active")
			return
		}
		inst.ActualState = LinkStateDegraded
		inst.LastTransition = now.Unix()
		r.Instances[id] = inst
		r.add(ReconcileActionUpdate, &spec, &inst, "standby driver state missing")
		return
	}
	inst = noteSecondarySAAbsent(inst, now)
	r.Instances[id] = inst
	ok, reason := shouldSecondaryTakeover(inst, InitiatorRoleSecondaryStandby, spec, sa, policy, in.TakeoverNotBefore, now)
	if !ok {
		r.add(ReconcileActionNoop, &spec, &inst, reason)
		return
	}
	inst.InitiatorRole = InitiatorRoleSecondaryTakeover
	inst.TakeoverPhase = TakeoverPhaseActive
	inst.TakeoverStartedAt = now.Unix()
	inst.TakeoverUntil = now.Add(TakeoverLeaseDuration(policy)).Unix()
	inst.LastFailure = nil
	inst.LastTransition = now.Unix()
	inst.ActualState = LinkStateConfiguring
	inst.DesiredSpecHash = TransportLinkSpecHash(spec)
	r.Instances[id] = inst
	takeoverSpec := spec
	takeoverSpec.InitiatorRole = InitiatorRoleSecondaryTakeover
	r.add(ReconcileActionCreate, &takeoverSpec, &inst, reason)
}

func (r *ReconcileResult) handleRotate(id string, spec TransportLinkSpec, existing LinkInstance, in ReconcileInputs, now time.Time, initiatorRole string) {
	group := groupSpecForSpec(spec, in.GroupSpecs)
	spec.InitiatorRole = initiatorRole
	desiredGen := contactGeneration(spec)
	if existing.StagedGeneration != 0 && existing.StagedGeneration != desiredGen {
		inst := existing
		inst.RotatePhase = RotatePhaseCleanup
		r.Instances[id] = inst
		stagedSpec, err := RuntimeSpecForPortGeneration(spec, group, existing.StagedGeneration)
		if err != nil {
			r.Err = fmt.Errorf("derive stale staged runtime for %s generation %d: %w", id, existing.StagedGeneration, err)
			return
		}
		r.add(ReconcileActionCleanupRotate, &stagedSpec, &inst, "stale staged generation")
		return
	}
	oldSA := findInstanceSA(in.SAs, existing)
	if existing.StagedGeneration == desiredGen {
		stagedSA := findStagedSA(in.SAs, existing)
		stagedSpec, err := RuntimeSpecForPortGeneration(spec, group, existing.StagedGeneration)
		if err != nil {
			r.Err = fmt.Errorf("derive staged runtime for %s generation %d: %w", id, existing.StagedGeneration, err)
			return
		}
		oldSAWasStaged := sameSARuntime(oldSA, stagedSA)
		if oldSAWasStaged {
			oldSA = SAState{}
		}
		stagedXFRMReady := !in.MissingDesiredXFRM[id]
		stagedLoaded := hasMatchingConnection(in.Connections, stagedSpec)
		stagedSpecChanged := existing.StagedSpecHash != "" && existing.StagedSpecHash != TransportLinkSpecHash(stagedSpec)
		stagedNeedsRepair := !stagedXFRMReady || (in.Connections != nil && !stagedLoaded)
		stagedEstablished := stagedSA.Established && stagedXFRMReady
		passiveReady := !IsActiveInitiatorRole(initiatorRole) && !oldSA.Established &&
			stagedLoaded && stagedXFRMReady && !stagedSpecChanged && existing.RotatePhase != RotatePhasePreparing
		if stagedEstablished || passiveReady {
			retention := rotateRetentionForSpec(spec, in.GroupRotateRetention)
			activationReady, activationGated := rotateActivationReady(id, in.RotateActivationReady)
			cutoverReady := rotateCutoverReady(id, in.RotateCutoverReady)
			retentionStarted := existing.RotatePhase == RotatePhaseDualRunning || existing.RotatePhase == RotatePhaseDraining
			if oldSA.Established && retention > 0 && (!retentionStarted || existing.RotateDeadline == 0) {
				inst := MarkLinkApplySuccess(existing, now)
				inst.ActualState = LinkStateUp
				inst.RotatePhase = RotatePhaseDualRunning
				if activationGated && activationReady {
					inst.RotatePhase = RotatePhaseDraining
				}
				inst.RotateDeadline = now.Add(retention).Unix()
				inst.LastTransition = now.Unix()
				r.Instances[id] = inst
				r.add(ReconcileActionNoop, &spec, &inst, "rotate retention active")
				return
			}
			if oldSA.Established && existing.RotateDeadline != 0 && now.Before(time.Unix(existing.RotateDeadline, 0)) {
				inst := existing
				inst.ActualState = LinkStateUp
				inst.RotatePhase = RotatePhaseDualRunning
				if activationGated && activationReady {
					inst.RotatePhase = RotatePhaseDraining
				}
				r.Instances[id] = inst
				r.add(ReconcileActionNoop, &spec, &inst, "rotate retention active")
				return
			}
			if oldSA.Established && activationGated && !activationReady {
				inst := existing
				inst.ActualState = LinkStateUp
				inst.RotatePhase = RotatePhaseDualRunning
				r.Instances[id] = inst
				r.add(ReconcileActionNoop, &spec, &inst, "route_activation_pending")
				return
			}
			if oldSA.Established && ((activationGated && existing.RotatePhase != RotatePhaseDraining) || !cutoverReady) {
				inst := existing
				inst.ActualState = LinkStateUp
				inst.RotatePhase = RotatePhaseDraining
				r.Instances[id] = inst
				r.add(ReconcileActionNoop, &spec, &inst, "route_cutover_pending")
				return
			}
			if inLinkBackoff(existing, now) {
				r.add(ReconcileActionNoop, &stagedSpec, &existing, "rotate backoff active")
				return
			}
			inst := existing
			inst.RemoteGeneration = desiredGen
			inst.IKEName = existing.StagedIKEName
			inst.ChildSAName = existing.StagedChildSAName
			inst.InterfaceName = firstNonEmptyString(existing.StagedInterfaceName, stagedSpec.InterfaceName)
			inst.XFRMIfID = firstNonZeroUint32(existing.StagedXFRMIfID, stagedSpec.XFRMIfID)
			inst.LocalTunnelAddr = stagedSpec.LocalTunnelAddr
			inst.PeerTunnelAddr = stagedSpec.PeerTunnelAddr
			inst.ActualState = LinkStateUp
			inst.Endpoint = stagedSA.Endpoint
			inst.SelectedContact = ContactPoint{}
			if point, ok := firstContactPointForGeneration(spec, desiredGen); ok {
				inst.SelectedContact = point
				inst.Endpoint = contactEndpoint(point)
			}
			inst.DesiredSpecHash = TransportLinkSpecHash(spec)
			inst.clearStaged(RotatePhaseIdle)
			inst.FailureCount = 0
			inst.BackoffUntil = 0
			inst.LastFailure = nil
			inst.LastTransition = now.Unix()
			reason := "staged sa established"
			if !stagedEstablished {
				inst.ActualState = LinkStateWaitingInbound
				inst.Endpoint = ""
				inst.SelectedContact = ContactPoint{}
				if initiatorRole == InitiatorRoleSecondaryStandby {
					// Resume the ordinary standby takeover policy on the new generation.
					inst.ActualState = LinkStateDown
					inst.InitiatorRole = InitiatorRoleSecondaryStandby
					inst.TakeoverPhase = TakeoverPhaseIdle
					inst.TakeoverStartedAt = 0
					inst.TakeoverUntil = 0
				}
				reason = "responder configuration ready without an old sa"
			}
			r.Instances[id] = inst
			if oldSAWasStaged || existing.IKEName == inst.IKEName {
				r.add(ReconcileActionNoop, &spec, &inst, "staged sa already current")
				return
			}
			oldSpec := TransportLinkSpec{
				PeerZone:      existing.PeerZone,
				TransportID:   existing.IKEName,
				InterfaceName: existing.InterfaceName,
				XFRMIfID:      existing.XFRMIfID,
				ContactPoints: []ContactPoint{existing.SelectedContact},
			}
			r.add(ReconcileActionCommitRotate, &oldSpec, &existing, reason)
			return
		}
		if existing.RotatePhase == RotatePhaseDualRunning || existing.RotatePhase == RotatePhaseDraining {
			// The new path disappeared before cutover. Give the surviving path
			// preference again and restart negotiation independently of retention.
			existing.RotatePhase = RotatePhaseTestingNew
			existing.RotateDeadline = 0
			existing.StagedAttemptCount = 0
			existing.StagedNextAttempt = 0
			existing.LastTransition = now.Unix()
			r.Instances[id] = existing
		}
		if inLinkBackoff(existing, now) {
			r.add(ReconcileActionNoop, &stagedSpec, &existing, "rotate backoff active")
			return
		}
		if initiatorRole == InitiatorRoleSecondaryTakeover && existing.StagedAttemptCount == 0 && existing.StagedNextAttempt != 0 {
			// A working takeover path gives the primary time to learn the new
			// local port record. The deadline is a fallback opportunity, never
			// evidence that Gossip delivery has completed. If the old path
			// disappears, do not delay recovery for the primary's benefit.
			if now.Before(time.Unix(existing.StagedNextAttempt, 0)) && oldSA.Established {
				stagedSpec.InitiatorRole = InitiatorRoleSecondaryStandby
				stagedSpec.ContactPoints = nil
				if existing.RotatePhase == RotatePhasePreparing || stagedNeedsRepair {
					r.add(ReconcileActionPrepareRotate, &stagedSpec, &existing, "resume passive staged preparation")
				} else {
					r.add(ReconcileActionNoop, &stagedSpec, &existing, "awaiting primary rotation")
				}
				return
			}
			inst := existing
			inst.StagedAttemptCount = 1
			inst.StagedNextAttempt = now.Add(stagedInitiateBackoff(1)).Unix()
			inst.RotateDeadline = now.Add(rotateTimeout()).Unix()
			inst.RotatePhase = RotatePhasePreparing
			inst.LastTransition = now.Unix()
			r.Instances[id] = inst
			// Reload the passive config with an actual remote endpoint before
			// initiating. A wildcard responder config cannot initiate itself.
			r.add(ReconcileActionPrepareRotate, &stagedSpec, &inst, "primary rotation fallback")
			return
		}
		if existing.RotatePhase == RotatePhasePreparing {
			r.add(ReconcileActionPrepareRotate, &stagedSpec, &existing, "resume staged sa preparation")
			return
		}
		if stagedNeedsRepair || stagedSpecChanged {
			existing.RotatePhase = RotatePhasePreparing
			existing.ActualState = LinkStateConfiguring
			if oldSA.Established {
				existing.ActualState = LinkStateUp
			}
			r.Instances[id] = existing
			r.add(ReconcileActionPrepareRotate, &stagedSpec, &existing, "repair staged configuration or xfrm")
			return
		}
		if !IsActiveInitiatorRole(stagedSpec.InitiatorRole) {
			existing.RotateDeadline = 0
			if initiatorRole == "" {
				state, endpoint := LinkStateWaitingInbound, ""
				if oldSA.Established {
					state, endpoint = LinkStateUp, oldSA.Endpoint
				}
				if existing.ActualState != state {
					existing.ActualState, existing.Endpoint = state, endpoint
					existing.LastTransition = now.Unix()
				}
			}
			r.Instances[id] = existing
			r.add(ReconcileActionNoop, &stagedSpec, &existing, "awaiting staged sa")
			return
		}
		inst := existing
		if oldSA.Established {
			inst.ActualState = LinkStateUp
		} else {
			inst.ActualState = LinkStateConnecting
		}
		if inst.RotateDeadline != 0 && !now.Before(time.Unix(inst.RotateDeadline, 0)) {
			inst.RotateDeadline = 0
			inst.StagedAttemptCount = 0
			inst.StagedNextAttempt = 0
			inst.LastFailure = errors.New("staged sa not established by deadline")
			inst.FailureCount++
			policy := groupBackoffForSpec(spec, in.GroupBackoff)
			inst.BackoffUntil = now.Add(nextLinkBackoff(policy, inst.FailureCount)).Unix()
			inst.LastTransition = now.Unix()
			if !oldSA.Established {
				inst.ActualState = LinkStateError
			}
			r.Instances[id] = inst
			r.add(ReconcileActionNoop, &stagedSpec, &inst, "staged sa deadline exceeded")
			return
		}
		if inst.RotateDeadline == 0 {
			inst.RotateDeadline = now.Add(rotateTimeout()).Unix()
			inst.StagedAttemptCount = 1
			inst.StagedNextAttempt = now.Add(stagedInitiateBackoff(1)).Unix()
			inst.LastTransition = now.Unix()
			r.Instances[id] = inst
			r.add(ReconcileActionInitiateRotate, &stagedSpec, &inst, "retry staged sa")
			return
		}
		// State written by older versions has no staged attempt metadata. Treat
		// the already prepared connection as the first attempt and wait before
		// retrying it, so an upgrade cannot immediately recreate the old loop.
		if inst.StagedAttemptCount == 0 {
			inst.StagedAttemptCount = 1
			inst.StagedNextAttempt = now.Add(stagedInitiateBackoff(inst.StagedAttemptCount)).Unix()
			r.Instances[id] = inst
			r.add(ReconcileActionNoop, &stagedSpec, &inst, "staged retry backoff active")
			return
		}
		if inst.StagedAttemptCount >= maxStagedInitiateAttempts {
			r.add(ReconcileActionNoop, &stagedSpec, &inst, "staged retry limit reached")
			return
		}
		if inst.StagedNextAttempt != 0 && now.Before(time.Unix(inst.StagedNextAttempt, 0)) {
			r.add(ReconcileActionNoop, &stagedSpec, &inst, "staged retry backoff active")
			return
		}
		inst.StagedAttemptCount++
		inst.StagedNextAttempt = now.Add(stagedInitiateBackoff(inst.StagedAttemptCount)).Unix()
		inst.LastTransition = now.Unix()
		r.Instances[id] = inst
		r.add(ReconcileActionInitiateRotate, &stagedSpec, &inst, "retry staged sa")
		return
	}
	if inLinkBackoff(existing, now) {
		r.add(ReconcileActionNoop, &spec, &existing, "rotate backoff active")
		return
	}
	inst := existing
	inst.StagedGeneration = desiredGen
	stagedSpec, err := RuntimeSpecForPortGeneration(spec, group, desiredGen)
	if err != nil {
		r.Err = fmt.Errorf("derive staged runtime for %s generation %d: %w", id, desiredGen, err)
		return
	}
	inst.StagedIKEName = stagedSpec.TransportID
	inst.StagedChildSAName = ChildSAName(stagedSpec)
	inst.StagedInterfaceName = stagedSpec.InterfaceName
	inst.StagedXFRMIfID = stagedSpec.XFRMIfID
	inst.StagedLocalTunnelAddr = stagedSpec.LocalTunnelAddr
	inst.StagedPeerTunnelAddr = stagedSpec.PeerTunnelAddr
	inst.RotatePhase = RotatePhasePreparing
	inst.ActualState = LinkStateConfiguring
	if oldSA.Established {
		inst.ActualState = LinkStateUp
	}
	if IsActiveInitiatorRole(stagedSpec.InitiatorRole) {
		inst.RotateDeadline = now.Add(rotateTimeout()).Unix()
		if initiatorRole == InitiatorRoleSecondaryTakeover && oldSA.Established {
			wait := takeoverDelayFor(group.Reconcile.Backoff, existing.FailureCount)
			inst.StagedNextAttempt = now.Add(wait).Unix()
			inst.RotateDeadline = now.Add(wait + rotateTimeout()).Unix()
			stagedSpec.InitiatorRole = InitiatorRoleSecondaryStandby
			stagedSpec.ContactPoints = nil
		} else {
			inst.StagedAttemptCount = 1
			inst.StagedNextAttempt = now.Add(stagedInitiateBackoff(inst.StagedAttemptCount)).Unix()
		}
	}
	inst.LastTransition = now.Unix()
	r.Instances[id] = inst
	r.add(ReconcileActionPrepareRotate, &stagedSpec, &inst, "remote port generation changed")
}

// clearStaged retires staged resources and retry metadata; callers choose the
// resulting phase and retain ownership of failure/backoff and transition time.
func (inst *LinkInstance) clearStaged(phase string) {
	inst.StagedGeneration = 0
	inst.StagedSpecHash = ""
	inst.StagedIKEName = ""
	inst.StagedChildSAName = ""
	inst.StagedInterfaceName = ""
	inst.StagedXFRMIfID = 0
	inst.StagedLocalTunnelAddr = netip.Addr{}
	inst.StagedPeerTunnelAddr = netip.Addr{}
	inst.StagedAttemptCount = 0
	inst.StagedNextAttempt = 0
	inst.RotatePhase = phase
	inst.RotateDeadline = 0
}

func (r *ReconcileResult) clearStagedIfIdle(existing LinkInstance, sas []SAState, now time.Time) LinkInstance {
	if existing.StagedGeneration == 0 {
		return existing
	}
	stagedSA := findStagedSA(sas, existing)
	if stagedSA.Established {
		inst := existing
		inst.RemoteGeneration = existing.StagedGeneration
		inst.IKEName = existing.StagedIKEName
		inst.ChildSAName = existing.StagedChildSAName
		inst.InterfaceName = firstNonEmptyString(existing.StagedInterfaceName, existing.InterfaceName)
		inst.XFRMIfID = firstNonZeroUint32(existing.StagedXFRMIfID, existing.XFRMIfID)
		inst.LocalTunnelAddr = existing.StagedLocalTunnelAddr
		inst.PeerTunnelAddr = existing.StagedPeerTunnelAddr
		inst.ActualState = LinkStateUp
		inst.Endpoint = stagedSA.Endpoint
		inst.SelectedContact = ContactPoint{}
		inst.clearStaged(RotatePhaseDualRunning)
		inst.LastTransition = now.Unix()
		r.Instances[existing.ID] = inst
		oldSpec := TransportLinkSpec{
			PeerZone:      existing.PeerZone,
			TransportID:   existing.TransportID,
			InterfaceName: existing.InterfaceName,
			XFRMIfID:      existing.XFRMIfID,
			ContactPoints: []ContactPoint{existing.SelectedContact},
		}
		r.add(ReconcileActionCleanupRotate, &oldSpec, &inst, "staged sa adopted")
		return inst
	}
	inst := existing
	inst.clearStaged(RotatePhaseIdle)
	r.Instances[existing.ID] = inst
	return inst
}

// InstanceID selects the existing runtime identity before deriving one from the spec.
func (action ReconcileAction) InstanceID() string {
	if action.Instance != nil && action.Instance.ID != "" {
		return action.Instance.ID
	}
	if action.Spec != nil {
		return LinkInstanceID(*action.Spec)
	}
	return ""
}

// RecordActionResult updates the instance snapshot after an attempted driver action.
// The caller owns execution order and publishing the resulting snapshot.
func RecordActionResult(instances map[string]LinkInstance, action ReconcileAction, policy BackoffPolicy, now time.Time, err error) {
	id := action.InstanceID()
	if id == "" {
		return
	}
	if err == nil && action.Action == ReconcileActionTeardown {
		delete(instances, id)
		return
	}
	inst, ok := instances[id]
	if !ok {
		if err == nil {
			return
		}
		if action.Instance != nil {
			inst = *action.Instance
		} else if action.Spec != nil {
			inst = NewLinkInstance(*action.Spec, LinkStateError, now)
		} else {
			return
		}
	}
	if err != nil {
		if action.Action == ReconcileActionCommitRotate && action.Instance != nil && action.Instance.StagedGeneration != 0 {
			// Keep both runtime identities until old-generation cleanup succeeds.
			inst = *action.Instance
		}
		oldPathUp := inst.ActualState == LinkStateUp && (action.Action == ReconcileActionPrepareRotate || action.Action == ReconcileActionInitiateRotate)
		inst = MarkLinkApplyFailure(inst, policy, now, err)
		if oldPathUp {
			inst.ActualState = LinkStateUp
		}
		switch action.Action {
		case ReconcileActionPrepareRotate, ReconcileActionInitiateRotate, ReconcileActionCommitRotate, ReconcileActionCleanupRotate:
			if inst.RotatePhase != "" && inst.LastFailure != nil {
				inst.LastFailure = fmt.Errorf("rotate %s: %w", inst.RotatePhase, inst.LastFailure)
			}
		}
		if inst.InitiatorRole == InitiatorRoleSecondaryTakeover {
			inst.TakeoverPhase = TakeoverPhaseCooldown
			inst.TakeoverUntil = now.Add(TakeoverCooldownDuration(policy)).Unix()
			inst.LastTakeoverFailure = inst.LastFailure
		}

		instances[id] = inst
		return
	}
	// Scheduling another negotiation does not confirm that a timed-out SA recovered.
	if action.Action == ReconcileActionInitiateRotate {
		return
	}
	inst = MarkLinkApplySuccess(inst, now)
	switch action.Action {
	case ReconcileActionCreate, ReconcileActionUpdate, ReconcileActionRepair, ReconcileActionPrepareStandby, ReconcileActionPrepareRotate:
		if action.Action == ReconcileActionPrepareRotate && action.Spec != nil {
			inst.RotatePhase = RotatePhaseTestingNew
			inst.StagedSpecHash = TransportLinkSpecHash(*action.Spec)
			if IsActiveInitiatorRole(action.Spec.InitiatorRole) {
				inst.RotateDeadline = now.Add(rotateTimeout()).Unix()
				inst.StagedAttemptCount = 1
				inst.StagedNextAttempt = now.Add(stagedInitiateBackoff(1)).Unix()
			}
			if inst.ActualState == LinkStateUp {
				break
			}
		}
		if inst.InitiatorRole == InitiatorRoleSecondaryStandby ||
			(action.Spec != nil && action.Spec.InitiatorRole == InitiatorRoleSecondaryStandby) {
			inst.ActualState = LinkStateDown
		} else if action.Spec != nil && action.Spec.InitiatorRole == "" {
			inst.ActualState = LinkStateWaitingInbound
			inst.Endpoint = ""
		} else {
			inst.ActualState = LinkStateConnecting
		}
		inst.LastTransition = now.Unix()
	case ReconcileActionCommitRotate:
		inst.RotatePhase = RotatePhaseIdle
		inst.LastTransition = now.Unix()
	case ReconcileActionCleanupRotate:
		inst.clearStaged(RotatePhaseIdle)
	}
	instances[id] = inst
}

func MarkLinkApplyFailure(inst LinkInstance, policy BackoffPolicy, now time.Time, err error) LinkInstance {
	if now.IsZero() {
		now = time.Now()
	}
	inst.FailureCount++
	inst.BackoffUntil = now.Add(nextLinkBackoff(policy, inst.FailureCount)).Unix()
	inst.LastTransition = now.Unix()
	inst.ActualState = LinkStateError
	if err != nil {
		inst.LastFailure = err
	}
	return inst
}

func MarkLinkApplySuccess(inst LinkInstance, now time.Time) LinkInstance {
	if now.IsZero() {
		now = time.Now()
	}
	inst.FailureCount = 0
	inst.BackoffUntil = 0
	inst.LastFailure = nil
	inst.LastTransition = now.Unix()
	return inst
}

func syncInstanceRuntimeFromSA(inst LinkInstance, sa SAState) LinkInstance {
	if sa.Name != "" {
		inst.IKEName = sa.Name
	}
	if inst.ChildSAName == "" && sa.ChildSA != "" {
		inst.ChildSAName = sa.ChildSA
	}
	if sa.XFRMIfID != 0 {
		inst.XFRMIfID = sa.XFRMIfID
		inst.InterfaceName = StableInterfaceName(sa.XFRMIfID)
	}
	if sa.Endpoint != "" {
		inst.Endpoint = sa.Endpoint
	}
	return inst
}

func syncInstanceDesiredRuntime(inst LinkInstance, spec TransportLinkSpec) LinkInstance {
	if spec.InterfaceName != "" {
		inst.InterfaceName = spec.InterfaceName
	}
	if spec.XFRMIfID != 0 {
		inst.XFRMIfID = spec.XFRMIfID
	}
	if spec.LocalTunnelAddr.IsValid() {
		inst.LocalTunnelAddr = spec.LocalTunnelAddr
	}
	if spec.PeerTunnelAddr.IsValid() {
		inst.PeerTunnelAddr = spec.PeerTunnelAddr
	}
	return inst
}

func instanceRuntimeChanged(a, b LinkInstance) bool {
	return a.IKEName != b.IKEName ||
		a.ChildSAName != b.ChildSAName ||
		a.XFRMIfID != b.XFRMIfID ||
		a.InterfaceName != b.InterfaceName ||
		a.LocalTunnelAddr != b.LocalTunnelAddr ||
		a.PeerTunnelAddr != b.PeerTunnelAddr ||
		a.Endpoint != b.Endpoint
}

func saEndpointMatchesSpec(sa SAState, spec TransportLinkSpec) bool {
	endpoint := firstNonEmptyString(sa.RemoteEndpoint, sa.Endpoint)
	if endpoint == "" || len(spec.ContactPoints) == 0 {
		return true
	}
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return true
	}
	for _, point := range spec.ContactPoints {
		if !contactHostMatches(host, point) {
			continue
		}
		if portMatchesContactPoint(port, point) {
			return true
		}
	}
	return false
}

func contactHostMatches(host string, point ContactPoint) bool {
	if point.Address != "" && host == point.Address {
		return true
	}
	return point.Host != "" && host == point.Host
}

func portMatchesContactPoint(port string, point ContactPoint) bool {
	return (point.NATTPort != 0 && port == fmt.Sprintf("%d", point.NATTPort)) ||
		(point.IKEPort != 0 && port == fmt.Sprintf("%d", point.IKEPort))
}

func nextLinkBackoff(policy BackoffPolicy, failureCount int) time.Duration {
	if failureCount < 1 {
		failureCount = 1
	}
	initial := policy.InitialSeconds
	if initial <= 0 {
		initial = 1
	}
	maximum := policy.MaxSeconds
	if maximum <= 0 {
		maximum = 60
	}
	seconds := initial
	for i := 1; i < failureCount; i++ {
		if seconds >= maximum {
			return time.Duration(maximum) * time.Second
		}
		seconds *= 2
	}
	if seconds > maximum {
		seconds = maximum
	}
	return time.Duration(seconds) * time.Second
}

func inLinkBackoff(inst LinkInstance, now time.Time) bool {
	if inst.BackoffUntil == 0 || now.IsZero() {
		return false
	}
	return now.Before(time.Unix(inst.BackoffUntil, 0))
}

func roleForSpec(id string, spec TransportLinkSpec, roles map[string]string) string {
	if roles == nil {
		return InitiatorRolePrimary
	}
	// An explicitly empty role is a passive responder, not a missing role.
	if role, ok := roles[id]; ok {
		return role
	}
	if spec.TransportID != "" {
		if role, ok := roles[spec.TransportID]; ok {
			return role
		}
	}
	return InitiatorRolePrimary
}

func groupBackoffForSpec(spec TransportLinkSpec, groups map[string]BackoffPolicy) BackoffPolicy {
	if groups == nil {
		return BackoffPolicy{}
	}
	return groups[spec.OverlayID]
}

func saObserved(sa SAState) bool {
	return sa.Name != "" || sa.ChildSA != "" || sa.IKEState != "" || sa.ChildState != "" || sa.XFRMIfID != 0 || sa.Endpoint != ""
}

func linkEstablishing(inst LinkInstance, now time.Time) bool {
	if inst.LastTransition == 0 {
		return false
	}
	return now.Before(time.Unix(inst.LastTransition, 0).Add(defaultLinkEstablishGrace))
}

func linkAutostartEstablishing(inst LinkInstance, policy BackoffPolicy, now time.Time) bool {
	if inst.LastTransition == 0 {
		return false
	}
	grace := nextLinkBackoff(policy, inst.FailureCount+1) + nextLinkBackoff(policy, inst.FailureCount+2)
	return now.Before(time.Unix(inst.LastTransition, 0).Add(grace))
}

func rotateRetentionForSpec(spec TransportLinkSpec, groups map[string]int) time.Duration {
	const defaultRotateRetention = time.Hour
	if groups == nil {
		return defaultRotateRetention
	}
	seconds, ok := groups[spec.OverlayID]
	if !ok || seconds == 0 {
		return defaultRotateRetention
	}
	if seconds < 0 {
		return defaultRotateRetention
	}
	return time.Duration(seconds) * time.Second
}

func rotateCutoverReady(id string, readiness map[string]bool) bool {
	if readiness == nil {
		return true
	}
	ready, ok := readiness[id]
	if !ok {
		return true
	}
	return ready
}

func rotateActivationReady(id string, readiness map[string]bool) (ready, gated bool) {
	if readiness == nil {
		return true, false
	}
	ready, ok := readiness[id]
	if !ok {
		return false, true
	}
	return ready, true
}

func takeoverDelayFor(policy BackoffPolicy, failureCount int) time.Duration {
	if failureCount < 0 {
		failureCount = 0
	}
	// Require at least 2-3 backoff cycles before a secondary takes over.
	delay := nextLinkBackoff(policy, failureCount+2) + nextLinkBackoff(policy, failureCount+3)
	const minDelay = 2 * time.Minute
	if delay < minDelay {
		return minDelay
	}
	return delay
}

func TakeoverLeaseDuration(policy BackoffPolicy) time.Duration {
	d := 5 * nextLinkBackoff(policy, 1)
	const minLease = 5 * time.Minute
	if d < minLease {
		return minLease
	}
	return d
}

func TakeoverCooldownDuration(policy BackoffPolicy) time.Duration {
	d := 3 * nextLinkBackoff(policy, 3)
	const minCooldown = 2 * time.Minute
	if d < minCooldown {
		return minCooldown
	}
	return d
}

func noteSecondarySAAbsent(inst LinkInstance, now time.Time) LinkInstance {
	if inst.SAAbsentSince == 0 {
		inst.SAAbsentSince = now.Unix()
		inst.SAAbsentCount = 1
		return inst
	}
	inst.SAAbsentCount++
	return inst
}

func shouldSecondaryTakeover(inst LinkInstance, role string, spec TransportLinkSpec, sa SAState, policy BackoffPolicy, takeoverNotBefore time.Time, now time.Time) (bool, string) {
	if role != InitiatorRoleSecondaryStandby {
		return false, ""
	}
	if sa.Established {
		return false, ""
	}
	if !takeoverNotBefore.IsZero() && now.Before(takeoverNotBefore) {
		return false, "takeover_startup_grace"
	}
	if inst.TakeoverPhase == TakeoverPhaseCooldown && now.Before(time.Unix(inst.TakeoverUntil, 0)) {
		return false, "takeover_cooldown_active"
	}
	if suppress, reason := suppressTakeoverDuringRotate(inst, now); suppress {
		return false, reason
	}
	if len(spec.ContactPoints) == 0 {
		return false, "takeover_no_contact_point"
	}
	// Cooldown expired after a previous failed takeover: allow retry.
	if inst.TakeoverPhase == TakeoverPhaseCooldown && !now.Before(time.Unix(inst.TakeoverUntil, 0)) {
		return true, "secondary_takeover_retry"
	}
	delay := takeoverDelayFor(policy, inst.FailureCount)
	if inst.SAAbsentSince == 0 || inst.SAAbsentCount < 2 {
		return false, "takeover_delay_active"
	}
	if now.Sub(time.Unix(inst.SAAbsentSince, 0)) < delay {
		return false, "takeover_delay_active"
	}
	return true, "secondary_takeover"
}

func suppressTakeoverDuringRotate(inst LinkInstance, now time.Time) (bool, string) {
	if inst.RotateDeadline == 0 || !now.Before(time.Unix(inst.RotateDeadline, 0)) {
		return false, ""
	}
	switch inst.RotatePhase {
	case RotatePhaseDualRunning, RotatePhaseDraining:
		return true, "rotate_retention_active"
	case RotatePhasePreparing, RotatePhaseTestingNew:
		if inst.StagedGeneration != 0 {
			return true, "rotate_staged_active"
		}
	}
	return false, ""
}

func ApplyReconcileAction(ctx context.Context, ipsec IPsecDriver, xfrm XFRMDriver, action ReconcileAction, netns NetNSSpec) (ApplyPlan, error) {
	if driver, ok := xfrm.(interface{ CheckAvailable() error }); ok {
		if err := driver.CheckAvailable(); err != nil {
			return ApplyPlan{}, err
		}
	}
	switch action.Action {
	case ReconcileActionPrepareStandby:
		if action.Spec == nil {
			return ApplyPlan{}, fmt.Errorf("%s action requires spec", action.Action)
		}
		return ApplyTransportLink(ctx, ipsec, xfrm, *action.Spec, netns)
	case ReconcileActionCreate:
		if action.Spec == nil {
			return ApplyPlan{}, fmt.Errorf("%s action requires spec", action.Action)
		}
		plan, err := ApplyTransportLink(ctx, ipsec, xfrm, *action.Spec, netns)
		if err != nil {
			return plan, err
		}
		if err := InitiateTransportChild(ctx, ipsec, *action.Spec, &plan); err != nil {
			return plan, err
		}
		return plan, nil
	case ReconcileActionRepair:
		if action.Spec == nil {
			return ApplyPlan{}, fmt.Errorf("%s action requires spec", action.Action)
		}
		plan := ApplyPlan{}
		if action.SAUniqueID != 0 {
			terminator, ok := ipsec.(SAUniqueIDTerminator)
			if !ok {
				return ApplyPlan{}, fmt.Errorf("ipsec driver does not support terminating an SA by unique id")
			}
			plan.add("terminate_sa_id", fmt.Sprintf("#%d", action.SAUniqueID), action.Reason)
			if err := terminator.TerminateSAByID(ctx, action.SAUniqueID); err != nil {
				return plan, fmt.Errorf("terminate stale SA #%d: %w", action.SAUniqueID, err)
			}
		}
		applied, err := ApplyTransportLink(ctx, ipsec, xfrm, *action.Spec, netns)
		plan.Operations = append(plan.Operations, applied.Operations...)
		if err != nil {
			return plan, err
		}
		if err := InitiateTransportChild(ctx, ipsec, *action.Spec, &plan); err != nil {
			return plan, err
		}
		return plan, nil
	case ReconcileActionUpdate:
		if action.Spec == nil {
			return ApplyPlan{}, fmt.Errorf("%s action requires spec", action.Action)
		}
		if action.Instance != nil && action.Instance.IKEName != "" {
			oldSpec := TransportLinkSpec{
				PeerZone:      action.Instance.PeerZone,
				TransportID:   action.Instance.IKEName,
				InterfaceName: action.Instance.InterfaceName,
				XFRMIfID:      action.Instance.XFRMIfID,
			}
			if _, err := TeardownConnectionOnly(ctx, ipsec, oldSpec); err != nil {
				return ApplyPlan{}, err
			}
		}
		plan, err := ApplyTransportLink(ctx, ipsec, xfrm, *action.Spec, netns)
		if err != nil {
			return plan, err
		}
		if err := InitiateTransportChild(ctx, ipsec, *action.Spec, &plan); err != nil {
			return plan, err
		}
		return plan, nil
	case ReconcileActionPrepareRotate:
		if action.Spec == nil {
			return ApplyPlan{}, fmt.Errorf("%s action requires spec", action.Action)
		}
		if action.Instance != nil && action.Instance.IKEName != "" && action.Instance.IKEName != action.Spec.TransportID {
			// Keep the established SA and XFRM data plane, but unload the old
			// config so inbound negotiation selects the staged generation.
			_ = ipsec.UnloadConnection(ctx, action.Instance.IKEName)
		}
		return ApplyStagedConnection(ctx, ipsec, xfrm, *action.Spec, netns)
	case ReconcileActionInitiateRotate:
		if action.Spec == nil {
			return ApplyPlan{}, fmt.Errorf("%s action requires spec", action.Action)
		}
		plan := ApplyPlan{}
		if err := InitiateTransportChild(ctx, ipsec, *action.Spec, &plan); err != nil {
			return plan, err
		}
		return plan, nil
	case ReconcileActionCommitRotate, ReconcileActionCleanupRotate:
		if action.Spec == nil {
			return ApplyPlan{}, fmt.Errorf("%s action requires spec", action.Action)
		}
		return TeardownTransportLink(ctx, ipsec, xfrm, *action.Spec)
	case ReconcileActionTeardown:
		if action.Spec != nil {
			return TeardownTransportLink(ctx, ipsec, xfrm, *action.Spec)
		}
		if action.Instance == nil {
			return ApplyPlan{}, fmt.Errorf("teardown action requires spec or instance")
		}
		if err := action.Instance.Owner.Validate(*action.Instance); err != nil {
			return ApplyPlan{}, fmt.Errorf("refuse unmanaged teardown: %w", err)
		}
		connSpec := TransportLinkSpec{
			PeerZone:      action.Instance.PeerZone,
			TransportID:   action.Instance.IKEName,
			InterfaceName: action.Instance.InterfaceName,
			XFRMIfID:      action.Instance.XFRMIfID,
		}
		if _, err := TeardownConnectionOnly(ctx, ipsec, connSpec); err != nil {
			return ApplyPlan{}, err
		}
		if action.Instance.StagedIKEName != "" {
			stagedSpec := TransportLinkSpec{
				PeerZone:      action.Instance.PeerZone,
				TransportID:   action.Instance.StagedIKEName,
				InterfaceName: firstNonEmptyString(action.Instance.StagedInterfaceName, action.Instance.InterfaceName),
				XFRMIfID:      firstNonZeroUint32(action.Instance.StagedXFRMIfID, action.Instance.XFRMIfID),
			}
			if _, err := TeardownConnectionOnly(ctx, ipsec, stagedSpec); err != nil {
				return ApplyPlan{}, err
			}
			if err := xfrm.DeleteInterface(ctx, stagedSpec.InterfaceName); err != nil {
				return ApplyPlan{}, fmt.Errorf("delete staged interface: %w", err)
			}
		}
		keySpec := TransportLinkSpec{
			PeerZone:      action.Instance.PeerZone,
			TransportID:   action.Instance.TransportID,
			InterfaceName: action.Instance.InterfaceName,
			XFRMIfID:      action.Instance.XFRMIfID,
		}
		if err := ipsec.UnloadPrivateKey(ctx, keySpec.TransportID); err != nil {
			return ApplyPlan{}, fmt.Errorf("unload private key: %w", err)
		}
		if err := xfrm.DeleteInterface(ctx, action.Instance.InterfaceName); err != nil {
			return ApplyPlan{}, fmt.Errorf("delete interface: %w", err)
		}
		return ApplyPlan{}, nil
	case ReconcileActionCleanupDuplicateSA:
		if action.SAUniqueID == 0 {
			return ApplyPlan{}, fmt.Errorf("%s action requires SA unique id", action.Action)
		}
		terminator, ok := ipsec.(SAUniqueIDTerminator)
		if !ok {
			return ApplyPlan{}, fmt.Errorf("ipsec driver does not support terminating an SA by unique id")
		}
		plan := ApplyPlan{}
		plan.add("terminate_sa_id", fmt.Sprintf("#%d", action.SAUniqueID), action.Reason)
		if err := terminator.TerminateSAByID(ctx, action.SAUniqueID); err != nil {
			return plan, fmt.Errorf("terminate duplicate SA #%d: %w", action.SAUniqueID, err)
		}
		return plan, nil
	case ReconcileActionAdopt, ReconcileActionNoop:
		return ApplyPlan{}, nil
	default:
		return ApplyPlan{}, fmt.Errorf("unsupported reconcile action %q", action.Action)
	}
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func firstNonZeroUint32(values ...uint32) uint32 {
	for _, value := range values {
		if value != 0 {
			return value
		}
	}
	return 0
}

func (r *ReconcileResult) add(action string, spec *TransportLinkSpec, inst *LinkInstance, reason string) {
	r.Actions = append(r.Actions, ReconcileAction{
		Action:   action,
		Spec:     spec,
		Instance: inst,
		Reason:   reason,
	})
}

func findMatchingSA(states []SAState, spec TransportLinkSpec) SAState {
	childName := ChildSAName(spec)
	var best SAState
	bestMatches := false
	for _, state := range states {
		if !saMatchesPathKey(state, spec.PathKey) {
			continue
		}
		if !saIdentityMatchesSpec(state, spec) {
			continue
		}
		if state.Name == spec.TransportID || state.ChildSA == childName || (spec.XFRMIfID != 0 && state.XFRMIfID == spec.XFRMIfID) {
			matches := (spec.XFRMIfID == 0 || state.XFRMIfID == spec.XFRMIfID) && saEndpointMatchesSpec(state, spec)
			if preferObservedSA(state, best, matches, bestMatches) {
				best, bestMatches = state, matches
			}
		}
	}
	return best
}

func hasMatchingConnection(states []ConnectionState, spec TransportLinkSpec) bool {
	for _, state := range states {
		if connectionMatchesSpec(state, spec) {
			return true
		}
	}
	return false
}

func connectionMatchesSpec(state ConnectionState, spec TransportLinkSpec) bool {
	return state.Name != "" && state.Name == spec.TransportID &&
		state.LocalIdentity == string(spec.LocalZone) && state.RemoteIdentity == string(spec.PeerZone)
}

// RecoverObservedLinkInstance reconstructs an in-memory instance only when an
// allowed generation has its exact XFRM resource and either its loaded
// connection or an established SA. The caller derives generations from the
// current verified port record in current-first order. When both current and
// previous are observed, the result retains previous as active and current as
// staged so ordinary rotation reconciliation owns and retires both resources.
func RecoverObservedLinkInstance(spec TransportLinkSpec, group LinkGroupSpec, generations []uint64, connections []ConnectionState, sas []SAState, links []XFRMLinkState, now time.Time) (LinkInstance, bool, error) {
	seen := make(map[uint64]bool, len(generations))
	type observedRuntime struct {
		spec        TransportLinkSpec
		instance    LinkInstance
		established bool
	}
	observed := make([]observedRuntime, 0, 2)
	for _, generation := range generations {
		runtimeGeneration := runtimeGenerationForPortGeneration(generation)
		if seen[runtimeGeneration] {
			continue
		}
		seen[runtimeGeneration] = true
		candidate, err := RuntimeSpecForPortGeneration(spec, group, generation)
		if err != nil {
			return LinkInstance{}, false, err
		}
		if !hasMatchingXFRMLink(links, candidate, group.Normalized().NetNS) {
			continue
		}
		state := findMatchingSA(sas, candidate)
		if state.Established {
			instance := NewLinkInstance(candidate, LinkStateUp, now)
			instance.RemoteGeneration = candidate.Generation
			instance.Endpoint = state.Endpoint
			if candidate.InitiatorRole == InitiatorRoleSecondaryStandby && state.InitiatorKnown && state.Initiator {
				instance.InitiatorRole = InitiatorRoleSecondaryTakeover
			}
			observed = append(observed, observedRuntime{spec: candidate, instance: instance, established: true})
			continue
		}
		if hasMatchingConnection(connections, candidate) {
			linkState := LinkStateConnecting
			if candidate.InitiatorRole == "" {
				linkState = LinkStateWaitingInbound
			}
			instance := NewLinkInstance(candidate, linkState, now)
			instance.RemoteGeneration = candidate.Generation
			observed = append(observed, observedRuntime{spec: candidate, instance: instance})
		}
	}
	if len(observed) == 0 {
		return LinkInstance{}, false, nil
	}
	if len(observed) == 1 {
		return observed[0].instance, true, nil
	}
	if observed[0].spec.Generation != contactGeneration(spec) {
		// Current is absent. Keep the newest observed previous generation as
		// active and let ordinary reconciliation prepare current.
		return observed[0].instance, true, nil
	}

	// Port generations are ordered current-first. When both current and
	// previous resources survive a crash, retain previous as the active side
	// and reconstruct current as staged. This gives the ordinary rotation
	// reconciler ownership of both generations so it can restart retention and
	// cleanly retire previous, instead of adopting current and orphaning the
	// older connection/XFRM interface.
	staged := observed[0]
	active := observed[1].instance
	active.StagedGeneration = staged.spec.Generation
	active.StagedIKEName = staged.spec.TransportID
	active.StagedChildSAName = ChildSAName(staged.spec)
	active.StagedInterfaceName = staged.spec.InterfaceName
	active.StagedXFRMIfID = staged.spec.XFRMIfID
	active.StagedLocalTunnelAddr = staged.spec.LocalTunnelAddr
	active.StagedPeerTunnelAddr = staged.spec.PeerTunnelAddr
	active.RotatePhase = RotatePhaseTestingNew
	if !staged.established && IsActiveInitiatorRole(active.InitiatorRole) {
		// A loaded current connection without an SA is an in-flight prepare.
		// Restart its bounded deadline from startup; no stale deadline or
		// backoff is recovered from disk.
		active.RotateDeadline = now.Add(rotateTimeout()).Unix()
		if active.InitiatorRole == InitiatorRoleSecondaryTakeover && observed[1].established {
			wait := takeoverDelayFor(group.Reconcile.Backoff, active.FailureCount)
			active.StagedNextAttempt = now.Add(wait).Unix()
			active.RotateDeadline = now.Add(wait + rotateTimeout()).Unix()
		}
	}
	return active, true, nil
}

func hasMatchingXFRMLink(states []XFRMLinkState, spec TransportLinkSpec, netns NetNSSpec) bool {
	wantNetNS := netns.Normalized()
	for _, state := range states {
		if !state.NamespaceExists || !state.InterfaceExists ||
			!sameNetNS(state.NetNS, wantNetNS) ||
			state.InterfaceName != spec.InterfaceName || state.XFRMIfID != spec.XFRMIfID {
			continue
		}
		if !spec.LocalTunnelAddr.IsValid() {
			return true
		}
		for _, address := range state.Addresses {
			if address.Addr() == spec.LocalTunnelAddr {
				return true
			}
		}
	}
	return false
}

func findInstanceSA(states []SAState, inst LinkInstance) SAState {
	var best SAState
	bestMatches := false
	for _, state := range states {
		if !saMatchesPathKey(state, inst.PathKey) {
			continue
		}
		if state.Name == inst.IKEName || state.ChildSA == inst.ChildSAName || (inst.XFRMIfID != 0 && state.XFRMIfID == inst.XFRMIfID) {
			matches := saIdentityMatchesInstance(state, inst) && (inst.XFRMIfID == 0 || state.XFRMIfID == inst.XFRMIfID)
			if inst.SelectedContact.Address != "" || inst.SelectedContact.Host != "" {
				matches = matches && saEndpointMatchesSpec(state, TransportLinkSpec{ContactPoints: []ContactPoint{inst.SelectedContact}})
			}
			if preferObservedSA(state, best, matches, bestMatches) {
				best, bestMatches = state, matches
			}
		}
	}
	return best
}

// Selection must not depend on list-sas/map iteration order. Prefer a working
// SA matching the verified runtime; stable age/ID ties retain an existing path
// while a second negotiation is still arriving under the same config name.
func preferObservedSA(candidate, current SAState, candidateMatches, currentMatches bool) bool {
	if !saObserved(current) {
		return true
	}
	if candidate.Established != current.Established {
		return candidate.Established
	}
	if candidateMatches != currentMatches {
		return candidateMatches
	}
	return olderSA(candidate, current)
}

func saMatchesPathKey(sa SAState, pathKey string) bool {
	family := pathKeyFamily(pathKey)
	if family == "" {
		return true
	}
	endpointFamily := saEndpointFamily(sa)
	return endpointFamily == "" || endpointFamily == family
}

func saIdentityMatchesSpec(sa SAState, spec TransportLinkSpec) bool {
	if sa.RemoteIdentity != "" && spec.PeerZone != "" && sa.RemoteIdentity != string(spec.PeerZone) {
		return false
	}
	if sa.LocalIdentity != "" && spec.LocalZone != "" && sa.LocalIdentity != string(spec.LocalZone) {
		return false
	}
	return true
}

func saIdentityMatchesInstance(sa SAState, inst LinkInstance) bool {
	if sa.RemoteIdentity != "" && inst.PeerZone != "" && sa.RemoteIdentity != string(inst.PeerZone) {
		return false
	}
	return true
}

func pathKeyFamily(pathKey string) string {
	if !strings.HasPrefix(pathKey, "family:") {
		return ""
	}
	family := strings.TrimPrefix(pathKey, "family:")
	if validFamily(family) {
		return family
	}
	return ""
}

func saEndpointFamily(sa SAState) string {
	endpoint := firstNonEmptyString(sa.RemoteEndpoint, sa.Endpoint)
	host := endpointHost(endpoint)
	if host == "" {
		return ""
	}
	return inferIPFamily(host)
}

func endpointHost(endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(endpoint); err == nil {
		return strings.Trim(host, "[]")
	}
	if strings.HasPrefix(endpoint, "[") {
		if end := strings.Index(endpoint, "]"); end > 1 {
			return endpoint[1:end]
		}
	}
	return endpoint
}

func sameSARuntime(a, b SAState) bool {
	if !saObserved(a) || !saObserved(b) {
		return false
	}
	if a.Name != "" && b.Name != "" && a.Name == b.Name {
		return true
	}
	if a.ChildSA != "" && b.ChildSA != "" && a.ChildSA == b.ChildSA {
		return true
	}
	return a.XFRMIfID != 0 && b.XFRMIfID != 0 && a.XFRMIfID == b.XFRMIfID
}

func firstContactPointForGeneration(spec TransportLinkSpec, generation uint64) (ContactPoint, bool) {
	for _, point := range spec.ContactPoints {
		if point.Generation == generation {
			return point, true
		}
	}
	return firstContactPoint(spec.ContactPoints)
}

func endpointForSpec(spec TransportLinkSpec) string {
	point, ok := firstContactPoint(spec.ContactPoints)
	if !ok {
		return ""
	}
	return contactEndpoint(point)
}

func contactEndpoint(point ContactPoint) string {
	if point.Address != "" {
		return point.Address
	}
	return point.Host
}
