package ipsec

import (
	"sort"
	"strings"
	"time"
)

const DuplicateSAGCGrace = 2 * time.Minute

// PlanDuplicateSAGC returns precise, unique-ID based cleanup actions for
// duplicate SAs of the same runtime connection. Each canonical role selects
// the same underlying survivor from its local perspective: primary keeps its
// oldest outbound SA, while secondary keeps its oldest inbound SA.
func PlanDuplicateSAGC(desired []TransportLinkSpec, instances map[string]LinkInstance, sas []SAState, roles map[string]string) []ReconcileAction {
	var actions []ReconcileAction
	for i := range desired {
		spec := desired[i]
		id := LinkInstanceID(spec)
		role := roleForSpec(id, spec, roles)
		if role != InitiatorRolePrimary && role != InitiatorRoleSecondaryStandby {
			continue
		}
		inst, ok := instances[id]
		if ok && (inst.RotatePhase != RotatePhaseIdle || inst.StagedGeneration != 0) {
			continue
		}
		candidates := duplicateSACandidates(spec, sas)
		if len(candidates) < 2 || !duplicateSAsStable(candidates) {
			continue
		}

		// The canonical primary's SA is outbound on primary and inbound on
		// secondary. Both sides therefore select the same IKE_SA even when
		// their GC passes run concurrently.
		wantInitiator := role == InitiatorRolePrimary
		survivor := -1
		for j := range candidates {
			if candidates[j].Initiator != wantInitiator {
				continue
			}
			if survivor < 0 || olderSA(candidates[j], candidates[survivor]) {
				survivor = j
			}
		}
		if survivor < 0 {
			// The canonical direction is absent. Retaining every SA is safer
			// than deleting the only working takeover or responder path.
			continue
		}
		for j := range candidates {
			if j == survivor {
				continue
			}
			instance := inst
			actions = append(actions, ReconcileAction{
				Action:     ReconcileActionCleanupDuplicateSA,
				Spec:       &spec,
				Instance:   &instance,
				Reason:     "duplicate runtime SA stable for 2m",
				SAUniqueID: candidates[j].UniqueID,
			})
		}
	}
	sort.Slice(actions, func(i, j int) bool {
		left, right := actions[i], actions[j]
		if left.Spec.TransportID != right.Spec.TransportID {
			return left.Spec.TransportID < right.Spec.TransportID
		}
		return left.SAUniqueID < right.SAUniqueID
	})
	return actions
}

func duplicateSACandidates(spec TransportLinkSpec, sas []SAState) []SAState {
	child := ChildSAName(spec)
	byID := make(map[uint64]SAState)
	for _, sa := range sas {
		if !sa.Established || sa.Name != spec.TransportID || !duplicateChildSAMatch(sa.ChildSA, child) {
			continue
		}
		// Policy-backend SAs have no if_id (bound by traffic selectors).
		// Only reject an SA whose non-zero if_id disagrees with the spec.
		if spec.XFRMIfID != 0 && sa.XFRMIfID != 0 && sa.XFRMIfID != spec.XFRMIfID {
			continue
		}
		if !saMatchesPathKey(sa, spec.PathKey) || !saIdentityMatchesSpec(sa, spec) {
			continue
		}
		if sa.UniqueID == 0 || !sa.InitiatorKnown {
			continue
		}
		if current, ok := byID[sa.UniqueID]; !ok || olderSA(sa, current) {
			byID[sa.UniqueID] = sa
		}
	}
	out := make([]SAState, 0, len(byID))
	for _, sa := range byID {
		out = append(out, sa)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UniqueID < out[j].UniqueID })
	return out
}

// duplicateChildSAMatch matches a VICI child SA name against the configured
// child. charon appends a "-<uniqueid>" (6.x) or "{reqid}" (older) suffix to
// the runtime child name.
func duplicateChildSAMatch(saChild, child string) bool {
	if saChild == child {
		return true
	}
	if strings.HasPrefix(saChild, child+"-") && isAllDigits(strings.TrimPrefix(saChild, child+"-")) {
		return true
	}
	if i := strings.LastIndex(saChild, "{"); i > 0 && saChild[:i] == child {
		return true
	}
	return false
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func duplicateSAsStable(sas []SAState) bool {
	grace := uint64(DuplicateSAGCGrace / time.Second)
	for _, sa := range sas {
		if sa.IKEAgeSeconds < grace || sa.ChildAgeSeconds < grace {
			return false
		}
	}
	return true
}

func olderSA(a, b SAState) bool {
	if a.ChildAgeSeconds != b.ChildAgeSeconds {
		return a.ChildAgeSeconds > b.ChildAgeSeconds
	}
	if a.IKEAgeSeconds != b.IKEAgeSeconds {
		return a.IKEAgeSeconds > b.IKEAgeSeconds
	}
	return a.UniqueID < b.UniqueID
}
