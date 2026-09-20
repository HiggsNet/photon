package gossip

import (
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/HiggsNet/photon/pkg/core/share"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

const (
	AdmissionReasonAdopted                = "adopted"
	AdmissionReasonNotApplicable          = "not_applicable"
	AdmissionReasonMissingZoneKey         = "missing_zone_private_key"
	AdmissionReasonMissingParentZone      = "missing_parent_zone"
	AdmissionReasonMissingDelegation      = "missing_delegation"
	AdmissionReasonDelegationKeyMismatch  = "delegation_key_mismatch"
	AdmissionReasonVerifyDelegationFailed = "verify_delegation_failed"
	AdmissionReasonNoBootstrapSync        = "no_bootstrap_sync"
	AdmissionReasonWaitingForAdoption     = "waiting_for_adoption"
)

// AdmissionDiagnosis is the structured result of diagnosing an auto-join
// pending state.
type AdmissionDiagnosis struct {
	// Pending is true when the node is in auto-join pending state.
	Pending bool `json:"pending"`
	// ManagedZone is the zone this node is trying to materialize.
	ManagedZone zone.ZonePath `json:"managed_zone,omitempty"`
	// ParentZone is the immediate parent zone.
	ParentZone zone.ZonePath `json:"parent_zone,omitempty"`
	// Reason is the structured pending reason code.
	Reason string `json:"reason,omitempty"`
	// ReasonDetail provides additional human-readable context.
	ReasonDetail string `json:"reason_detail,omitempty"`
	// JoinRequestB64 is the base64-encoded join request that the parent zone
	// admin needs to sign a delegation for.
	JoinRequestB64 string `json:"join_request_b64,omitempty"`
	// HasZonePrivateKey indicates whether the local state has a usable zone
	// private key for adoption.
	HasZonePrivateKey bool `json:"has_zone_private_key"`
	// ParentZoneKnown indicates whether the parent zone exists in the local
	// verified state.
	ParentZoneKnown bool `json:"parent_zone_known"`
	// ParentAuthorityKnown indicates whether the parent zone has a usable
	// authority in local state.
	ParentAuthorityKnown bool `json:"parent_authority_known"`
	// DelegationKnown indicates whether a delegation for the managed zone
	// exists in the parent zone.
	DelegationKnown bool `json:"delegation_known"`
	// DelegationKeyMatches indicates whether the delegation authority
	// contains the local zone private key's public key.
	DelegationKeyMatches bool `json:"delegation_key_matches"`
	// LastBootstrapSyncUnix is the most recent successful bootstrap sync
	// timestamp (0 = never).
	LastBootstrapSyncUnix int64 `json:"last_bootstrap_sync_unix,omitempty"`
}

// AutoJoinPending reports whether a valid non-root identity has yet to be adopted.
func AutoJoinPending(state *corestate.VerifiedState) bool {
	if state == nil || !state.ManagedZone.Valid() || state.ManagedZone == zone.RootZone {
		return false
	}
	if state.Network == nil {
		return true
	}
	zs := state.Network.Zones[state.ManagedZone]
	if zs == nil || zs.Authority == nil {
		return true
	}
	if len(state.IdentityPrivateKey) != ed25519.PrivateKeySize {
		return true
	}
	pub := state.IdentityPrivateKey.Public().(ed25519.PublicKey)
	return !zs.Authority.HasPublicKey(pub)
}

// DiagnoseAutoJoinAdmission derives the current auto-join status from common
// verified state and the loss-tolerant gossip checkpoint. It performs no I/O
// and owns no separately persisted admission snapshot.
func DiagnoseAutoJoinAdmission(verified *corestate.VerifiedState, checkpoint *corestate.GossipCheckpoint, bootstrap []string, now time.Time) AdmissionDiagnosis {
	if verified == nil {
		return AdmissionDiagnosis{}
	}
	d := AdmissionDiagnosis{
		ManagedZone: verified.ManagedZone,
		ParentZone:  verified.ManagedZone.Parent(),
	}
	d.LastBootstrapSyncUnix = lastBootstrapSyncUnix(checkpoint, bootstrap)

	if !AutoJoinPending(verified) {
		d.Pending = false
		if verified.ManagedZone != zone.RootZone && verified.ManagedZone.Valid() {
			d.Reason = AdmissionReasonAdopted
		} else {
			d.Reason = AdmissionReasonNotApplicable
		}
		return d
	}

	d.Pending = true

	// Build join request for diagnostics.
	if len(verified.IdentityPrivateKey) == ed25519.PrivateKeySize {
		d.HasZonePrivateKey = true
		pub := verified.IdentityPrivateKey.Public().(ed25519.PublicKey)
		if request, err := NewJoinRequest(verified.ManagedZone, pub); err == nil {
			if text, err := share.EncodeBase64JSON(request); err == nil {
				d.JoinRequestB64 = text
			}
		}
	} else {
		d.Reason = AdmissionReasonMissingZoneKey
		d.ReasonDetail = "zone private key is not loaded"
		return d
	}

	// Check parent zone presence.
	if verified.Network == nil {
		d.Reason = AdmissionReasonMissingParentZone
		d.ReasonDetail = "network state is empty; bootstrap peer must sync the parent zone"
		return d
	}
	parentState := verified.Network.Zones[d.ParentZone]
	if parentState == nil {
		d.Reason = AdmissionReasonMissingParentZone
		d.ReasonDetail = fmt.Sprintf("parent zone %s is not in local verified state; waiting for bootstrap sync", d.ParentZone)
		return d
	}
	d.ParentZoneKnown = true
	if parentState.Authority == nil {
		d.Reason = AdmissionReasonMissingParentZone
		d.ReasonDetail = fmt.Sprintf("parent zone %s has no authority; waiting for bootstrap sync", d.ParentZone)
		return d
	}
	d.ParentAuthorityKnown = true

	// Check delegation presence.
	delegation := parentState.Delegations[verified.ManagedZone]
	if delegation == nil {
		d.Reason = AdmissionReasonMissingDelegation
		d.ReasonDetail = fmt.Sprintf("parent zone %s has no delegation for %s; parent zone admin must run 'delegate issue'", d.ParentZone, verified.ManagedZone)
		return d
	}
	d.DelegationKnown = true

	// Check delegation key match.
	pub := verified.IdentityPrivateKey.Public().(ed25519.PublicKey)
	if delegation.ZoneName != verified.ManagedZone || delegation.Authority.Zone != verified.ManagedZone || !delegation.Authority.HasPublicKey(pub) {
		d.Reason = AdmissionReasonDelegationKeyMismatch
		d.ReasonDetail = "delegation authority does not match local zone private key; parent zone admin may have signed for a different public key"
		return d
	}
	d.DelegationKeyMatches = true

	// Check VerifyDelegation.
	if err := photoncrypto.VerifyDelegation(delegation, parentState.Authority, d.ParentZone, now); err != nil {
		d.Reason = AdmissionReasonVerifyDelegationFailed
		d.ReasonDetail = fmt.Sprintf("VerifyDelegation failed: %v", err)
		return d
	}

	// All checks pass — either we should be adopted on next sync, or
	// VerifyChain would fail if we tried to materialize now.
	d.Reason = AdmissionReasonWaitingForAdoption
	if d.LastBootstrapSyncUnix == 0 {
		d.Reason = AdmissionReasonNoBootstrapSync
		d.ReasonDetail = "no bootstrap peer has successfully synced yet; check bootstrap config and peer reachability"
	} else {
		d.ReasonDetail = "all local checks pass; waiting for a sync round to apply the delegation and verify the full chain"
	}

	return d
}

func lastBootstrapSyncUnix(checkpoint *corestate.GossipCheckpoint, bootstrap []string) int64 {
	if checkpoint == nil {
		return 0
	}
	var latest int64
	for _, peer := range bootstrap {
		if synced := checkpoint.Peers[peer].LastSyncUnix; synced > latest {
			latest = synced
		}
	}
	return latest
}
