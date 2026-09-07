package inspect

import "github.com/HiggsNet/photon/pkg/core/zone"

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
