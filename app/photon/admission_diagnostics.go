package main

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	inspecttext "github.com/HiggsNet/photon/internal/inspect/text"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

// diagnoseAutoJoinAdmission derives the current auto-join status from common
// verified state and the loss-tolerant gossip checkpoint. It performs no I/O
// and owns no separately persisted admission snapshot.
func diagnoseAutoJoinAdmission(verified *corestate.VerifiedState, checkpoint *corestate.GossipCheckpoint, bootstrap []syncConfigPeer, now time.Time) inspect.AdmissionDiagnosis {
	if verified == nil {
		return inspect.AdmissionDiagnosis{}
	}
	d := inspect.AdmissionDiagnosis{
		ManagedZone: verified.ManagedZone,
		ParentZone:  verified.ManagedZone.Parent(),
	}
	d.LastBootstrapSyncUnix = lastBootstrapSyncUnix(checkpoint, bootstrap)

	if !autoJoinPendingVerified(verified) {
		d.Pending = false
		if verified.ManagedZone != zone.RootZone && verified.ManagedZone.Valid() {
			d.Reason = inspect.AdmissionReasonAdopted
		} else {
			d.Reason = inspect.AdmissionReasonNotApplicable
		}
		return d
	}

	d.Pending = true

	// Build join request for diagnostics.
	if len(verified.IdentityPrivateKey) == ed25519.PrivateKeySize {
		d.HasZonePrivateKey = true
		pub := verified.IdentityPrivateKey.Public().(ed25519.PublicKey)
		request := joinRequest{Version: 1, Zone: verified.ManagedZone, PublicKey: pub}
		if text, err := encodeBase64JSON(&request); err == nil {
			d.JoinRequestB64 = text
		}
	} else {
		d.Reason = inspect.AdmissionReasonMissingZoneKey
		d.ReasonDetail = "zone private key is not loaded; check identity.key_path in config"
		return d
	}

	// Check parent zone presence.
	if verified.Network == nil {
		d.Reason = inspect.AdmissionReasonMissingParentZone
		d.ReasonDetail = "network state is empty; bootstrap peer must sync the parent zone"
		return d
	}
	parentState := verified.Network.Zones[d.ParentZone]
	if parentState == nil {
		d.Reason = inspect.AdmissionReasonMissingParentZone
		d.ReasonDetail = fmt.Sprintf("parent zone %s is not in local verified state; waiting for bootstrap sync", d.ParentZone)
		return d
	}
	d.ParentZoneKnown = true
	if parentState.Authority == nil {
		d.Reason = inspect.AdmissionReasonMissingParentZone
		d.ReasonDetail = fmt.Sprintf("parent zone %s has no authority; waiting for bootstrap sync", d.ParentZone)
		return d
	}
	d.ParentAuthorityKnown = true

	// Check delegation presence.
	delegation := parentState.Delegations[verified.ManagedZone]
	if delegation == nil {
		d.Reason = inspect.AdmissionReasonMissingDelegation
		d.ReasonDetail = fmt.Sprintf("parent zone %s has no delegation for %s; parent zone admin must run 'delegate issue'", d.ParentZone, verified.ManagedZone)
		return d
	}
	d.DelegationKnown = true

	// Check delegation key match.
	pub := verified.IdentityPrivateKey.Public().(ed25519.PublicKey)
	if delegation.ZoneName != verified.ManagedZone || delegation.Authority.Zone != verified.ManagedZone || !authorityHasKey(&delegation.Authority, pub) {
		d.Reason = inspect.AdmissionReasonDelegationKeyMismatch
		d.ReasonDetail = "delegation authority does not match local zone private key; parent zone admin may have signed for a different public key"
		return d
	}
	d.DelegationKeyMatches = true

	// Check VerifyDelegation.
	if err := photoncrypto.VerifyDelegation(delegation, parentState.Authority, d.ParentZone, now); err != nil {
		d.Reason = inspect.AdmissionReasonVerifyDelegationFailed
		d.ReasonDetail = fmt.Sprintf("VerifyDelegation failed: %v", err)
		return d
	}

	// All checks pass — either we should be adopted on next sync, or
	// VerifyChain would fail if we tried to materialize now.
	d.Reason = inspect.AdmissionReasonWaitingForAdoption
	if d.LastBootstrapSyncUnix == 0 {
		d.Reason = inspect.AdmissionReasonNoBootstrapSync
		d.ReasonDetail = "no bootstrap peer has successfully synced yet; check bootstrap config and peer reachability"
	} else {
		d.ReasonDetail = "all local checks pass; adoption will complete on next sync round that applies the delegation"
	}

	return d
}

func lastBootstrapSyncUnix(checkpoint *corestate.GossipCheckpoint, bootstrap []syncConfigPeer) int64 {
	if checkpoint == nil {
		return 0
	}
	var latest int64
	for _, peer := range bootstrap {
		if synced := checkpoint.Peers[peer.ID].LastSyncUnix; synced > latest {
			latest = synced
		}
	}
	return latest
}

func debugAdmission() error {
	rt, err := NewAppContext()
	if err != nil {
		return err
	}
	if diagnosis, ok, err := admissionStatusViaControl(rt); err != nil {
		return err
	} else if ok {
		fmt.Fprintln(os.Stdout, "daemon: online")
		return inspecttext.WriteAdmissionDiagnosis(os.Stdout, diagnosis)
	}
	common, _, err := loadOfflineOwnerViews(rt)
	if err != nil {
		return err
	}
	if common.State == nil {
		return fmt.Errorf("common state owner is not initialized")
	}
	diagnosis := diagnoseAutoJoinAdmission(common.State, common.Gossip, rt.Config.Bootstrap, rt.Now())
	return inspecttext.WriteAdmissionDiagnosis(os.Stdout, diagnosis)
}
