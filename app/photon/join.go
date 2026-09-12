package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"github.com/HiggsNet/photon/internal/photonlinux"
	"os"
	"slices"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

type privateKeyFile struct {
	Type       string             `json:"type"`
	PublicKey  ed25519.PublicKey  `json:"public_key"`
	PrivateKey ed25519.PrivateKey `json:"private_key"`
}

type joinRequest struct {
	Version   uint8             `json:"version"`
	Zone      zone.ZonePath     `json:"zone"`
	PublicKey ed25519.PublicKey `json:"public_key"`
}

type joinBundle struct {
	Version       uint8              `json:"version"`
	Zone          zone.ZonePath      `json:"zone"`
	RootPublicKey ed25519.PublicKey  `json:"root_public_key"`
	Network       *zone.NetworkState `json:"network"`
}

type delegationIssueResult struct {
	Zone   zone.ZonePath
	Bundle *joinBundle
}

type joinAcceptResult struct {
	Zone          zone.ZonePath
	RootPublicKey ed25519.PublicKey
}

func createJoinRequest(path zone.ZonePath, keyPath string, outPath string) error {
	if !path.Valid() || path == zone.RootZone {
		return fmt.Errorf("invalid join zone: %s", path)
	}
	key, err := readPrivateKeyFile(keyPath)
	if err != nil {
		return err
	}
	request := joinRequest{
		Version:   1,
		Zone:      path,
		PublicKey: key.PublicKey,
	}
	if outPath == "" {
		text, err := encodeBase64JSON(&request)
		if err != nil {
			return err
		}
		fmt.Printf("%s\n", text)
		return nil
	}
	if err := writeBase64JSONFile(outPath, 0o644, &request); err != nil {
		return err
	}
	fmt.Printf("wrote join request: %s\n", outPath)
	return nil
}

func issueDelegation(requestInput string, outPath string, permissions []zone.Permission, direct bool) error {
	rt, err := NewAppContext()
	if err != nil {
		return err
	}
	rt.DisableControl = direct
	var request joinRequest
	if err := readBase64JSONOrJSON(requestInput, &request); err != nil {
		return err
	}
	if err := validateJoinRequest(&request); err != nil {
		return err
	}
	bundle, controlled, err := issueDelegationViaControl(rt, &request, permissions)
	if err != nil {
		return err
	}
	if controlled {
		if outPath == "" {
			fmt.Fprintf(os.Stderr, "issued delegation for %s via daemon\n", request.Zone)
			text, err := encodeBase64JSON(bundle)
			if err != nil {
				return err
			}
			fmt.Printf("%s\n", text)
			return nil
		}
		fmt.Printf("issued delegation for %s via daemon\n", request.Zone)
		if err := writeBase64JSONFile(outPath, 0o644, bundle); err != nil {
			return err
		}
		fmt.Printf("wrote join bundle: %s\n", outPath)
		return nil
	}
	if !direct {
		logControlFallback("delegate_issue")
	}
	result, err := issueDelegationDirect(rt, &request, permissions)
	if err != nil {
		return err
	}
	if outPath == "" {
		fmt.Fprintf(os.Stderr, "issued delegation for %s\n", request.Zone)
		text, err := encodeBase64JSON(result.Bundle)
		if err != nil {
			return err
		}
		fmt.Printf("%s\n", text)
		return nil
	}
	fmt.Printf("issued delegation for %s\n", request.Zone)
	if err := writeBase64JSONFile(outPath, 0o644, result.Bundle); err != nil {
		return err
	}
	fmt.Printf("wrote join bundle: %s\n", outPath)
	return nil
}

func issueDelegationDirect(rt *AppContext, request *joinRequest, permissions []zone.Permission) (*delegationIssueResult, error) {
	if err := validateJoinRequest(request); err != nil {
		return nil, err
	}
	state, err := openState(rt)
	if err != nil {
		return nil, err
	}
	defer state.Close()
	view := state.Common.ReadView()
	parent := request.Zone.Parent()
	parentState := view.State.Network.Zones[parent]
	if parentState == nil || parentState.Authority == nil {
		return nil, fmt.Errorf("%w: parent %s", zone.ErrZoneNotFound, parent)
	}
	authorityEpoch := uint64(1)
	if parentState.Revocations != nil {
		if revocation := parentState.Revocations[request.Zone]; revocation != nil && revocation.RevokedAuthorityEpoch >= authorityEpoch {
			authorityEpoch = revocation.RevokedAuthorityEpoch + 1
		}
	}
	authority := &zone.ZoneAuthority{
		Zone:      request.Zone,
		Epoch:     authorityEpoch,
		Threshold: photoncrypto.SupportedThreshold,
		Keys: []zone.AuthorizedKey{{
			Key:          request.PublicKey,
			Capabilities: delegationCapabilities(permissions),
		}},
	}
	if _, err := state.Common.ApplyLocalIntent(context.Background(), corestate.PutDelegationIntent{
		Parent: parent, Authority: authority,
	}, rt.Now()); err != nil {
		return nil, err
	}
	bundle, err := joinBundleFromNetwork(state.Common.ReadView().State.Network, request.Zone, rt.Now())
	if err != nil {
		return nil, err
	}
	return &delegationIssueResult{Zone: request.Zone, Bundle: bundle}, nil
}

func delegationCapabilities(permissions []zone.Permission) []zone.Capability {
	if len(permissions) == 0 {
		return defaultDelegationCapabilities()
	}
	out := append([]zone.Permission(nil), permissions...)
	slices.Sort(out)
	return []zone.Capability{{Permissions: out}}
}

func revokeDelegation(path zone.ZonePath, reason string, direct bool) error {
	rt, err := NewAppContext()
	if err != nil {
		return err
	}
	rt.DisableControl = direct
	controlled, err := revokeDelegationViaControl(rt, path, reason)
	if err != nil {
		return err
	}
	if controlled {
		fmt.Printf("revoked delegation for %s via daemon\n", path)
		return nil
	}
	if !direct {
		logControlFallback("delegate_revoke")
	}
	if err := revokeDelegationDirect(rt, path, reason); err != nil {
		return err
	}
	fmt.Printf("revoked delegation for %s\n", path)
	return nil
}

func revokeDelegationDirect(rt *AppContext, path zone.ZonePath, reason string) error {
	if !path.Valid() || path == zone.RootZone {
		return fmt.Errorf("invalid revoke zone: %s", path)
	}
	state, err := openState(rt)
	if err != nil {
		return err
	}
	defer state.Close()
	_, err = state.Common.ApplyLocalIntent(context.Background(), corestate.RevokeDelegationIntent{
		Parent: path.Parent(), Child: path, Reason: reason,
	}, rt.Now())
	return err
}

func acceptJoinBundle(bundleInput string, keyPath string, direct bool) error {
	rt, err := NewAppContext()
	if err != nil {
		return err
	}
	rt.DisableControl = direct
	var bundle joinBundle
	if err := readBase64JSONOrJSON(bundleInput, &bundle); err != nil {
		return err
	}
	key, err := optionalJoinAcceptKey(rt, keyPath)
	if err != nil {
		return err
	}
	controlled, err := acceptJoinBundleViaControl(rt, &bundle, key)
	if err != nil {
		return err
	}
	if controlled {
		fmt.Printf("joined %s via daemon in %s\n", bundle.Zone, rt.StatePath)
		fmt.Printf("trusted root public key: %s\n", formatPublicKey(bundle.RootPublicKey))
		return nil
	}
	if !direct {
		logControlFallback("join_accept")
	}
	result, err := acceptJoinBundleInState(rt, &bundle, key)
	if err != nil {
		return err
	}
	fmt.Printf("joined %s in %s\n", result.Zone, rt.StatePath)
	fmt.Printf("trusted root public key: %s\n", formatPublicKey(result.RootPublicKey))
	return nil
}

func acceptJoinBundleInState(rt *AppContext, bundle *joinBundle, key *privateKeyFile) (*joinAcceptResult, error) {
	if rt == nil || rt.Config == nil || rt.StatePath == "" {
		return nil, errors.New("runtime state path is not configured")
	}
	if bundle == nil {
		return nil, errors.New("join bundle is nil")
	}
	if bundle.Version != 1 {
		return nil, fmt.Errorf("unsupported join bundle version: %d", bundle.Version)
	}
	if bundle.Network == nil {
		return nil, errors.New("join bundle network is nil")
	}
	boltStore, err := corestate.OpenBoltStore(rt.StatePath, 0o600, daemonBoltLockTimeout)
	if err != nil {
		return nil, err
	}
	state, found, err := restoreState(boltStore, rt.Config.TrustedRootPublicKey)
	if err != nil {
		_ = boltStore.Close()
		return nil, err
	}
	if !found {
		if key == nil {
			_ = boltStore.Close()
			return nil, errors.New("join accept requires key.json because no existing state is available")
		}
		if err := validatePrivateKeyFile(key); err != nil {
			_ = boltStore.Close()
			return nil, err
		}
		initial := corestate.NewStore(nil, nil)
		if _, err := initial.InstallIdentity(context.Background(), corestate.IdentityInstall{
			ManagedZone: bundle.Zone, Network: bundle.Network,
			TrustedRootPublicKey: bundle.RootPublicKey, IdentityPrivateKey: key.PrivateKey,
		}, rt.Now()); err != nil {
			_ = boltStore.Close()
			return nil, err
		}
		view := initial.ReadView()
		if err := initializeStateDB(boltStore, &corestate.CommitCandidate{Verified: view.State, Gossip: view.Gossip}, view.Revision, &photonlinux.LinuxState{}); err != nil {
			_ = boltStore.Close()
			return nil, err
		}
		state, found, err = restoreState(boltStore, rt.Config.TrustedRootPublicKey)
		if err != nil {
			_ = boltStore.Close()
			return nil, err
		}
		if !found {
			_ = boltStore.Close()
			return nil, errors.New("initialized join state could not be restored")
		}
	}
	defer state.Close()
	if key == nil {
		view := state.Common.ReadView()
		key, err = joinAcceptKeyFromIdentity(view.State, bundle.Zone)
		if err != nil {
			return nil, err
		}
	}
	if err := validatePrivateKeyFile(key); err != nil {
		return nil, err
	}
	if _, err := state.Common.InstallIdentity(context.Background(), corestate.IdentityInstall{
		ManagedZone: bundle.Zone, Network: bundle.Network,
		TrustedRootPublicKey: bundle.RootPublicKey, IdentityPrivateKey: key.PrivateKey,
	}, rt.Now()); err != nil {
		return nil, err
	}
	return &joinAcceptResult{Zone: bundle.Zone, RootPublicKey: append([]byte(nil), bundle.RootPublicKey...)}, nil
}

func optionalJoinAcceptKey(_ *AppContext, keyPath string) (*privateKeyFile, error) {
	if keyPath != "" {
		return readPrivateKeyFile(keyPath)
	}
	return nil, nil
}

func joinAcceptKeyFromIdentity(state *corestate.VerifiedState, expectedZone zone.ZonePath) (*privateKeyFile, error) {
	if state == nil {
		return nil, errors.New("join accept requires key.json because no existing state is available")
	}
	if state.ManagedZone != expectedZone {
		return nil, fmt.Errorf("join accept requires key.json because existing state manages %s, not %s", state.ManagedZone, expectedZone)
	}
	if len(state.IdentityPrivateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("join accept requires key.json because existing state has no zone_private_key")
	}
	pub := state.IdentityPrivateKey.Public().(ed25519.PublicKey)
	return &privateKeyFile{
		Type:       "photon.ed25519.private.v1",
		PublicKey:  append([]byte(nil), pub...),
		PrivateKey: append([]byte(nil), state.IdentityPrivateKey...),
	}, nil
}

func rootPublicKey(ns *zone.NetworkState) (ed25519.PublicKey, error) {
	root := ns.Zones[zone.RootZone]
	if root == nil || root.Authority == nil || len(root.Authority.Keys) == 0 {
		return nil, errors.New("root authority has no public key")
	}
	return root.Authority.Keys[0].Key, nil
}

func authorityHasKey(authority *zone.ZoneAuthority, pub ed25519.PublicKey) bool {
	for _, key := range authority.Keys {
		if equalPublicKey(key.Key, pub) {
			return true
		}
	}
	return false
}

func readPrivateKeyFile(path string) (*privateKeyFile, error) {
	var key privateKeyFile
	if err := readJSONFile(path, &key); err != nil {
		return nil, err
	}
	if err := validatePrivateKeyFile(&key); err != nil {
		return nil, err
	}
	return &key, nil
}

func validatePrivateKeyFile(key *privateKeyFile) error {
	if key == nil {
		return errors.New("private key is nil")
	}
	if key.Type != "photon.ed25519.private.v1" {
		return errors.New("unsupported key file type")
	}
	if len(key.PrivateKey) != ed25519.PrivateKeySize || len(key.PublicKey) != ed25519.PublicKeySize {
		return errors.New("invalid ed25519 key file")
	}
	derived := key.PrivateKey.Public().(ed25519.PublicKey)
	if !equalPublicKey(derived, key.PublicKey) {
		return errors.New("private key does not match public key")
	}
	return nil
}

func validateJoinRequest(request *joinRequest) error {
	if request == nil {
		return errors.New("join request is nil")
	}
	if request.Version != 1 {
		return fmt.Errorf("unsupported join request version: %d", request.Version)
	}
	if !request.Zone.Valid() || request.Zone == zone.RootZone {
		return fmt.Errorf("invalid join zone: %s", request.Zone)
	}
	if len(request.PublicKey) != ed25519.PublicKeySize {
		return errors.New("join request public key is invalid")
	}
	return nil
}

func minimalNetworkForJoinBundle(ns *zone.NetworkState, target zone.ZonePath) (*zone.NetworkState, error) {
	if ns == nil {
		return nil, errors.New("network state is nil")
	}
	if !target.Valid() || target == zone.RootZone {
		return nil, fmt.Errorf("invalid join zone: %s", target)
	}
	out := zone.NewNetworkState()
	ancestors := target.Ancestors()
	for _, path := range slices.Backward(ancestors) {

		source := ns.Zones[path]
		if source == nil || source.Authority == nil {
			return nil, fmt.Errorf("%w: %s", zone.ErrZoneNotFound, path)
		}
		zs := zone.NewZoneState(path, cloneAuthorityForJoinBundle(source.Authority))
		if path != zone.RootZone {
			proof, err := directParentProofForBundle(ns, path, source)
			if err != nil {
				return nil, err
			}
			zs.ParentProof = []*zone.Delegation{proof}
		}
		out.Zones[path] = zs
	}
	normalizeState(out)
	return out, nil
}

func directParentProofForBundle(ns *zone.NetworkState, path zone.ZonePath, source *zone.ZoneState) (*zone.Delegation, error) {
	parent := path.Parent()
	if parentState := ns.Zones[parent]; parentState != nil {
		if delegation := parentState.Delegations[path]; delegation != nil {
			return cloneDelegationForJoinBundle(delegation), nil
		}
	}
	for _, proof := range source.ParentProof {
		if proof != nil && proof.ZoneName == path {
			return cloneDelegationForJoinBundle(proof), nil
		}
	}
	return nil, fmt.Errorf("delegation not found: %s", path)
}

func cloneAuthorityForJoinBundle(authority *zone.ZoneAuthority) *zone.ZoneAuthority {
	if authority == nil {
		return nil
	}
	out := &zone.ZoneAuthority{
		Zone:      authority.Zone,
		Epoch:     authority.Epoch,
		Threshold: authority.Threshold,
		Keys:      make([]zone.AuthorizedKey, 0, len(authority.Keys)),
	}
	for _, key := range authority.Keys {
		cloned := zone.AuthorizedKey{
			Key:       append(ed25519.PublicKey(nil), key.Key...),
			NotBefore: key.NotBefore,
			NotAfter:  key.NotAfter,
		}
		if len(key.Capabilities) > 0 {
			cloned.Capabilities = make([]zone.Capability, 0, len(key.Capabilities))
			for _, capability := range key.Capabilities {
				cloned.Capabilities = append(cloned.Capabilities, zone.Capability{
					Permissions: append([]zone.Permission(nil), capability.Permissions...),
					KeyPrefix:   capability.KeyPrefix,
				})
			}
		}
		out.Keys = append(out.Keys, cloned)
	}
	return out
}

func cloneDelegationForJoinBundle(delegation *zone.Delegation) *zone.Delegation {
	if delegation == nil {
		return nil
	}
	out := &zone.Delegation{
		ZoneName:       delegation.ZoneName,
		Scope:          delegation.Scope,
		AuthorityEpoch: delegation.AuthorityEpoch,
		AuthorityHash:  append([]byte(nil), delegation.AuthorityHash...),
		Authority:      *cloneAuthorityForJoinBundle(&delegation.Authority),
		SignedBy:       append(ed25519.PublicKey(nil), delegation.SignedBy...),
		Signature:      append([]byte(nil), delegation.Signature...),
	}
	if delegation.ExpiresAt != nil {
		expiresAt := *delegation.ExpiresAt
		out.ExpiresAt = &expiresAt
	}
	return out
}
