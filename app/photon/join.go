package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"slices"
	"time"

	"github.com/HiggsNet/photon/internal/photonlinux"
	"github.com/HiggsNet/photon/pkg/core/gossip"
	"github.com/HiggsNet/photon/pkg/core/share"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

type privateKeyFile = share.PrivateKeyFile

type joinBundle = share.JoinBundle

type joinAcceptResult struct {
	Zone          zone.ZonePath
	RootPublicKey ed25519.PublicKey
}

var errDelegationAlreadyExists = errors.New("delegation already exists")

func createJoinRequest(path zone.ZonePath, keyPath string, outPath string) error {
	if !path.Valid() || path == zone.RootZone {
		return fmt.Errorf("invalid join zone: %s", path)
	}
	key, err := readPrivateKeyFile(keyPath)
	if err != nil {
		return err
	}
	request, err := gossip.NewJoinRequest(path, key.PublicKey)
	if err != nil {
		return err
	}
	if outPath == "" {
		text, err := share.EncodeBase64JSON(request)
		if err != nil {
			return err
		}
		fmt.Printf("%s\n", text)
		return nil
	}
	if err := writeBase64JSONFile(outPath, 0o644, request); err != nil {
		return err
	}
	fmt.Printf("wrote join request: %s\n", outPath)
	return nil
}

func issueDelegation(requestInput string, outPath string, permissions []zone.Permission, direct bool) error {
	config, err := loadAppConfig()
	if err != nil {
		return err
	}

	var request gossip.JoinRequest
	if err := readBase64JSONOrJSON(requestInput, &request); err != nil {
		return err
	}
	if err := gossip.ValidateJoinRequest(&request); err != nil {
		return err
	}
	bundle, controlled, err := issueDelegationViaControl(config, &request, permissions, direct)
	if err != nil {
		return err
	}
	via := ""
	if controlled {
		via = " via daemon"
	} else {
		if !direct {
			logControlFallback("delegate_issue")
		}
		bundle, err = issueDelegationDirect(config, &request, permissions, time.Now())
		if err != nil {
			return err
		}
	}

	if outPath == "" {
		fmt.Fprintf(os.Stderr, "issued delegation for %s%s\n", request.Zone, via)
		text, err := share.EncodeBase64JSON(bundle)
		if err != nil {
			return err
		}
		fmt.Printf("%s\n", text)
		return nil
	}
	fmt.Printf("issued delegation for %s%s\n", request.Zone, via)
	if err := writeBase64JSONFile(outPath, 0o644, bundle); err != nil {
		return err
	}
	fmt.Printf("wrote join bundle: %s\n", outPath)
	return nil
}

func issueDelegationDirect(config *appConfig, request *gossip.JoinRequest, permissions []zone.Permission, now time.Time) (*joinBundle, error) {
	if err := gossip.ValidateJoinRequest(request); err != nil {
		return nil, err
	}
	state, err := openState(config)
	if err != nil {
		return nil, err
	}
	defer state.Close()
	view := state.Common.ReadView()
	intent, err := planDelegationIssue(view.State.Network, request, permissions, now)
	if err != nil {
		return nil, err
	}
	if _, err := state.Common.ApplyLocalIntent(context.Background(), intent, now); err != nil {
		return nil, err
	}
	return joinBundleFromNetwork(state.Common.ReadView().State.Network, request.Zone, now)
}

func planDelegationIssue(network *zone.NetworkState, request *gossip.JoinRequest, permissions []zone.Permission, now time.Time) (corestate.LocalIntent, error) {
	if err := gossip.ValidateJoinRequest(request); err != nil {
		return nil, err
	}
	if network == nil {
		return nil, errors.New("network state is nil")
	}
	parent := request.Zone.Parent()
	parentState := network.Zones[parent]
	if parentState == nil || parentState.Authority == nil {
		return nil, fmt.Errorf("%w: parent %s", zone.ErrZoneNotFound, parent)
	}
	if network.ActiveRevocation(request.Zone, now) == nil && (parentState.Delegations[request.Zone] != nil || network.Zones[request.Zone] != nil) {
		return nil, fmt.Errorf("%w for %s; use gossip delegate grant to add permissions", errDelegationAlreadyExists, request.Zone)
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
			Key:          append([]byte(nil), request.PublicKey...),
			Capabilities: delegationCapabilities(permissions),
		}},
	}
	return corestate.PutDelegationIntent{Parent: parent, Authority: authority}, nil
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
	config, err := loadAppConfig()
	if err != nil {
		return err
	}

	controlled, err := revokeDelegationViaControl(config, path, reason, direct)
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
	if err := revokeDelegationDirect(config, path, reason, time.Now()); err != nil {
		return err
	}
	fmt.Printf("revoked delegation for %s\n", path)
	return nil
}

func revokeDelegationDirect(config *appConfig, path zone.ZonePath, reason string, now time.Time) error {
	if !path.Valid() || path == zone.RootZone {
		return fmt.Errorf("invalid revoke zone: %s", path)
	}
	state, err := openState(config)
	if err != nil {
		return err
	}
	defer state.Close()
	_, err = state.Common.ApplyLocalIntent(context.Background(), corestate.RevokeDelegationIntent{
		Parent: path.Parent(), Child: path, Reason: reason,
	}, now)
	return err
}

func acceptJoinBundle(bundleInput string, keyPath string, direct bool) error {
	config, err := loadAppConfig()
	if err != nil {
		return err
	}

	var bundle joinBundle
	if err := readBase64JSONOrJSON(bundleInput, &bundle); err != nil {
		return err
	}
	key, err := optionalJoinAcceptKey(keyPath)
	if err != nil {
		return err
	}
	controlled, err := acceptJoinBundleViaControl(config, &bundle, key, direct)
	if err != nil {
		return err
	}
	if controlled {
		fmt.Printf("joined %s via daemon in %s\n", bundle.Zone, config.StatePath)
		fmt.Printf("trusted root public key: %s\n", base64.StdEncoding.EncodeToString(bundle.RootPublicKey))
		return nil
	}
	if !direct {
		logControlFallback("join_accept")
	}
	result, err := acceptJoinBundleInState(config, &bundle, key, time.Now())
	if err != nil {
		return err
	}
	fmt.Printf("joined %s in %s\n", result.Zone, config.StatePath)
	fmt.Printf("trusted root public key: %s\n", base64.StdEncoding.EncodeToString(result.RootPublicKey))
	return nil
}

func acceptJoinBundleInState(config *appConfig, bundle *joinBundle, key *privateKeyFile, now time.Time) (*joinAcceptResult, error) {
	if config == nil || config.StatePath == "" {
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
	if trusted := config.TrustedRootPublicKey; len(trusted) != 0 && !bytes.Equal(trusted, bundle.RootPublicKey) {
		return nil, errors.New("join bundle root does not match trusted_root_public_key")
	}
	if err := photoncrypto.VerifyPinnedRoot(bundle.Network, bundle.RootPublicKey); err != nil {
		return nil, fmt.Errorf("join bundle root authority: %w", err)
	}
	boltStore, err := corestate.OpenBoltStore(config.StatePath, 0o600, daemonBoltLockTimeout)
	if err != nil {
		return nil, err
	}
	state, found, err := restoreState(boltStore, config.TrustedRootPublicKey)
	defer func() {
		if state != nil {
			_ = state.Close()
		} else {
			_ = boltStore.Close()
		}
	}()
	if err != nil {
		return nil, err
	}
	var common *corestate.Store
	if found {
		common = state.Common
	} else {
		common = corestate.NewStore(nil, nil)
		defer common.Close()
	}
	if key == nil {
		view := common.ReadView()
		key, err = joinAcceptKeyFromIdentity(view.State, bundle.Zone)
		if err != nil {
			return nil, err
		}
	}
	if err := key.Validate(); err != nil {
		return nil, err
	}
	if _, err := common.InstallIdentity(context.Background(), corestate.IdentityInstall{
		ManagedZone: bundle.Zone, Network: bundle.Network,
		TrustedRootPublicKey: bundle.RootPublicKey, IdentityPrivateKey: key.PrivateKey,
	}, now); err != nil {
		return nil, err
	}
	if !found {
		view := common.ReadView()
		if err := initializeStateDB(boltStore, &corestate.CommitCandidate{Verified: view.State, Gossip: view.Gossip}, view.Revision, &photonlinux.LinuxState{}); err != nil {
			return nil, err
		}
	}
	return &joinAcceptResult{Zone: bundle.Zone, RootPublicKey: append([]byte(nil), bundle.RootPublicKey...)}, nil
}

func optionalJoinAcceptKey(keyPath string) (*privateKeyFile, error) {
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

func readPrivateKeyFile(path string) (*privateKeyFile, error) {
	var key privateKeyFile
	if err := readJSONFile(path, &key); err != nil {
		return nil, err
	}
	if err := key.Validate(); err != nil {
		return nil, err
	}
	return &key, nil
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
