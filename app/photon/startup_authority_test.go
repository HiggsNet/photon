package main

import (
	"crypto/ed25519"
	"path/filepath"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/photonlinux"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

// This remains an app test because it verifies the daemon startup composition:
// recovery repairs the cached managed authority and persists the repair.
func TestPrepareStartupStateRefreshesCachedManagedAuthority(t *testing.T) {
	state, config, rootPriv := buildManagedAuthorityRefreshState(t)
	now := time.Unix(2000, 0)
	managed := state.ManagedZone
	snapshot := managedAuthorityGrantSnapshot(t, state.Network, managed, rootPriv, zone.PermAllocateIP)
	state.Network.Zones[managed.Parent()].Delegations[managed] = cloneDelegationForJoinBundle(snapshot.Delegations[managed])
	rt := &AppContext{Config: defaultAppConfig(), StatePath: filepath.Join(t.TempDir(), "photon.db"), Clock: func() time.Time { return now }}
	rt.Config.PublishEndpoints = false
	boltStore, err := corestate.OpenBoltStore(rt.StatePath, 0o600, daemonBoltLockTimeout)
	if err != nil {
		t.Fatalf("OpenBoltStore: %v", err)
	}
	if err := initializeStateDB(boltStore, &corestate.CommitCandidate{
		Verified: state,
		Gossip:   &corestate.GossipCheckpoint{},
	}, 0, &photonlinux.LinuxState{}); err != nil {
		_ = boltStore.Close()
		t.Fatalf("initializeStateDB: %v", err)
	}
	owner, found, err := restoreState(boltStore, nil)
	if err != nil || !found {
		_ = boltStore.Close()
		t.Fatalf("restoreState = found %v err %v", found, err)
	}
	rt.Config = config
	service := newDaemon(rt, owner, defaultDaemonInterval)
	if changed, err := service.prepareStartupState(); err != nil {
		t.Fatalf("prepareStartupState: %v", err)
	} else if !changed {
		t.Fatal("prepareStartupState did not refresh cached managed authority")
	}

	committed := service.State.Common.ReadView()
	if got := committed.State.Network.Zones[managed].Authority.Epoch; got != 2 {
		t.Fatalf("managed authority epoch = %d, want 2", got)
	}
	if !authorityHasPermission(committed.State.Network.Zones[managed].Authority, zone.PermAllocateIP) {
		t.Fatal("managed authority missing allocate-ip after startup refresh")
	}
	if err := photoncrypto.VerifyChain(committed.State.Network, managed, now); err != nil {
		t.Fatalf("VerifyChain(managed): %v", err)
	}
	if err := service.State.Close(); err != nil {
		t.Fatalf("Close State: %v", err)
	}
	reopened, _, err := loadOfflineOwnerViews(rt)
	if err != nil {
		t.Fatalf("loadOfflineOwnerViews(reopened): %v", err)
	}
	if got := reopened.State.Network.Zones[managed].Authority.Epoch; got != 2 {
		t.Fatalf("reopened managed authority epoch = %d, want 2", got)
	}
	if !authorityHasPermission(reopened.State.Network.Zones[managed].Authority, zone.PermAllocateIP) {
		t.Fatal("reopened managed authority missing allocate-ip")
	}
}

func buildManagedAuthorityRefreshState(t *testing.T) (*corestate.VerifiedState, *appConfig, ed25519.PrivateKey) {
	t.Helper()
	rootPub, rootPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(root): %v", err)
	}
	managedPub, managedPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(managed): %v", err)
	}
	rootAuthority := &zone.ZoneAuthority{
		Zone:      zone.RootZone,
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: rootPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermDelegate, zone.PermWrite},
			}},
		}},
	}
	managedAuthority := &zone.ZoneAuthority{
		Zone:      "catofes.",
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: managedPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermDelegate, zone.PermWrite},
			}},
		}},
	}
	delegation := &zone.Delegation{ZoneName: "catofes.", Scope: zone.DelegationScopeDirectChild, Authority: *managedAuthority}
	if err := photoncrypto.SignDelegation(delegation, zone.RootZone, rootPriv); err != nil {
		t.Fatalf("SignDelegation(managed): %v", err)
	}
	network := zone.NewNetworkState()
	network.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, rootAuthority)
	network.Zones[zone.RootZone].Delegations["catofes."] = delegation
	network.Zones["catofes."] = zone.NewZoneState("catofes.", managedAuthority)
	network.Zones["catofes."].ParentProof = []*zone.Delegation{cloneDelegationForJoinBundle(delegation)}
	configureValidation(network)
	state := &corestate.VerifiedState{ManagedZone: "catofes.", IdentityPrivateKey: managedPriv, Network: network}
	config := defaultAppConfig()
	config.PeerID, config.ListenAddr = "catofes.", "127.0.0.1:0"
	return state, config, rootPriv
}

func managedAuthorityGrantSnapshot(t *testing.T, network *zone.NetworkState, managed zone.ZonePath, parentPriv ed25519.PrivateKey, permissions ...zone.Permission) *corestate.ZoneSnapshot {
	t.Helper()
	remote := zone.CloneNetworkState(network)
	authority := cloneAuthorityForJoinBundle(remote.Zones[managed].Authority)
	grantPermissionsToAuthority(authority, permissions)
	authority.Epoch++
	delegation := &zone.Delegation{ZoneName: managed, Scope: zone.DelegationScopeDirectChild, Authority: *authority}
	if err := photoncrypto.SignDelegation(delegation, managed.Parent(), parentPriv); err != nil {
		t.Fatalf("SignDelegation(grant): %v", err)
	}
	remote.Zones[managed.Parent()].Delegations[managed] = delegation
	remote.Zones[managed].Authority = authority
	snapshot, err := corestate.Snapshot(remote, managed.Parent())
	if err != nil {
		t.Fatalf("Snapshot(parent): %v", err)
	}
	return snapshot
}
