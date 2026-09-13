package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	photonstate "github.com/HiggsNet/photon/internal/state"

	"github.com/HiggsNet/photon/internal/photonlinux"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
	bolt "go.etcd.io/bbolt"
)

func TestLegacyLinuxStateMigrationIsAtomicAndIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "photon.db")
	state, trustedRoot := legacyRuntimeMigrationFixture(t)
	seedLegacyLinuxState(t, path, state)

	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatalf("bolt.Open: %v", err)
	}
	defer db.Close()
	var report legacyStateMigrationReport
	if err := db.Update(func(tx *bolt.Tx) error {
		var migrated bool
		var err error
		report, migrated, err = migrateLegacyLinuxStateTx(tx, trustedRoot)
		if err == nil && !migrated {
			t.Fatal("legacy state was not migrated")
		}
		return err
	}); err != nil {
		t.Fatalf("migrateLegacyLinuxStateTx: %v", err)
	}
	if report.Gossip.PeersMigrated != 1 || report.Gossip.CleanupsMigrated != 1 || report.Gossip.CleanupsDropped != 0 {
		t.Fatalf("migration report = %+v", report)
	}

	if err := db.View(func(tx *bolt.Tx) error {
		candidate, revision, _, found, err := corestate.LoadBoltState(tx)
		if err != nil {
			return err
		}
		if !found || revision != 0 || candidate.Verified.ManagedZone != zone.RootZone {
			t.Fatalf("common state found/revision/zone = %v/%d/%s", found, revision, candidate.Verified.ManagedZone)
		}
		if !reflect.DeepEqual(candidate.Verified.TrustedRootPublicKey, trustedRoot) || candidate.Gossip.Peers["peer.catofes."].BackoffUntilUnix != 20 {
			t.Fatalf("common state projection = %+v", candidate)
		}
		if got := candidate.Gossip.Peers["cleaned.catofes."].ObservedLastSeenUnix; got != 10 {
			t.Fatalf("migrated cleanup last active = %d, want 10", got)
		}
		linuxState, found, err := photonlinux.LoadLinuxStateTx(tx)
		if err != nil {
			return err
		}
		if !found {
			t.Fatalf("LinuxState = %+v", linuxState)
		}
		payload, err := json.Marshal(linuxState)
		if err != nil {
			return err
		}
		if strings.Contains(string(payload), "identity_key_path") || strings.Contains(string(payload), "routing_reconcile") || strings.Contains(string(payload), "firewall_reconcile") || strings.Contains(string(payload), "bird_instances") || strings.Contains(string(payload), "peer_cleanups") {
			t.Fatalf("legacy derived state survived Linux state migration: %s", payload)
		}
		if meta := tx.Bucket(bucketLegacyMeta); meta != nil && meta.Get([]byte(cliMetaKey)) != nil {
			t.Fatal("legacy cli_state survived migration")
		}
		legacyNetwork, err := zone.LoadNetworkTx(tx)
		if err != nil {
			return err
		}
		if len(legacyNetwork.Zones) != 0 {
			t.Fatalf("legacy zone buckets survived migration: %+v", legacyNetwork.Zones)
		}
		return nil
	}); err != nil {
		t.Fatalf("inspect migrated state: %v", err)
	}

	if err := db.Update(func(tx *bolt.Tx) error {
		_, migrated, err := migrateLegacyLinuxStateTx(tx, trustedRoot)
		if err == nil && migrated {
			t.Fatal("second migration reported a change")
		}
		return err
	}); err != nil {
		t.Fatalf("idempotent migration: %v", err)
	}
}

func TestPartitionedLinuxStateMigratesOfflineCleanupIntoCheckpoint(t *testing.T) {
	owners, _, _, _ := buildPeerStateTestOwners(t)
	verified := owners.verified
	now := time.Unix(500_000, 0)
	peerID := zone.ZonePath("node-b.catofes.")
	addTestIPsecRecords(t, verified.Network.Zones[peerID], peerID, now, ipsec.RoleIn)

	path := filepath.Join(t.TempDir(), "photon.db")
	seedPartitionedStateDB(t, path, verified, &corestate.GossipCheckpoint{}, &photonlinux.LinuxState{})
	legacyPayload, err := json.Marshal(struct {
		PeerCleanups map[string]photonlinux.LegacyPeerCleanupState `json:"peer_cleanups"`
	}{PeerCleanups: map[string]photonlinux.LegacyPeerCleanupState{
		peerID.String(): {
			LastActiveUnix: now.Add(-4 * time.Second).Unix(),
			CleanupUnix:    now.Unix(),
			Reason:         peerCleanupReasonOffline,
		},
	}})
	if err != nil {
		t.Fatalf("marshal old Linux payload: %v", err)
	}
	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatalf("bolt.Open old partitioned state: %v", err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(photonlinux.LinuxStateBucketName)).Put([]byte("payload"), legacyPayload)
	}); err != nil {
		_ = db.Close()
		t.Fatalf("seed old cleanup marker: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close old partitioned state: %v", err)
	}

	store, err := corestate.OpenBoltStore(path, 0o600, daemonBoltLockTimeout)
	if err != nil {
		t.Fatalf("OpenBoltStore: %v", err)
	}
	state, found, err := restoreState(store, nil)
	if err != nil || !found {
		_ = store.Close()
		t.Fatalf("restoreState = found %v err %v", found, err)
	}

	cfg := inspect.PeerLifecycleConfig{
		StaleAfter: time.Second, OfflineAfter: 2 * time.Second,
		CleanupAfter: 3 * time.Second, KeepSAWhileStale: true,
	}
	view := state.Common.ReadView()
	peer := view.Gossip.Peers[peerID.String()]
	if peer.LastSyncUnix != 0 || peer.ObservedLastSeenUnix != now.Add(-4*time.Second).Unix() {
		t.Fatalf("migrated peer checkpoint = %+v", peer)
	}
	excluded := peerLifecycleExcludedPeers(view.Gossip, now, cfg)
	if excluded[peerID] != peerCleanupReasonOffline {
		t.Fatalf("migrated exclusion = %+v", excluded)
	}

	groups := []ipsec.LinkGroupSpec{{
		ID: "main", Provider: ipsec.ProviderStrongSwan,
		NetNS:              ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "photon-lifecycle", Create: true},
		DefaultPathMode:    ipsec.PathModeFamilyRedundant,
		AddressSourceOrder: []string{ipsec.SourceManualAddress},
		ConnectRules:       []string{"strongswan://*.catofes.?role=in"},
	}}
	plan, err := ipsec.PlanTransportLinks(context.Background(), view.State.Network, view.State.ManagedZone, groups, ipsec.LinkPlannerOptions{
		Now: now, ExcludedPeers: excluded,
	})
	if err != nil || len(plan.Desired) != 0 {
		t.Fatalf("suppressed plan = desired %d err %v", len(plan.Desired), err)
	}

	if _, err := state.Common.UpdatePeerCheckpoint(context.Background(), peerID.String(), corestate.PeerCheckpointPatch{
		LastSyncUnix: corestate.PatchField[int64]{Set: true, Value: now.Unix()},
	}); err != nil {
		t.Fatalf("record successful sync: %v", err)
	}
	view = state.Common.ReadView()
	if excluded := peerLifecycleExcludedPeers(view.Gossip, now, cfg); excluded[peerID] != "" {
		t.Fatalf("successful sync retained exclusion = %+v", excluded)
	}
	plan, err = ipsec.PlanTransportLinks(context.Background(), view.State.Network, view.State.ManagedZone, groups, ipsec.LinkPlannerOptions{Now: now})
	if err != nil || len(plan.Desired) != 1 {
		t.Fatalf("recovered plan = desired %d err %v", len(plan.Desired), err)
	}
	if err := state.Close(); err != nil {
		t.Fatalf("close migrated state: %v", err)
	}

	db, err = bolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatalf("reopen migrated state: %v", err)
	}
	defer db.Close()
	if err := db.Update(func(tx *bolt.Tx) error {
		report, migrated, err := migrateLegacyLinuxStateTx(tx, nil)
		if err == nil && (migrated || report.Gossip.CleanupsMigrated != 0) {
			t.Fatalf("second migration = migrated %v report %+v", migrated, report)
		}
		return err
	}); err != nil {
		t.Fatalf("idempotent partitioned migration: %v", err)
	}
	if err := db.View(func(tx *bolt.Tx) error {
		payload := tx.Bucket([]byte(photonlinux.LinuxStateBucketName)).Get([]byte("payload"))
		if strings.Contains(string(payload), "peer_cleanups") {
			t.Fatalf("legacy cleanup field survived one-time migration: %s", payload)
		}
		return nil
	}); err != nil {
		t.Fatalf("inspect migrated Linux payload: %v", err)
	}
}

func TestLegacyLinuxStateMigrationFailureRollsBack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "photon.db")
	state, trustedRoot := legacyRuntimeMigrationFixture(t)
	seedLegacyLinuxState(t, path, state)
	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatalf("bolt.Open: %v", err)
	}
	defer db.Close()
	if err := db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketLegacyMeta).Put([]byte(cliMetaKey), []byte("{"))
	}); err != nil {
		t.Fatalf("corrupt legacy fixture: %v", err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		_, _, err := migrateLegacyLinuxStateTx(tx, trustedRoot)
		return err
	}); err == nil {
		t.Fatal("malformed legacy metadata unexpectedly migrated")
	}
	if err := db.View(func(tx *bolt.Tx) error {
		_, _, _, found, err := corestate.LoadBoltState(tx)
		if err != nil {
			return err
		}
		if found || tx.Bucket([]byte(photonlinux.LinuxStateBucketName)) != nil {
			t.Fatal("failed migration retained new buckets")
		}
		legacyNetwork, err := zone.LoadNetworkTx(tx)
		if err != nil {
			return err
		}
		if len(legacyNetwork.Zones) == 0 || tx.Bucket(bucketLegacyMeta).Get([]byte(cliMetaKey)) == nil {
			t.Fatal("failed migration removed legacy state")
		}
		return nil
	}); err != nil {
		t.Fatalf("inspect rollback: %v", err)
	}
}

func TestLegacyLinuxStateMigrationRejectsCoexistingRepresentations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "photon.db")
	state, trustedRoot := legacyRuntimeMigrationFixture(t)
	seedLegacyLinuxState(t, path, state)
	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatalf("bolt.Open: %v", err)
	}
	defer db.Close()
	if err := db.Update(func(tx *bolt.Tx) error {
		_, _, err := migrateLegacyLinuxStateTx(tx, trustedRoot)
		return err
	}); err != nil {
		t.Fatalf("initial migration: %v", err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		meta, err := tx.CreateBucketIfNotExists(bucketLegacyMeta)
		if err != nil {
			return err
		}
		data, err := json.Marshal(stateMetaFromState(state))
		if err != nil {
			return err
		}
		return meta.Put([]byte(cliMetaKey), data)
	}); err != nil {
		t.Fatalf("create conflicting fixture: %v", err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		_, _, err := migrateLegacyLinuxStateTx(tx, trustedRoot)
		return err
	}); !errors.Is(err, errLegacyStateConflict) {
		t.Fatalf("coexisting representations error = %v, want errLegacyStateConflict", err)
	}
}

func legacyRuntimeMigrationFixture(t *testing.T) (*stateFile, ed25519.PublicKey) {
	t.Helper()
	rootPublic, rootPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(root): %v", err)
	}
	network := zone.NewNetworkState()
	network.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, &zone.ZoneAuthority{
		Zone: zone.RootZone, Epoch: 1, Threshold: 1, Keys: []zone.AuthorizedKey{{Key: rootPublic}},
	})
	return &stateFile{
		ManagedZone:     zone.RootZone,
		IdentityKeyPath: "/etc/photon/identity.key",
		RootPrivateKey:  rootPrivate,
		Network:         network,
		SyncPeers: map[string]photonstate.PeerRuntimeState{
			"peer.catofes.": {BackoffUntilUnix: 20, LastError: "diagnostic-only"},
		},
		PeerCleanups: map[string]photonlinux.LegacyPeerCleanupState{
			"cleaned.catofes.": {LastActiveUnix: 10, CleanupUnix: 30, Reason: peerCleanupReasonOffline},
		},
	}, rootPublic
}

func seedLegacyLinuxState(t *testing.T, path string, state *stateFile) {
	t.Helper()
	store, err := zone.OpenBoltStore(path, 0o600)
	if err != nil {
		t.Fatalf("OpenBoltStore: %v", err)
	}
	if err := store.SaveNetworkAndMetaJSON(cliMetaKey, stateMetaFromState(state), state.Network); err != nil {
		_ = store.Close()
		t.Fatalf("seed legacy state: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close legacy store: %v", err)
	}
}
