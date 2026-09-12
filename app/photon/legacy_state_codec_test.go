package main

import (
	"path/filepath"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func TestLegacyStateFixtureCommitsMetaAndNetworkAtomically(t *testing.T) {
	verified, _, _, _ := buildTestDaemonOwners(t)
	initial := &stateFile{
		ManagedZone:    verified.ManagedZone,
		RootPrivateKey: verified.RootPrivateKey,
		ZonePrivateKey: verified.IdentityPrivateKey,
		Network:        verified.Network,
	}
	path := filepath.Join(t.TempDir(), "photon.db")
	if err := saveStateAt(path, initial); err != nil {
		t.Fatalf("save initial state: %v", err)
	}
	before := stateDBTxID(t, path)

	initial.IdentityKeyPath = "/new/identity.key"
	initial.Network.Zones["node-b.catofes."].Authority.Epoch++
	if err := saveStateAt(path, initial); err != nil {
		t.Fatalf("save updated state: %v", err)
	}
	if got := stateDBTxID(t, path); got != before+1 {
		t.Fatalf("full state save tx id = %d, want one commit after %d", got, before)
	}

	loaded, err := loadLegacyStateAt(path)
	if err != nil {
		t.Fatalf("load updated state: %v", err)
	}
	if loaded.IdentityKeyPath != initial.IdentityKeyPath {
		t.Fatalf("identity path = %q, want %q", loaded.IdentityKeyPath, initial.IdentityKeyPath)
	}
	if got, want := loaded.Network.Zones["node-b.catofes."].Authority.Epoch, initial.Network.Zones["node-b.catofes."].Authority.Epoch; got != want {
		t.Fatalf("Network epoch = %d, want %d", got, want)
	}
}

func stateDBTxID(t *testing.T, path string) int {
	t.Helper()
	db, err := bolt.Open(path, 0o600, &bolt.Options{ReadOnly: true})
	if err != nil {
		t.Fatalf("open state database: %v", err)
	}
	defer db.Close()
	var id int
	if err := db.View(func(tx *bolt.Tx) error {
		id = tx.ID()
		return nil
	}); err != nil {
		t.Fatalf("read state transaction id: %v", err)
	}
	return id
}
