package main

import (
	"crypto/ed25519"
	"errors"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	bolt "go.etcd.io/bbolt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestUnsupportedConfigurationRejected(t *testing.T) {
	for _, input := range []string{
		"observer:\n  ui_path: ''\n",
		"health:\n  metrics:\n    remote_write_url: ''\n",
		"health:\n  metrics:\n    remote_write_queue_capacity: 1024\n",
	} {
		if err := parseConfigYAML(input, defaultAppConfig()); err == nil || !strings.Contains(err.Error(), "not supported") {
			t.Fatalf("config %q: %v", input, err)
		}
	}
}

func TestDebugDBLockTimeout(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	owner, err := bolt.Open(path, 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	start := time.Now()
	db, err := openDebugDB(path)
	if db != nil {
		db.Close()
		t.Fatal("opened locked database")
	}
	if !errors.Is(err, bolt.ErrTimeout) || !strings.Contains(err.Error(), "stop daemon") {
		t.Fatalf("lock error: %v", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("lock wait exceeded bound")
	}
}

func TestDelegationPlansPreserveSource(t *testing.T) {
	network := zone.NewNetworkState()
	pub := make(ed25519.PublicKey, ed25519.PublicKeySize)
	network.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, &zone.ZoneAuthority{Zone: zone.RootZone, Epoch: 3, Keys: []zone.AuthorizedKey{{Key: pub}}})
	child := zone.ZonePath("child.")
	network.Zones[zone.RootZone].Revocations[child] = &zone.DelegationRevocation{RevokedAuthorityEpoch: 7}
	intent, err := planDelegationIssue(network, &joinRequest{Version: 1, Zone: child, PublicKey: pub}, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	issue := intent.(corestate.PutDelegationIntent)
	if issue.Authority.Epoch != 8 {
		t.Fatalf("epoch = %d", issue.Authority.Epoch)
	}
	network.Zones[child] = zone.NewZoneState(child, issue.Authority)
	grant, err := planDelegationGrant(network, child, []zone.Permission{zone.PermAllocateIP})
	if err != nil {
		t.Fatal(err)
	}
	if grant.(corestate.PutDelegationIntent).Authority.Epoch != 9 || network.Zones[zone.RootZone].Authority.Epoch != 3 || len(network.Zones[zone.RootZone].Authority.Keys[0].Capabilities) != 0 {
		t.Fatal("grant mutated source or used wrong epoch")
	}
}

func TestDebugDBCurrentLayout(t *testing.T) {
	verified, checkpoint, linux, _ := buildTestRoutingOwners(t)
	path := filepath.Join(t.TempDir(), "state.db")
	seedPartitionedStateDB(t, path, verified, checkpoint, linux)
	db, err := openDebugDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// Capture to a file: a full nested dump can exceed a pipe buffer.
	out, err := os.CreateTemp(t.TempDir(), "dump")
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	original := os.Stdout
	os.Stdout = out
	defer func() { os.Stdout = original }()
	if err := db.View(func(tx *bolt.Tx) error { return dumpDBTx(tx, verified.ManagedZone.String()) }); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "zone "+verified.ManagedZone.String()) || strings.Contains(string(data), "identity_private_key") {
		t.Fatalf("invalid filtered dump")
	}
	if err := out.Truncate(0); err != nil {
		t.Fatal(err)
	}
	if _, err := out.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	if err := db.View(func(tx *bolt.Tx) error { return dumpDBTx(tx, "") }); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(out.Name())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"photon:common-state", "verified", "gossip-checkpoint", "payload"} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("nested dump missing %s", want)
		}
	}
}
