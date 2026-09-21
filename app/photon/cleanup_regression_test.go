package main

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	bolt "go.etcd.io/bbolt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
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
	db, err := openDebugDB(path, nil)
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

func TestDelegationIssuePlanPreservesSource(t *testing.T) {
	network := zone.NewNetworkState()
	pub := make(ed25519.PublicKey, ed25519.PublicKeySize)
	network.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, &zone.ZoneAuthority{Zone: zone.RootZone, Epoch: 3, Keys: []zone.AuthorizedKey{{Key: pub}}})
	child := zone.ZonePath("child.")
	network.Zones[zone.RootZone].Revocations[child] = &zone.DelegationRevocation{RevokedAuthorityEpoch: 7}
	intent, err := planDelegationIssue(network, &gossip.JoinRequest{Version: 1, Zone: child, PublicKey: pub}, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	issue := intent.(corestate.PutDelegationIntent)
	if issue.Authority.Epoch != 8 {
		t.Fatalf("epoch = %d", issue.Authority.Epoch)
	}
	if network.Zones[child] != nil || network.Zones[zone.RootZone].Authority.Epoch != 3 || len(network.Zones[zone.RootZone].Authority.Keys[0].Capabilities) != 0 {
		t.Fatal("issue mutated source")
	}
}

func TestDebugDBCurrentLayout(t *testing.T) {
	verified, checkpoint, linux, _ := buildTestRoutingOwners(t)
	path := filepath.Join(t.TempDir(), "state.db")
	seedPartitionedStateDB(t, path, verified, checkpoint, linux)
	db, err := openDebugDB(path, nil)
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

func TestDebugDBReportsConfigErrorsAndStillReadsWithoutWriting(t *testing.T) {
	rt := &testApp{Config: testConfigWithStatePath(defaultAppConfig(), filepath.Join(t.TempDir(), "state.db"))}
	root, err := initializeRootState(rt.Config)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(rt.Config.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	wrong := append(ed25519.PublicKey(nil), root...)
	wrong[0] ^= 0xff
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("PHOTON_CONFIG", configPath)
	t.Setenv("PHOTON_STATE", rt.Config.StatePath)
	for _, tc := range []struct{ name, input, diagnostic string }{
		{"wrong root", "trusted_root_public_key: " + formatPublicKey(wrong) + "\n", "does not match persisted state"},
		{"invalid config", "unknown_field: true\n", "cannot load configuration"},
		{"missing config", "", "cannot load configuration"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.input == "" {
				if err := os.Remove(configPath); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(configPath, []byte(tc.input), 0600); err != nil {
				t.Fatal(err)
			}
			for _, inspect := range []func() error{func() error { return debugDBDump("") }, debugDBStats} {
				stdout, err := os.CreateTemp(t.TempDir(), "stdout")
				if err != nil {
					t.Fatal(err)
				}
				stderr, err := os.CreateTemp(t.TempDir(), "stderr")
				if err != nil {
					t.Fatal(err)
				}
				oldOut, oldErr := os.Stdout, os.Stderr
				os.Stdout, os.Stderr = stdout, stderr
				func() { defer func() { os.Stdout, os.Stderr = oldOut, oldErr }(); err = inspect() }()
				stdout.Close()
				stderr.Close()
				if err != nil {
					t.Fatal(err)
				}
				diagnostic, err := os.ReadFile(stderr.Name())
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(string(diagnostic), "ERROR:") || !strings.Contains(string(diagnostic), tc.diagnostic) {
					t.Fatalf("diagnostic = %s", diagnostic)
				}
				output, err := os.ReadFile(stdout.Name())
				if err != nil {
					t.Fatal(err)
				}
				if len(output) == 0 {
					t.Fatal("debug output was suppressed")
				}
			}
		})
	}
	after, err := os.ReadFile(rt.Config.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("debug inspection modified database")
	}
}
