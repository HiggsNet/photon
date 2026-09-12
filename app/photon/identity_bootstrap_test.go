package main

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/photonlinux"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

func TestParseConfigYAMLIdentity(t *testing.T) {
	config := defaultAppConfig()
	input := `
gossip:
  init:
    managed_zone: node-b.catofes.
    key_path: keys/node-b.json
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	if config.ManagedZone != "node-b.catofes." || config.Identity.KeyPath != "keys/node-b.json" {
		t.Fatalf("identity config = zone:%s key:%q", config.ManagedZone, config.Identity.KeyPath)
	}
}

func TestOpenStateAutoJoinCreatesPendingBootstrapState(t *testing.T) {
	dir := t.TempDir()
	keyPath, pub := writeTestPrivateKey(t, dir, "node-b")
	rootPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(root): %v", err)
	}
	config := defaultAppConfig()
	config.StatePath = filepath.Join(dir, "photon.db")
	config.ManagedZone = "node-b.catofes."
	config.Identity.KeyPath = keyPath
	config.TrustedRootPublicKey = rootPub
	config.Bootstrap = []syncConfigPeer{{ID: "catofes.", Addr: "127.0.0.1:33434"}}
	rt := &AppContext{Config: config, StatePath: config.StatePath, Clock: func() time.Time { return time.Unix(1000, 0) }}

	opened, err := openState(rt)
	if err != nil {
		t.Fatalf("openState: %v", err)
	}
	state := opened.Common.ReadView().State
	if state.ManagedZone != "node-b.catofes." || !autoJoinPendingVerified(state) {
		t.Fatalf("state = zone:%s pending:%v", state.ManagedZone, autoJoinPendingVerified(state))
	}
	if !equalPublicKey(state.IdentityPrivateKey.Public().(ed25519.PublicKey), pub) {
		t.Fatalf("IdentityPrivateKey public mismatch")
	}
	root := state.Network.Zones[zone.RootZone]
	if root == nil || root.Authority == nil || !authorityHasKey(root.Authority, rootPub) {
		t.Fatalf("trusted root authority missing: %+v", root)
	}

	if err := opened.Close(); err != nil {
		t.Fatalf("Close State: %v", err)
	}

	reopened, err := openState(rt)
	if err != nil {
		t.Fatalf("openState(reopened): %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatalf("Close reopened State: %v", err)
	}
}

func TestOpenStateAutoJoinWithoutBootstrapReportsActionableError(t *testing.T) {
	dir := t.TempDir()
	keyPath, _ := writeTestPrivateKey(t, dir, "node-b")
	rootPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(root): %v", err)
	}
	config := defaultAppConfig()
	config.StatePath = filepath.Join(dir, "photon.db")
	config.ManagedZone = "node-b.catofes."
	config.Identity.KeyPath = keyPath
	config.TrustedRootPublicKey = rootPub
	rt := &AppContext{Config: config, StatePath: config.StatePath}

	_, err = openState(rt)
	if err == nil {
		t.Fatal("openState accepted auto-join config without gossip.bootstrap")
	}
	for _, want := range []string{"cannot initialize empty state for auto-join", "gossip.bootstrap", "at least one peer is required"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("openState error = %q, want substring %q", err, want)
		}
	}
}

func TestValidateAutoJoinBootstrapConfigReportsSpecificMissingFields(t *testing.T) {
	dir := t.TempDir()
	keyPath, _ := writeTestPrivateKey(t, dir, "identity")
	rootPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(root): %v", err)
	}
	valid := func() *appConfig {
		config := defaultAppConfig()
		config.ManagedZone = "node-b.catofes."
		config.Identity.KeyPath = keyPath
		config.TrustedRootPublicKey = rootPub
		config.Bootstrap = []syncConfigPeer{{ID: "catofes.", Addr: "127.0.0.1:33434"}}
		return config
	}
	tests := []struct {
		name   string
		mutate func(*appConfig)
		want   string
	}{
		{name: "managed zone", mutate: func(config *appConfig) { config.ManagedZone = "" }, want: "gossip.init.managed_zone"},
		{name: "identity key", mutate: func(config *appConfig) { config.Identity.KeyPath = "" }, want: "gossip.init.key_path"},
		{name: "trusted root", mutate: func(config *appConfig) { config.TrustedRootPublicKey = nil }, want: "trusted_root_public_key"},
		{name: "bootstrap", mutate: func(config *appConfig) { config.Bootstrap = nil }, want: "gossip.bootstrap"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := valid()
			tt.mutate(config)
			err := validateAutoJoinBootstrapConfig(config)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("validateAutoJoinBootstrapConfig error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestOpenStateRejectsConfiguredIdentityMismatch(t *testing.T) {
	dir := t.TempDir()
	verified, keyPath := buildIdentityVerifiedState(t, dir, "node-b.catofes.")
	config := defaultAppConfig()
	config.StatePath = filepath.Join(dir, "photon.db")
	config.ManagedZone = "node-b.catofes."
	config.Identity.KeyPath = keyPath
	rt := &AppContext{Config: config, StatePath: config.StatePath}
	seedPartitionedStateDB(t, rt.StatePath, verified, &corestate.GossipCheckpoint{}, &photonlinux.LinuxState{})

	otherKeyPath, _ := writeTestPrivateKey(t, dir, "other")
	config.Identity.KeyPath = otherKeyPath
	if _, err := openState(rt); err == nil || !strings.Contains(err.Error(), "public key does not match persisted identity private key") {
		t.Fatalf("openState mismatch error = %v", err)
	}
}

func TestOpenStateRejectsConfiguredManagedZoneMismatch(t *testing.T) {
	dir := t.TempDir()
	verified, keyPath := buildIdentityVerifiedState(t, dir, "node-b.catofes.")
	config := defaultAppConfig()
	config.StatePath = filepath.Join(dir, "photon.db")
	config.ManagedZone = "node-a.catofes."
	config.Identity.KeyPath = keyPath
	rt := &AppContext{Config: config, StatePath: config.StatePath}
	seedPartitionedStateDB(t, rt.StatePath, verified, &corestate.GossipCheckpoint{}, &photonlinux.LinuxState{})
	if _, err := openState(rt); err == nil || !strings.Contains(err.Error(), "does not match persisted managed zone") {
		t.Fatalf("openState managed_zone mismatch error = %v", err)
	}
}

func TestOpenStateAllowsConfiguredIdentityPathMove(t *testing.T) {
	dir := t.TempDir()
	verified, keyPath := buildIdentityVerifiedState(t, dir, "node-b.catofes.")
	config := defaultAppConfig()
	config.StatePath = filepath.Join(dir, "photon.db")
	config.ManagedZone = "node-b.catofes."
	config.Identity.KeyPath = keyPath
	rt := &AppContext{Config: config, StatePath: config.StatePath}
	seedPartitionedStateDB(t, rt.StatePath, verified, &corestate.GossipCheckpoint{}, &photonlinux.LinuxState{})

	opened, err := openState(rt)
	if err != nil {
		t.Fatalf("openState: %v", err)
	}
	if err := opened.Close(); err != nil {
		t.Fatalf("Close State: %v", err)
	}

	reopened, err := openState(rt)
	if err != nil {
		t.Fatalf("openState(reopened): %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatalf("Close reopened State: %v", err)
	}

	config.Identity.KeyPath = copyTestPrivateKey(t, keyPath, filepath.Join(dir, "moved.key.json"))
	moved, err := openState(rt)
	if err != nil {
		t.Fatalf("openState moved key: %v", err)
	}
	if err := moved.Close(); err != nil {
		t.Fatalf("Close moved-path State: %v", err)
	}
}

func TestDaemonReloadAllowsPathMoveAndRejectsIdentityChange(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	verified, keyPath := buildIdentityVerifiedState(t, dir, "node-b.catofes.")
	movedKeyPath := copyTestPrivateKey(t, keyPath, filepath.Join(dir, "copy.key.json"))
	otherKeyPath, _ := writeTestPrivateKey(t, dir, "other")
	dataDir := filepath.Join(dir, "data")
	statePath := filepath.Join(dataDir, "photon.db")
	t.Setenv("PHOTON_CONFIG", configPath)
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	writeIdentityConfig(t, configPath, dataDir, "node-b.catofes.", keyPath)

	appConfig := defaultAppConfig()
	appConfig.DataDir = dataDir
	appConfig.StatePath = statePath
	appConfig.ManagedZone = "node-b.catofes."
	appConfig.Identity.KeyPath = keyPath
	runtime := &photonlinux.LinuxState{}
	rt := &AppContext{Config: appConfig, StatePath: statePath}
	service := newTestDaemonFromOwners(rt, verified, nil, runtime, appConfig, time.Second)

	writeIdentityConfig(t, configPath, dataDir, "node-b.catofes.", movedKeyPath)
	result, syncNow, shutdown := service.handleEvent(daemonEvent{Type: daemonEventReloadConfig})
	if result.Error != nil {
		t.Fatalf("reload moved identity key: %v", result.Error)
	}
	if !syncNow || shutdown {
		t.Fatalf("moved-key reload syncNow/shutdown = %v/%v, want true/false", syncNow, shutdown)
	}

	writeIdentityConfig(t, configPath, dataDir, "node-b.catofes.", otherKeyPath)
	result, syncNow, shutdown = service.handleEvent(daemonEvent{Type: daemonEventReloadConfig})
	if result.Error == nil || !strings.Contains(result.Error.Error(), "identity.key_path") {
		t.Fatalf("reload error = %v, want identity.key_path rejection", result.Error)
	}
	if syncNow || shutdown {
		t.Fatalf("syncNow/shutdown = %v/%v, want false/false", syncNow, shutdown)
	}

	writeIdentityConfig(t, configPath, dataDir, "node-b.catofes.", keyPath)
	result, syncNow, shutdown = service.handleEvent(daemonEvent{Type: daemonEventReloadConfig})
	if result.Error != nil {
		t.Fatalf("reload matching identity: %v", result.Error)
	}
	if !syncNow || shutdown {
		t.Fatalf("matching reload syncNow/shutdown = %v/%v, want true/false", syncNow, shutdown)
	}
}

func buildPendingAutoJoinOwners(t *testing.T, dir string, managed zone.ZonePath, matchingDelegation bool) (*corestate.VerifiedState, *photonlinux.LinuxState, string) {
	t.Helper()
	keyPath, pub := writeTestPrivateKey(t, dir, "identity")
	if !matchingDelegation {
		_, pub = writeTestPrivateKey(t, dir, "other")
	}
	rootPub, rootPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(root): %v", err)
	}
	parentPub, parentPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(parent): %v", err)
	}
	parent := managed.Parent()
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
	parentAuthority := &zone.ZoneAuthority{
		Zone:      parent,
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: parentPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermDelegate, zone.PermWrite},
			}},
		}},
	}
	childAuthority := &zone.ZoneAuthority{
		Zone:      managed,
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: pub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermWrite, zone.PermDelegate},
			}},
		}},
	}
	parentDelegation := &zone.Delegation{
		ZoneName:  parent,
		Scope:     zone.DelegationScopeDirectChild,
		Authority: *parentAuthority,
	}
	if err := photoncrypto.SignDelegation(parentDelegation, zone.RootZone, rootPriv); err != nil {
		t.Fatalf("SignDelegation(parent): %v", err)
	}
	childDelegation := &zone.Delegation{
		ZoneName:  managed,
		Scope:     zone.DelegationScopeDirectChild,
		Authority: *childAuthority,
	}
	if err := photoncrypto.SignDelegation(childDelegation, parent, parentPriv); err != nil {
		t.Fatalf("SignDelegation(child): %v", err)
	}
	ns := zone.NewNetworkState()
	ns.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, rootAuthority)
	ns.Zones[zone.RootZone].Delegations[parent] = parentDelegation
	ns.Zones[parent] = zone.NewZoneState(parent, parentAuthority)
	ns.Zones[parent].ParentProof = []*zone.Delegation{cloneDelegationForJoinBundle(parentDelegation)}
	ns.Zones[parent].Delegations[managed] = childDelegation
	configureValidation(ns)
	key, err := readPrivateKeyFile(keyPath)
	if err != nil {
		t.Fatalf("readPrivateKeyFile: %v", err)
	}
	return &corestate.VerifiedState{
		ManagedZone:        managed,
		IdentityPrivateKey: key.PrivateKey,
		Network:            ns,
	}, &photonlinux.LinuxState{}, keyPath
}

func buildIdentityVerifiedState(t *testing.T, dir string, managed zone.ZonePath) (*corestate.VerifiedState, string) {
	t.Helper()
	keyPath, pub := writeTestPrivateKey(t, dir, "identity")
	rootPub, rootPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(root): %v", err)
	}
	parent := managed.Parent()
	parentAuthority := &zone.ZoneAuthority{
		Zone:      parent,
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: rootPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermDelegate},
			}},
		}},
	}
	childAuthority := &zone.ZoneAuthority{
		Zone:      managed,
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: pub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermWrite},
			}},
		}},
	}
	delegation := &zone.Delegation{
		ZoneName:  managed,
		Scope:     zone.DelegationScopeDirectChild,
		Authority: *childAuthority,
	}
	if err := photoncrypto.SignDelegation(delegation, parent, rootPriv); err != nil {
		t.Fatalf("SignDelegation: %v", err)
	}
	ns := zone.NewNetworkState()
	ns.Zones[parent] = zone.NewZoneState(parent, parentAuthority)
	ns.Zones[managed] = zone.NewZoneState(managed, childAuthority)
	ns.Zones[parent].Delegations[managed] = delegation
	configureValidation(ns)
	key, err := readPrivateKeyFile(keyPath)
	if err != nil {
		t.Fatalf("readPrivateKeyFile: %v", err)
	}
	return &corestate.VerifiedState{
		ManagedZone:        managed,
		IdentityPrivateKey: key.PrivateKey,
		Network:            ns,
	}, keyPath
}

func writeTestPrivateKey(t *testing.T, dir, name string) (string, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(%s): %v", name, err)
	}
	path := filepath.Join(dir, name+".key.json")
	key := privateKeyFile{Type: "photon.ed25519.private.v1", PublicKey: pub, PrivateKey: priv}
	if err := writeJSONFile(path, 0o600, &key); err != nil {
		t.Fatalf("writeJSONFile(%s): %v", name, err)
	}
	return path, pub
}

func copyTestPrivateKey(t *testing.T, source, dest string) string {
	t.Helper()
	data, err := os.ReadFile(source)
	if err != nil {
		t.Fatalf("ReadFile(source): %v", err)
	}
	if err := os.WriteFile(dest, data, 0o600); err != nil {
		t.Fatalf("WriteFile(dest): %v", err)
	}
	return dest
}

func writeIdentityConfig(t *testing.T, path, dataDir string, managed zone.ZonePath, keyPath string) {
	t.Helper()
	data := strings.Join([]string{
		"data_dir: " + dataDir,
		"gossip:",
		"  init:",
		"    managed_zone: " + string(managed),
		"    key_path: " + keyPath,
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("WriteFile(config): %v", err)
	}
}
