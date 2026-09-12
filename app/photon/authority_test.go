package main

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/urfave/cli/v3"
)

func TestRootInitHasAllAuthorityPermissions(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "root.yaml")
	writeConfig(t, configPath, filepath.Join(dir, "root"))
	t.Setenv("PHOTON_CONFIG", configPath)

	if err := runRootInit(); err != nil {
		t.Fatalf("runRootInit: %v", err)
	}
	state, err := loadConfiguredVerifiedState()
	if err != nil {
		t.Fatalf("loadState: %v", err)
	}
	root := state.Network.Zones[zone.RootZone]
	for _, permission := range allAuthorityPermissions() {
		if !authorityHasPermission(root.Authority, permission) {
			t.Fatalf("root authority missing permission %s", permission)
		}
	}
}

func TestDelegateGrantReissuesChildDelegation(t *testing.T) {
	dir := t.TempDir()
	adminConfig := filepath.Join(dir, "admin.yaml")
	catofesConfig := filepath.Join(dir, "catofes.yaml")
	catofesKeyPath := filepath.Join(dir, "catofes.key.json")
	catofesRequestPath := filepath.Join(dir, "catofes.request.b64")
	catofesBundlePath := filepath.Join(dir, "catofes.bundle.b64")
	grantBundlePath := filepath.Join(dir, "catofes.grant.b64")

	writeConfig(t, adminConfig, filepath.Join(dir, "admin"))
	t.Setenv("PHOTON_CONFIG", adminConfig)
	if err := runRootInit(); err != nil {
		t.Fatalf("runRootInit(admin): %v", err)
	}

	writeConfig(t, catofesConfig, filepath.Join(dir, "catofes"))
	t.Setenv("PHOTON_CONFIG", catofesConfig)
	if err := keygen(catofesKeyPath); err != nil {
		t.Fatalf("keygen(catofes): %v", err)
	}
	if err := createJoinRequest("catofes.", catofesKeyPath, catofesRequestPath); err != nil {
		t.Fatalf("createJoinRequest(catofes): %v", err)
	}
	t.Setenv("PHOTON_CONFIG", adminConfig)
	if err := issueDelegation(catofesRequestPath, catofesBundlePath, nil, true); err != nil {
		t.Fatalf("issueDelegation(catofes): %v", err)
	}
	t.Setenv("PHOTON_CONFIG", catofesConfig)
	if err := acceptJoinBundle(catofesBundlePath, catofesKeyPath, true); err != nil {
		t.Fatalf("acceptJoinBundle(initial): %v", err)
	}
	if err := putRecord("catofes.", "local-note", []byte("keep me"), "policy.string", true); err != nil {
		t.Fatalf("putRecord(catofes local): %v", err)
	}

	t.Setenv("PHOTON_CONFIG", adminConfig)
	state, err := loadConfiguredVerifiedState()
	if err != nil {
		t.Fatalf("loadState admin before grant: %v", err)
	}
	before := state.Network.Zones["catofes."].Authority.Epoch
	if authorityHasPermission(state.Network.Zones["catofes."].Authority, zone.PermAllocateIP) {
		t.Fatalf("catofes authority unexpectedly has allocate-ip before grant")
	}

	if err := grantDelegationPermissions("catofes.", []zone.Permission{zone.PermAllocateIP}, grantBundlePath, true); err != nil {
		t.Fatalf("grantDelegationPermissions(catofes): %v", err)
	}
	state, err = loadConfiguredVerifiedState()
	if err != nil {
		t.Fatalf("loadState admin after grant: %v", err)
	}
	catofes := state.Network.Zones["catofes."]
	if catofes.Authority.Epoch != before+1 {
		t.Fatalf("catofes epoch = %d, want %d", catofes.Authority.Epoch, before+1)
	}
	if !authorityHasPermission(catofes.Authority, zone.PermAllocateIP) {
		t.Fatalf("catofes authority missing allocate-ip after grant")
	}
	delegation := state.Network.Zones[zone.RootZone].Delegations["catofes."]
	if delegation == nil || !authorityHasPermission(&delegation.Authority, zone.PermAllocateIP) {
		t.Fatalf("root delegation missing updated catofes authority")
	}

	t.Setenv("PHOTON_CONFIG", catofesConfig)
	if err := acceptJoinBundle(grantBundlePath, "", true); err != nil {
		t.Fatalf("acceptJoinBundle(grant): %v", err)
	}
	childState, err := loadConfiguredVerifiedState()
	if err != nil {
		t.Fatalf("loadState catofes after grant accept: %v", err)
	}
	if !authorityHasPermission(childState.Network.Zones["catofes."].Authority, zone.PermAllocateIP) {
		t.Fatalf("catofes local authority missing allocate-ip after accepting grant bundle")
	}
	if childState.Network.Zones["catofes."].Records["local-note"] == nil {
		t.Fatalf("catofes local record was lost while accepting grant bundle")
	}
}

func TestDelegationCommandsOwnPermissionManagement(t *testing.T) {
	root := rootCommand()
	if authorityTestCommandByName(root.Commands, "authority") != nil {
		t.Fatal("root command still exposes authority")
	}
	gossip := authorityTestCommandByName(root.Commands, "gossip")
	if gossip == nil {
		t.Fatal("root command does not expose gossip")
	}
	delegate := authorityTestCommandByName(gossip.Commands, "delegate")
	if delegate == nil {
		t.Fatal("gossip command does not expose delegate")
	}
	want := []string{"issue", "grant", "revoke"}
	if len(delegate.Commands) != len(want) {
		t.Fatalf("delegate subcommands = %d, want %d", len(delegate.Commands), len(want))
	}
	for i, name := range want {
		if delegate.Commands[i].Name != name {
			t.Errorf("delegate subcommand %d = %q, want %q", i, delegate.Commands[i].Name, name)
		}
	}
	issue := authorityTestCommandByName(delegate.Commands, "issue")
	if issue == nil || len(issue.Flags) == 0 {
		t.Fatal("delegate issue permissions flag is missing")
	}
	if names := issue.Flags[0].Names(); len(names) != 1 || names[0] != "permissions" {
		t.Fatalf("delegate issue first flag names = %#v, want permissions", names)
	}
}

func authorityTestCommandByName(commands []*cli.Command, name string) *cli.Command {
	for _, command := range commands {
		if command.Name == name {
			return command
		}
	}
	return nil
}

func authorityHasPermission(authority *zone.ZoneAuthority, permission zone.Permission) bool {
	if authority == nil {
		return false
	}
	for _, key := range authority.Keys {
		for _, capability := range key.Capabilities {
			if slices.Contains(capability.Permissions, permission) {
				return true
			}
		}
	}
	return false
}
