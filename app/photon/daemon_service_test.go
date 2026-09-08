package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	photonlinux "github.com/HiggsNet/photon/internal/photonlinux"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestNewDaemonDefaultsInterval(t *testing.T) {
	service := newTestDaemonFromOwners(
		&AppContext{}, &corestate.VerifiedState{}, nil, &linuxRuntimeState{}, &gossipStartupConfig{}, 0,
	)
	if service.Interval != defaultDaemonInterval {
		t.Fatalf("default interval = %s, want %s", service.Interval, defaultDaemonInterval)
	}
	if service.App == nil || service.currentGossipConfig() == nil {
		t.Fatal("daemon app or gossip config is nil")
	}
}

func TestConfiguredStrongSwanLinuxDriverWithoutLinkGroupsUsesDryRunObservation(t *testing.T) {
	driver, err := newConfiguredLinuxDriver(ipsecConfig{Driver: ipsecDriverStrongSwan}, nil, nil)
	if err != nil {
		t.Fatalf("newConfiguredLinuxDriver: %v", err)
	}
	sas, err := driver.ListIPsecSAs(context.Background())
	if err != nil || len(sas) != 0 {
		t.Fatalf("ListIPsecSAs = (%v, %v), want empty dry-run observation", sas, err)
	}
}

func TestDaemonReplacesAndClosesSingleLinuxDriver(t *testing.T) {
	service := newTestDaemonFromOwners(
		&AppContext{}, &corestate.VerifiedState{}, nil, &linuxRuntimeState{}, &gossipStartupConfig{}, time.Second,
	)
	firstClosed := 0
	firstDriver := &ipsec.DryRunDriver{}
	first := newTestLinuxDriverWithOptions(photonlinux.LinuxDriverOptions{
		IPsecDriver: firstDriver,
		XFRMDriver:  firstDriver,
		Close: func() error {
			firstClosed++
			return nil
		},
	})
	if err := service.installLinuxDriver(first); err != nil {
		t.Fatalf("install first Linux driver: %v", err)
	}
	if service.linuxDriver != first {
		t.Fatal("first Linux driver was not installed")
	}

	secondClosed := 0
	secondDriver := &ipsec.DryRunDriver{}
	second := newTestLinuxDriverWithOptions(photonlinux.LinuxDriverOptions{
		IPsecDriver: secondDriver,
		XFRMDriver:  secondDriver,
		Close: func() error {
			secondClosed++
			return nil
		},
	})
	if err := service.installLinuxDriver(second); err != nil {
		t.Fatalf("replace Linux driver: %v", err)
	}
	if firstClosed != 1 {
		t.Fatalf("first driver close calls = %d, want 1", firstClosed)
	}
	if service.linuxDriver != second {
		t.Fatal("replacement Linux driver was not installed")
	}
	if err := service.closeLinuxDriver(); err != nil {
		t.Fatalf("close Linux driver: %v", err)
	}
	if secondClosed != 1 {
		t.Fatalf("second driver close calls = %d, want 1", secondClosed)
	}
	if service.linuxDriver != nil {
		t.Fatal("Linux driver remains installed after close")
	}
}

func TestDaemonStateChangedHook(t *testing.T) {
	service := newTestDaemonFromOwners(
		&AppContext{},
		&corestate.VerifiedState{ManagedZone: "node-a.catofes."},
		nil,
		&linuxRuntimeState{},
		&gossipStartupConfig{},
		time.Second,
	)
	var called bool
	service.Hooks.OnStateChanged = func() {
		called = true
	}
	service.notifyStateChanged()
	if !called {
		t.Fatal("state changed hook was not called")
	}
}

func TestDaemonStateChangedWithoutLinuxDriverSkipsPlatformReconcile(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	service := newTestDaemonFromOwners(
		&AppContext{Config: defaultAppConfig()}, verified, checkpoint, runtime, config, time.Second,
	)
	if err := service.closeLinuxDriver(); err != nil {
		t.Fatalf("close Linux driver: %v", err)
	}
	var flushed []string
	service.Hooks.OnReconcileFlush = func(layer string) {
		flushed = append(flushed, layer)
	}

	service.notifyStateChanged()

	if len(flushed) != 0 {
		t.Fatalf("platform reconcile flushed without Linux driver: %v", flushed)
	}
	if service.ipsecDirty || service.routingDirty || service.firewallDirty {
		t.Fatalf("platform dirty flags set without Linux driver: ipsec:%v routing:%v firewall:%v", service.ipsecDirty, service.routingDirty, service.firewallDirty)
	}
}

func TestDaemonNotifyStateChangedDefersReconcileWhileDrainingEvents(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	service := newTestDaemonFromOwners(
		&AppContext{Config: defaultAppConfig()}, verified, checkpoint, runtime, config, time.Second,
	)
	service.drainingEvents = true
	var flushed []string
	service.Hooks.OnReconcileFlush = func(layer string) {
		flushed = append(flushed, layer)
	}

	service.notifyStateChanged()

	if len(flushed) != 0 {
		t.Fatalf("reconcile flushed while draining events: %v", flushed)
	}
	if !service.ipsecDirty || !service.routingDirty || !service.firewallDirty {
		t.Fatalf("dirty flags = ipsec:%v routing:%v firewall:%v, want all true", service.ipsecDirty, service.routingDirty, service.firewallDirty)
	}
}

func TestEmptyFirewallAndRoutingFlushDoNotRepublishLegacyState(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	service := newTestDaemonFromOwners(
		&AppContext{Config: defaultAppConfig()}, verified, checkpoint, runtime, config, time.Second,
	)
	beforeRevision := service.StateStore.Meta().Revision

	service.firewallDirty = true
	flushed, err := service.flushFirewallReconcileResult(context.Background())
	if err != nil {
		t.Fatalf("flushFirewallReconcileResult: %v", err)
	}
	if !flushed {
		t.Fatal("firewall reconcile was not flushed")
	}

	service.routingDirty = true
	flushed, err = service.flushRoutingReconcileResult(context.Background())
	if err != nil {
		t.Fatalf("flushRoutingReconcileResult: %v", err)
	}
	if !flushed {
		t.Fatal("routing reconcile was not flushed")
	}

	if revision := service.StateStore.Meta().Revision; revision != beforeRevision {
		t.Fatalf("empty reconciles changed revision from %d to %d", beforeRevision, revision)
	}
}

func TestDaemonReloadConfigReconcilesIPsecLinkGroups(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	now := time.Unix(4200, 0)
	addTestIPsecRecords(t, verified.Network.Zones["node-b.catofes."], "node-b.catofes.", now, ipsec.RoleIn)
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	statePath := filepath.Join(dataDir, "photon.db")
	configPath := filepath.Join(dir, "config.yaml")
	t.Setenv("PHOTON_CONFIG", configPath)
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatalf("MkdirAll(dataDir): %v", err)
	}
	if err := os.WriteFile(configPath, []byte("data_dir: "+dataDir+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(initial config): %v", err)
	}
	appConfig := defaultAppConfig()
	appConfig.DataDir = dataDir
	appConfig.StatePath = statePath
	rt := &AppContext{
		Config:    appConfig,
		StatePath: statePath,
		Clock:     func() time.Time { return now },
	}
	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, config, time.Second)

	reply := make(chan daemonEventResult, 1)
	service.Events <- daemonEvent{Type: daemonEventReloadConfig, Reply: reply}
	syncNow, shutdown, _, _, _ := service.processEvents(context.Background())
	result := <-reply
	if result.Error != nil {
		t.Fatalf("processEvents(reload initial): %v", result.Error)
	}
	if !syncNow || shutdown {
		t.Fatalf("initial reload syncNow/shutdown = %v/%v, want true/false", syncNow, shutdown)
	}
	latestLinks, latestReconcile := readTestIPsecObservation(service)
	if len(latestLinks) != 0 {
		t.Fatalf("initial link instances = %+v, want none", latestLinks)
	}

	reloadedConfig := strings.Join([]string{
		"data_dir: " + dataDir,
		"ipsec:",
		"  driver: dry-run",
		"overlays:",
		"  - id: main",
		"    provider: strongswan",
		"    netns:",
		"      name: photontesth2",
		"      create: true",
		"    default_path_mode: family-redundant",
		"    address_source_order: [manual-address]",
		"    connect:",
		"      - strongswan://*.catofes.?role=in",
		"",
	}, "\n")
	if err := os.WriteFile(configPath, []byte(reloadedConfig), 0o600); err != nil {
		t.Fatalf("WriteFile(reloaded config): %v", err)
	}

	reply = make(chan daemonEventResult, 1)
	service.Events <- daemonEvent{Type: daemonEventReloadConfig, Reply: reply}
	syncNow, shutdown, _, _, _ = service.processEvents(context.Background())
	result = <-reply
	if result.Error != nil {
		t.Fatalf("processEvents(reload overlay): %v", result.Error)
	}
	if !syncNow || shutdown {
		t.Fatalf("overlay reload syncNow/shutdown = %v/%v, want true/false", syncNow, shutdown)
	}
	latestLinks, latestReconcile = readTestIPsecObservation(service)
	if len(latestLinks) != 1 {
		t.Fatalf("link instances after reload = %d, want 1", len(latestLinks))
	}
	if latestReconcile == nil || len(latestReconcile.Actions) != 1 || latestReconcile.Actions[0].Action != ipsec.ReconcileActionCreate {
		t.Fatalf("ipsec reconcile after reload = %+v, want create", latestReconcile)
	}
	if current := service.currentGossipConfig(); len(service.App.Config.IPsec.LinkGroups) != 1 || current.PeerID != config.PeerID {
		t.Fatalf("daemon config was not refreshed: app=%+v sync=%+v", service.App.Config.IPsec.LinkGroups, current)
	}
}

func TestDaemonReloadConfigRejectsStatePathSwitch(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	dataDir := filepath.Join(dir, "data")
	otherDir := filepath.Join(dir, "other")
	t.Setenv("PHOTON_CONFIG", configPath)
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatalf("MkdirAll(dataDir): %v", err)
	}
	if err := os.WriteFile(configPath, []byte("data_dir: "+otherDir+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(config): %v", err)
	}
	rt := &AppContext{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(dataDir, "photon.db"),
		Clock:     func() time.Time { return time.Unix(4300, 0) },
	}
	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, config, time.Second)

	result, syncNow, shutdown := service.handleEvent(daemonEvent{Type: daemonEventReloadConfig})
	if result.Error == nil || !strings.Contains(result.Error.Error(), "restart daemon to switch state") {
		t.Fatalf("reload error = %v, want state path switch rejection", result.Error)
	}
	if syncNow || shutdown {
		t.Fatalf("syncNow/shutdown = %v/%v, want false/false", syncNow, shutdown)
	}
}

func TestRootCommandIncludesDaemon(t *testing.T) {
	for _, command := range rootCommand().Commands {
		if command.Name == "daemon" {
			return
		}
	}
	t.Fatal("root command does not include daemon")
}
