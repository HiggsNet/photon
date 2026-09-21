package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLinuxStatePathOverride(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	configDataDir := filepath.Join(dir, "config-data")
	overridePath := filepath.Join(dir, "override", "state.db")
	writeRuntimeConfig(t, configPath, configDataDir, nil)
	t.Setenv("PHOTON_CONFIG", configPath)
	t.Setenv("PHOTON_STATE", overridePath)

	config, err := loadAppConfig()
	if err != nil {
		t.Fatalf("loadAppConfig: %v", err)
	}
	if config.StatePath != overridePath {
		t.Fatalf("StatePath = %q, want override %q", config.StatePath, overridePath)
	}
	if _, err := initializeRootState(config); err != nil {
		t.Fatalf("initialize overridden state: %v", err)
	}
	state, err := openState(config)
	if err != nil {
		t.Fatalf("reopen overridden state: %v", err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(overridePath); err != nil {
		t.Fatalf("overridden state file: %v", err)
	}
	if _, err := os.Stat(filepath.Join(configDataDir, defaultStateFile)); !os.IsNotExist(err) {
		t.Fatalf("default state file should not be created: %v", err)
	}
}

func TestRuntimeSyncConfigDerivesLimitsAndPeerID(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	writeRuntimeConfig(t, configPath, filepath.Join(dir, "data"), map[string]string{
		"max_datagram_bytes": "4096",
		"max_sync_zones":     "8",
		"max_sync_records":   "64",
	})
	t.Setenv("PHOTON_CONFIG", configPath)

	config, err := loadAppConfig()
	if err != nil {
		t.Fatalf("loadAppConfig: %v", err)
	}
	verified, _, _, _ := buildTestDaemonOwners(t)
	peerID := configuredPeerID(config, verified)
	if peerID != string(verified.ManagedZone) {
		t.Fatalf("PeerID = %q, want managed zone default %q", peerID, verified.ManagedZone)
	}
	limits := syncLimits(config)
	if limits.MaxBytes != 4096 || limits.MaxZones != 8 || limits.MaxRecords != 64 {
		t.Fatalf("limits = %#v, want 4096/8/64", limits)
	}
}

func TestRuntimeLogConfigAndEnvironmentOverride(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	writeRuntimeConfig(t, configPath, filepath.Join(dir, "data"), map[string]string{
		"log.level": "debug",
		"log.mode":  "stderr+file",
		"log.file":  filepath.Join(dir, "photon.log"),
	})
	t.Setenv("PHOTON_CONFIG", configPath)
	t.Setenv("PHOTON_LOG_LEVEL", "")
	config, err := loadAppConfig()
	if err != nil {
		t.Fatal(err)
	}
	if syncDebugLogger(config) == nil {
		t.Fatalf("config log.level=debug should enable debug logs")
	}
	if config.Log.Mode != "stderr+file" || config.Log.File != filepath.Join(dir, "photon.log") {
		t.Fatalf("log output config = mode %q file %q, want stderr+file/%s", config.Log.Mode, config.Log.File, filepath.Join(dir, "photon.log"))
	}
	t.Setenv("PHOTON_LOG_LEVEL", "info")
	if syncDebugLogger(config) != nil {
		t.Fatalf("PHOTON_LOG_LEVEL should override config log.level")
	}
	t.Setenv("PHOTON_LOG_LEVEL", "debug")
	config.Log.Level = "info"
	if syncDebugLogger(config) == nil {
		t.Fatalf("PHOTON_LOG_LEVEL=debug should enable debug logs")
	}
}

func writeRuntimeConfig(t *testing.T, path string, dataDir string, extra map[string]string) {
	t.Helper()
	var lines []string
	lines = append(lines, "data_dir: "+dataDir)
	lines = append(lines, "gossip:")
	lines = append(lines, "  listen_addr: 127.0.0.1:0")
	for _, key := range []string{"max_datagram_bytes", "max_sync_zones", "max_sync_records"} {
		if value := extra[key]; value != "" {
			lines = append(lines, "  "+key+": "+value)
		}
	}
	if value := extra["log.level"]; value != "" || extra["log.mode"] != "" {
		lines = append(lines, "log:")
		if mode := extra["log.mode"]; mode != "" {
			lines = append(lines, "  mode: "+mode)
			if file := extra["log.file"]; file != "" {
				lines = append(lines, "  file: "+file)
			}
		}
		if value != "" {
			lines = append(lines, "  level: "+value)
		}
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(config): %v", err)
	}
}
