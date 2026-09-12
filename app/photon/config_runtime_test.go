package main

import (
	"path/filepath"
	"testing"
)

func TestLinuxStatePathOverride(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	configDataDir := filepath.Join(dir, "config-data")
	overridePath := filepath.Join(dir, "override", "state.db")
	writeRuntimeConfig(t, configPath, configDataDir, nil, nil)
	t.Setenv("PHOTON_CONFIG", configPath)
	t.Setenv("PHOTON_STATE", overridePath)

	rt, err := NewAppContext()
	if err != nil {
		t.Fatalf("NewAppContext: %v", err)
	}
	if rt.StatePath != overridePath {
		t.Fatalf("StatePath = %q, want override %q", rt.StatePath, overridePath)
	}
}

func TestRuntimeSyncConfigDerivesLimitsAndDefaults(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	writeRuntimeConfig(t, configPath, filepath.Join(dir, "data"), nil, map[string]string{
		"max_datagram_bytes": "4096",
		"max_sync_zones":     "8",
		"max_sync_records":   "64",
		"log.level":          "debug",
		"log.mode":           "stderr+file",
		"log.file":           filepath.Join(dir, "photon.log"),
	})
	t.Setenv("PHOTON_CONFIG", configPath)

	rt, err := NewAppContext()
	if err != nil {
		t.Fatalf("NewAppContext: %v", err)
	}
	verified, _, _, _ := buildTestDaemonOwners(t)
	peerID := configuredPeerID(rt.Config, verified)
	if peerID != string(verified.ManagedZone) {
		t.Fatalf("PeerID = %q, want managed zone default %q", peerID, verified.ManagedZone)
	}
	limits := syncLimits(rt.Config)
	if limits.MaxBytes != 4096 || limits.MaxZones != 8 || limits.MaxRecords != 64 {
		t.Fatalf("limits = %#v, want 4096/8/64", limits)
	}
	if !debugLogEnabled(rt.Config) {
		t.Fatalf("config log.level=debug should enable debug logs")
	}
	if rt.Config.Log.Mode != "stderr+file" || rt.Config.Log.File != filepath.Join(dir, "photon.log") {
		t.Fatalf("log output config = mode %q file %q, want stderr+file/%s", rt.Config.Log.Mode, rt.Config.Log.File, filepath.Join(dir, "photon.log"))
	}
	t.Setenv("PHOTON_LOG_LEVEL", "info")
	if debugLogEnabled(rt.Config) {
		t.Fatalf("PHOTON_LOG_LEVEL should override config log.level")
	}
	t.Setenv("PHOTON_LOG_LEVEL", "debug")
	rt.Config.LogLevel = "info"
	if !debugLogEnabled(rt.Config) {
		t.Fatalf("PHOTON_LOG_LEVEL=debug should enable debug logs")
	}
}
