package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "photon-app-test-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "MkdirTemp: %v\n", err)
		os.Exit(1)
	}
	if err := installTestConfigDefaults(dir); err != nil {
		fmt.Fprintf(os.Stderr, "install test config defaults: %v\n", err)
		os.RemoveAll(dir)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func installTestConfigDefaults(dir string) error {
	dataDir := filepath.Join(dir, "data")
	configPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("data_dir: "+dataDir+"\n"), 0o600); err != nil {
		return err
	}
	if err := os.Setenv("PHOTON_CONFIG", configPath); err != nil {
		return err
	}
	os.Unsetenv("PHOTON_STATE")
	os.Unsetenv("PHOTON_CONTROL_SOCKET")
	if err := os.Setenv("PHOTON_CONTROL_SOCKET_SCOPE", "data-dir"); err != nil {
		return err
	}
	return nil
}

func TestPackageTestsUseIsolatedConfigDefaults(t *testing.T) {
	if path := configPath(); path == defaultConfigPath || strings.HasPrefix(path, defaultDataDir) {
		t.Fatalf("test config path = %q, want isolated temporary config", path)
	}

	config, err := loadAppConfig()
	if err != nil {
		t.Fatalf("loadAppConfig: %v", err)
	}
	if strings.HasPrefix(config.StatePath, defaultDataDir) {
		t.Fatalf("test StatePath = %q, want isolated temporary state", config.StatePath)
	}

	controlPath := controlSocketPath(config)
	wantControlPath := filepath.Join(config.DataDir, controlSocketName)
	if controlPath != wantControlPath {
		t.Fatalf("controlSocketPath = %q, want isolated path %q", controlPath, wantControlPath)
	}
}
