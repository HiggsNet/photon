package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersionCommandUsesPhotonWindowsName(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"version"}, &stdout, &stderr); code != 0 {
		t.Fatalf("run(version) code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.HasPrefix(stdout.String(), "photon-windows ") {
		t.Fatalf("version output = %q", stdout.String())
	}
}

func TestRunRequiresExplicitConsoleAndConfig(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"run"}, &stdout, &stderr); code != 2 {
		t.Fatalf("run(run) code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "run --console --config <path>") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestConfigValidate(t *testing.T) {
	source, err := os.ReadFile("../../docs/photon-windows/config.example.yaml")
	if err != nil {
		t.Fatalf("read example: %v", err)
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, source, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"config", "validate", "--config", path}, &stdout, &stderr); code != 0 {
		t.Fatalf("run(config validate) code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "valid Photon Windows config (schema 1)") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestConfigValidateRejectsInvalidConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("schema_version: 1\nunknown: true\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"config", "validate", "--config", path}, &stdout, &stderr); code != 1 {
		t.Fatalf("run(config validate) code = %d, stderr = %q", code, stderr.String())
	}
}
