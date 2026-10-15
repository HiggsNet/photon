package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/HiggsNet/photon/internal/photonwindows"
)

func desktopTestConfig(state string) string {
	return fmt.Sprintf("schema_version: 1\ntrusted_root_public_key: %s\nmanaged_zone: laptop.\nstate:\n  path: '%s'\noverlay:\n  id: main\n  split_routes: [10.42.0.0/16]\ngateway:\n  allowed_zones: [gateway.]\n", strings.Repeat("01", 32), strings.ReplaceAll(state, "'", "''"))
}

func TestDesktopConfigSaveValidationConflictAndRecovery(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	text := desktopTestConfig(filepath.Join(dir, "state.db"))
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	b, err := newDesktopBackend(desktopOptions{ConfigPath: path})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.SaveConfigText(text); err == nil {
		t.Fatal("save without load accepted")
	}
	if _, err := b.LoadConfigText(); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{text + "unknown_field: true\n", strings.ReplaceAll(text, filepath.Join(dir, "state.db"), "relative.db"), text + "---\nschema_version: 1\n"} {
		if err := b.SaveConfigText(invalid); err == nil {
			t.Fatal("invalid config saved")
		}
		if got, _ := os.ReadFile(path); string(got) != text {
			t.Fatal("invalid save changed original")
		}
	}
	external := text + "# external edit\n"
	if err := os.WriteFile(path, []byte(external), 0600); err != nil {
		t.Fatal(err)
	}
	if err := b.SaveConfigText(text); err == nil {
		t.Fatal("external edit overwritten")
	}
	if got, _ := os.ReadFile(path); string(got) != external {
		t.Fatal("conflict changed external edit")
	}
	if _, err := b.LoadConfigText(); err != nil {
		t.Fatal(err)
	}
	if err := b.SaveConfigText(text + "# edited\n"); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); string(got) != text+"# edited\n" {
		t.Fatal("saved text not preserved")
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(path)
		if info.Mode().Perm() != 0600 {
			t.Fatal("permissions widened")
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "state.db")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("editor opened or created state")
	}
	files, _ := filepath.Glob(filepath.Join(dir, ".photon-config-*"))
	if len(files) != 0 {
		t.Fatalf("temporary files leaked: %v", files)
	}
}

func TestDesktopMissingConfigAndNoClobber(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	b, err := newDesktopBackend(desktopOptions{ConfigPath: path})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.LoadConfigText(); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing load: %v", err)
	}
	text := desktopTestConfig(filepath.Join(dir, "state.db"))
	if err := os.WriteFile(path, []byte(text+"# concurrent create\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := b.SaveConfigText(text); err == nil {
		t.Fatal("concurrent creation overwritten")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := b.LoadConfigText(); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if err := b.SaveConfigText(text); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); string(got) != text {
		t.Fatal("missing config not saved")
	}
}

func TestDesktopConfigReplacedIdentityAndCommitFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	text := desktopTestConfig(filepath.Join(dir, "state.db"))
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	b, _ := newDesktopBackend(desktopOptions{ConfigPath: path})
	if _, err := b.LoadConfigText(); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(dir, "external.yaml")
	if err := os.WriteFile(other, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	if err := desktopReplaceConfig(other, path, true); err != nil {
		t.Fatal(err)
	}
	if err := b.SaveConfigText(text + "# edited\n"); err == nil {
		t.Fatal("same-content replacement was overwritten")
	}
	if err := desktopReplaceConfig(filepath.Join(dir, "missing"), path, true); err == nil {
		t.Fatal("missing replacement succeeded")
	}
	if got, _ := os.ReadFile(path); string(got) != text {
		t.Fatal("commit failure damaged original")
	}
}

func TestDesktopRejectsNonregularConfig(t *testing.T) {
	dir := t.TempDir()
	b, err := newDesktopBackend(desktopOptions{ConfigPath: dir})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.LoadConfigText(); err == nil {
		t.Fatal("directory accepted as config")
	}
}

func TestDesktopRejectsLinkedConfig(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.yaml")
	text := desktopTestConfig(filepath.Join(dir, "state.db"))
	if err := os.WriteFile(target, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "config.yaml")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	b, err := newDesktopBackend(desktopOptions{ConfigPath: link})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.LoadConfigText(); err == nil {
		t.Fatal("linked config accepted")
	}
	if err := b.SaveConfigText(text + "# edited\n"); err == nil {
		t.Fatal("linked config saved")
	}
	if got, _ := os.ReadFile(target); string(got) != text {
		t.Fatal("link target changed")
	}
}

func TestDesktopUnavailableObservationClearsView(t *testing.T) {
	good := photonwindows.ControlResponse{Version: photonwindows.ControlVersion, Method: "status", Result: json.RawMessage(`{"running":true,"tunnel_ready":true}`)}
	if out, err := desktopObservation(good); err != nil || out == nil || !out.TunnelReady {
		t.Fatalf("good response: %v, %v", out, err)
	}
	for _, response := range []photonwindows.ControlResponse{
		{Version: 1, Method: "status", Result: json.RawMessage(`{"running":false}`)},
		{Version: 1, Method: "status", Result: json.RawMessage(`null`)},
		{Version: 1, Method: "status", Result: json.RawMessage(`{`)},
		{Version: 1, Method: "routes", Result: good.Result},
		{Version: 2, Method: "status", Result: good.Result},
		{Version: 1, Method: "status", Error: &photonwindows.ControlError{Code: "unavailable", Message: "stopped"}},
	} {
		if out, err := desktopObservation(response); err == nil || out != nil {
			t.Fatalf("stale observation retained: %v, %v", out, err)
		}
	}
}
