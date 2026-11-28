package configedit

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/HiggsNet/photon/internal/photonwindows"
)

func TestCopyConfigurationCanMoveAndKeepsOriginals(t *testing.T) {
	source := filepath.Join(t.TempDir(), "source.yaml")
	editor := New(source)
	form, err := editor.LoadForm()
	if err != nil {
		t.Fatal(err)
	}
	form.RootPublicKey, form.ManagedZone, form.SplitRoutes = strings.Repeat("01", 32), "leaf.catofes.", "10.16.0.0/16"
	if err := editor.SaveForm(form); err != nil {
		t.Fatal(err)
	}
	original, _ := os.ReadFile(source)
	template := []byte("rules: [MATCH,DIRECT]\n")
	if err := os.WriteFile(filepath.Join(filepath.Dir(source), "source.proxy.yaml"), template, 0600); err != nil {
		t.Fatal(err)
	}
	parent := t.TempDir()
	dir := filepath.Join(parent, "imported")
	target := filepath.Join(dir, "photon.yaml")
	if err := Copy(source, target); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(source)
	if !bytes.Equal(after, original) {
		t.Fatal("source changed")
	}
	moved := filepath.Join(parent, "moved")
	if err := os.Rename(dir, moved); err != nil {
		t.Fatal(err)
	}
	config, err := photonwindows.LoadConfig(filepath.Join(moved, "photon.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if config.State.Path != filepath.Join(moved, "photon.db") {
		t.Fatalf("state stayed at old location: %s", config.State.Path)
	}
	data, err := os.ReadFile(filepath.Join(moved, "photon.proxy.yaml"))
	if err != nil || !bytes.Equal(data, template) {
		t.Fatalf("template lost: %v", err)
	}
	if err := Copy(source, filepath.Join(moved, "photon.yaml")); err == nil {
		t.Fatal("accepted occupied directory")
	}
}

func TestCopyRejectsInvalidIdentityAndLeavesNoPartialConfiguration(t *testing.T) {
	source := filepath.Join(t.TempDir(), "source.yaml")
	editor := New(source)
	form, _ := editor.LoadForm()
	form.RootPublicKey, form.ManagedZone, form.SplitRoutes = strings.Repeat("01", 32), "leaf.catofes.", "10.16.0.0/16"
	if err := editor.SaveForm(form); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(source), form.StatePath), []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "destination")
	if err := Copy(source, filepath.Join(dir, "photon.yaml")); err == nil {
		t.Fatal("copied invalid identity")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("failed copy left files: %v %v", entries, err)
	}
}

func TestProxyV2ConfigSurvivesDesktopSettingsAndCopy(t *testing.T) {
	source := filepath.Join(t.TempDir(), "photon.yaml")
	proxy := filepath.Join(filepath.Dir(source), "proxy-v2.yaml")
	if err := os.WriteFile(proxy, []byte("state_dir: proxy-state\nclient: {}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	form := DefaultForm(source)
	form.RootPublicKey, form.ManagedZone, form.SplitRoutes = strings.Repeat("01", 32), "leaf.catofes.", "10.16.0.0/16"
	text, err := formText(form, filepath.Base(proxy))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	editor := New(source)
	form, err = editor.LoadForm()
	if err != nil {
		t.Fatal(err)
	}
	form.LogLevel = "debug"
	if err := editor.SaveForm(form); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "photon.yaml")
	if err := Copy(source, target); err != nil {
		t.Fatal(err)
	}
	config, err := photonwindows.LoadConfig(target)
	if err != nil {
		t.Fatal(err)
	}
	if config.ProxyV2ConfigPath != proxy || config.Log.Level != "debug" {
		t.Fatalf("copied configuration lost edited settings or Proxy v2: %+v", config)
	}
}
