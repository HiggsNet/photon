//go:build linux

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/HiggsNet/photon/internal/inspect"
)

func TestOpenWrtEditorUsesStrictRealConfigParser(t *testing.T) {
	for _, content := range []string{
		"", "[]", "null", "unknown_option: true\n", "log: {mode: invalid}\n",
		"data_dir: /etc/photon\n---\nunknown_option: true\n",
	} {
		if _, err := parseOpenWrtConfig(content); err == nil {
			t.Fatalf("editor accepted invalid config %q", content)
		}
	}
	content, err := os.ReadFile("../../contrib/openwrt/files/config.yaml.example")
	if err != nil {
		t.Fatal(err)
	}
	config, err := parseOpenWrtConfig(string(content))
	if err != nil || config.StatePath != "/etc/photon/photon.db" {
		t.Fatalf("example is not accepted by editor: %v, %v", config, err)
	}
}

func TestOpenWrtOfflineSnapshotNeverCreatesDatabase(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("data_dir: "+dir+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PHOTON_CONTROL_SOCKET", filepath.Join(dir, "absent.sock"))
	_, err := openWrtControlViews(context.Background(), path)
	if err == nil {
		t.Fatal("missing daemon was presented as online")
	}
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if strings.Contains(file.Name(), ".db") {
			t.Fatal("offline panel query opened or initialized a database")
		}
	}
}

func TestOpenWrtReadsCanonicalViewsThroughRealLocalControlSocket(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("data_dir: "+dir+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	_, daemon := newTestObserverServer()
	defer daemon.State.Close()
	daemon.ControlSocketPath = filepath.Join(dir, "photon.sock")
	t.Setenv("PHOTON_CONTROL_SOCKET", daemon.ControlSocketPath)
	stop, err := daemon.startControlServer(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	views, err := openWrtControlViews(t.Context(), configPath)
	if err != nil {
		t.Fatal(err)
	}
	var operational inspect.DaemonStatusView
	var summary inspect.StatusView
	if err := json.Unmarshal(views.Daemon, &operational); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(views.Summary, &summary); err != nil {
		t.Fatal(err)
	}
	if !operational.DaemonOnline || !summary.DaemonOnline || operational.PeerID != daemon.Config.PeerID {
		t.Fatalf("wrong canonical views: %+v, %+v", operational, summary)
	}
	var peers inspect.PeersView
	var links inspect.LinksDebugView
	if json.Unmarshal(views.Peers, &peers) != nil || json.Unmarshal(views.Links, &links) != nil {
		t.Fatal("peer/link views were not canonical inspect DTOs")
	}
	if _, err := os.Stat(filepath.Join(dir, "photon.db")); !os.IsNotExist(err) {
		t.Fatal("control query created a database")
	}
	runtime, err := openWrtIntegrationStatus(t.Context(), configPath)
	if err != nil {
		t.Fatal(err)
	}
	var integration openWrtStatus
	if err := json.Unmarshal(runtime, &integration); err != nil {
		t.Fatal(err)
	}
	if integration.Enabled || integration.FirewallApplied {
		t.Fatalf("disabled daemon reported active integration: %+v", integration)
	}
}
