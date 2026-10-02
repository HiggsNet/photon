package photonwindows

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
)

// TestCrossHostGossip is opt-in: the rig coordinates two independent OS processes
// on Linux and Windows. It never uses production identities or databases.
func TestCrossHostGossip(t *testing.T) {
	role := os.Getenv("PHOTON_CROSS_ROLE")
	if role == "" {
		t.Skip("run docs/scripts/windows-cross-host-smoke.sh")
	}
	dir := os.Getenv("PHOTON_CROSS_DIR")
	if dir == "" {
		t.Fatal("PHOTON_CROSS_DIR required")
	}
	type manifest struct {
		Root           ed25519.PublicKey
		Linux, Windows string
	}
	var m manifest
	write := func(name string, data []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	waitFile := func(name string) {
		t.Helper()
		waitForWindowsState(t, 60*time.Second, func() bool { _, err := os.Stat(filepath.Join(dir, name)); return err == nil })
	}
	probe := func(address string) bool {
		r, err := (objectPullClient{}).Exchange(t.Context(), address, &gossip.ObjectPullRequest{Type: gossip.ObjectPullZone, Zone: "node-a.catofes."})
		return err == nil && r.OK && r.Snapshot != nil
	}
	switch role {
	case "linux":
		f := newWindowsGossipFixture(t)
		m = manifest{f.rootPublic, os.Getenv("PHOTON_CROSS_LINUX"), os.Getenv("PHOTON_CROSS_WINDOWS")}
		data, err := os.ReadFile(f.rightPath)
		if err != nil {
			t.Fatal(err)
		}
		write("right.db", data)
		data, err = json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		write("manifest.json", data)
		_, stop := startConsole(t, &Config{State: StateConfig{Path: f.leftPath}, ManagedZone: "node-a.catofes.", TrustedRootPublicKey: m.Root, GossipListen: m.Linux})
		defer stop()
		write("ready", nil)
		waitFile("verify")
		waitForWindowsState(t, 15*time.Second, func() bool { return probe(m.Windows) })
		t.Log("Linux pulled the persisted node-a object from restarted Windows over TCP")
	case "windows":
		data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
		if err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal(data, &m); err != nil {
			t.Fatal(err)
		}
		cfg := &Config{State: StateConfig{Path: filepath.Join(dir, "right.db")}, ManagedZone: "node-b.catofes.", TrustedRootPublicKey: m.Root, GossipListen: m.Windows, Gateway: GatewayConfig{BootstrapHints: []BootstrapHint{{Peer: "node-a.catofes.", Address: m.Linux}}}}
		initial, err := OpenState(cfg.State.Path, cfg.ManagedZone, m.Root, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		initialView, err := initial.ReadView(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if initialView.Revision != 11 || initialView.State.Network.Zones["node-a.catofes."] != nil {
			t.Fatal("fixture already contains Linux object")
		}
		if err = initial.Close(); err != nil {
			t.Fatal(err)
		}
		_, stop := startConsole(t, cfg)
		waitForWindowsState(t, 30*time.Second, func() bool { return probe(m.Windows) })
		stop()
		state, err := OpenState(cfg.State.Path, cfg.ManagedZone, m.Root, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		view, err := state.ReadView(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if view.Revision != initialView.Revision+1 || view.State.Network.Zones["node-a.catofes."] == nil {
			t.Fatal("cross-host convergence not persisted")
		}
		if err = state.Close(); err != nil {
			t.Fatal(err)
		}
		// No bootstrap on restart: subsequent TCP responses must use persisted state.
		cfg.Gateway.BootstrapHints = nil
		_, stopRestarted := startConsole(t, cfg)
		defer stopRestarted()
		if !probe(m.Windows) {
			t.Fatal("missing restored object")
		}
		write("restarted", nil)
		waitFile("stop")
		stopRestarted()
		restored, err := OpenState(cfg.State.Path, cfg.ManagedZone, m.Root, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer restored.Close()
		restoredView, err := restored.ReadView(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if restoredView.Revision != view.Revision {
			t.Fatalf("restart changed revision: %d -> %d", view.Revision, restoredView.Revision)
		}
		t.Logf("Windows revisions: initial=%d synchronized=%d restarted=%d", initialView.Revision, view.Revision, restoredView.Revision)
		t.Log("Windows synchronized from Linux, reopened the same DB and UDP/TCP port, and served restored state")
	default:
		t.Fatalf("unknown cross-host role %q", role)
	}
}
