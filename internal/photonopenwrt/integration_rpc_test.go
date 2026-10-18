//go:build linux

package photonopenwrt

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func networkRPCFixture(t *testing.T) (*Handler, string, *[]string) {
	h, path, calls := fixture(t)
	original := h.options.Run
	h.options.Run = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "ubus" && len(args) == 3 && args[1] == "network.interface" && args[2] == "dump" {
			*calls = append(*calls, name+" "+strings.Join(args, " "))
			return []byte(inventoryFixture), nil
		}
		return original(ctx, name, args...)
	}
	return h, path, calls
}

func TestRPCNetworkSettingsAndNodeSaveShareConfigHashAndValidator(t *testing.T) {
	h, path, calls := networkRPCFixture(t)
	before := "# retain\ndata_dir: /etc/photon\nidentity_key_path: /etc/photon/key.pem\n"
	if err := os.WriteFile(path, []byte(before), 0600); err != nil {
		t.Fatal(err)
	}
	initial := invoke(t, h, "network_settings", map[string]any{})
	if initial["ok"] != true || len(initial["inventory"].([]any)) != 3 {
		t.Fatal(initial)
	}
	settings := `{"wan_networks":["wan","wan6"],"announce_ipsec":true,"auto_firewall":true}`
	saved := invoke(t, h, "save_network_settings", map[string]any{"settings": settings, "sha256": initial["sha256"]})
	if saved["ok"] != true || saved["sha256"] == initial["sha256"] || !strings.Contains(saved["content"].(string), "# retain") {
		t.Fatal(saved)
	}
	content, _ := os.ReadFile(path)
	if string(content) != saved["content"] {
		t.Fatal("returned editor content does not match committed YAML")
	}
	current := invoke(t, h, "network_settings", map[string]any{})
	if current["sha256"] != saved["sha256"] || current["status"].(map[string]any)["ready"] != true {
		t.Fatal(current)
	}
	conflict := invoke(t, h, "save_network_settings", map[string]any{"settings": settings, "sha256": initial["sha256"]})
	if conflict["ok"] != false {
		t.Fatal("stale form overwrote configuration")
	}
	for _, call := range *calls {
		if strings.Contains(call, "init-photon") || strings.HasPrefix(call, "uci set") || strings.HasPrefix(call, "uci commit") {
			t.Fatalf("network settings changed runtime/UCI: %s", call)
		}
	}
}

func TestRPCNetworkSettingsInvalidRequestsAndConcurrentLockPreserveYAML(t *testing.T) {
	h, path, _ := networkRPCFixture(t)
	content := "data_dir: /etc/photon\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	hash := configHash([]byte(content), true)
	for _, settings := range []string{`null`, `[]`, `{"auto_firewall":true}`, `{"wan_networks":["wan"],"arbitrary_path":"/etc/network"}`, `{"announce_ipsec":"true"}`, `{} {}`} {
		if reply := invoke(t, h, "save_network_settings", map[string]any{"settings": settings, "sha256": hash}); reply["ok"] != false {
			t.Fatalf("accepted invalid settings %s: %v", settings, reply)
		}
	}
	if err := os.MkdirAll(h.options.RuntimeDir, 0700); err != nil {
		t.Fatal(err)
	}
	lock, err := os.OpenFile(filepath.Join(h.options.RuntimeDir, "config.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	settings, _ := json.Marshal(Config{WANNetworks: []string{"wan"}, AutoFirewall: true})
	if reply := invoke(t, h, "save_network_settings", map[string]any{"settings": string(settings), "sha256": hash}); reply["ok"] != false {
		t.Fatal("form bypassed YAML file lock")
	}
	after, _ := os.ReadFile(path)
	if string(after) != content {
		t.Fatal("failed network form changed YAML")
	}
}

func TestRPCNetworkInventoryFailureIsVisibleAndCanSaveDisabled(t *testing.T) {
	h, path, _ := networkRPCFixture(t)
	content := "openwrt:\n  wan_networks: [missing]\n  announce_ipsec: true\n"
	os.WriteFile(path, []byte(content), 0600)
	reply := invoke(t, h, "network_settings", map[string]any{})
	if reply["ok"] != true || reply["status"].(map[string]any)["ready"] != false || !strings.Contains(reply["status"].(map[string]any)["error"].(string), "missing") {
		t.Fatal(reply)
	}
	original := h.options.Run
	h.options.Run = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "ubus" {
			return nil, errors.New("netifd disconnected")
		}
		return original(ctx, name, args...)
	}
	reply = invoke(t, h, "network_settings", map[string]any{})
	if reply["ok"] != true || reply["inventory_error"] == nil || reply["status"].(map[string]any)["ready"] != false {
		t.Fatal(reply)
	}
	if saved := invoke(t, h, "save_network_settings", map[string]any{"settings": `{"wan_networks":[],"announce_ipsec":false,"auto_firewall":false}`, "sha256": reply["sha256"]}); saved["ok"] != true {
		t.Fatal(saved)
	}
}

func TestRPCNetworkRuntimeIsIndependentOfInventoryReadiness(t *testing.T) {
	h, path, _ := networkRPCFixture(t)
	if err := os.WriteFile(path, []byte("data_dir: /etc/photon\n"), 0600); err != nil {
		t.Fatal(err)
	}
	h.options.IntegrationStatus = func(_ context.Context, gotPath string) (json.RawMessage, error) {
		if gotPath != path {
			t.Fatalf("runtime callback path = %q", gotPath)
		}
		return json.RawMessage(`{"enabled":true,"auto_firewall":true,"firewall_applied":false,"last_error":"fw4 chain missing","addresses":["192.168.1.2"]}`), nil
	}
	reply := invoke(t, h, "network_settings", map[string]any{})
	if reply["status"].(map[string]any)["ready"] != true || reply["runtime"].(map[string]any)["firewall_applied"] != false {
		t.Fatalf("inventory readiness replaced runtime proof: %v", reply)
	}
	h.options.IntegrationStatus = func(context.Context, string) (json.RawMessage, error) {
		return nil, errors.New("control socket offline")
	}
	reply = invoke(t, h, "network_settings", map[string]any{})
	if reply["runtime"] != nil || reply["runtime_error"] != "control socket offline" || reply["settings"] == nil {
		t.Fatalf("offline runtime hid config or retained applied state: %v", reply)
	}
}
