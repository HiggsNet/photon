package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/photonwindows"
	"github.com/HiggsNet/photon/pkg/core/share"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

func TestStateImportCLI(t *testing.T) {
	for _, format := range []string{"json", "base64"} {
		t.Run(format, func(t *testing.T) {
			root, rootKey, err := ed25519.GenerateKey(nil)
			if err != nil {
				t.Fatal(err)
			}
			public, private, err := ed25519.GenerateKey(nil)
			if err != nil {
				t.Fatal(err)
			}
			managed := zone.ZonePath("laptop.")
			authority := &zone.ZoneAuthority{Zone: managed, Epoch: 1, Threshold: 1, Keys: []zone.AuthorizedKey{{Key: public, Capabilities: []zone.Capability{{Permissions: []zone.Permission{zone.PermWrite}}}}}}
			delegation := &zone.Delegation{ZoneName: managed, Authority: *authority}
			if err := photoncrypto.SignDelegation(delegation, zone.RootZone, rootKey); err != nil {
				t.Fatal(err)
			}
			network := zone.NewNetworkState()
			network.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, photoncrypto.ConfiguredRootAuthority(root))
			network.Zones[managed] = zone.NewZoneState(managed, authority)
			// Match Linux's minimal bundle: proof on the child, no parent delegation map.
			network.Zones[managed].ParentProof = []*zone.Delegation{delegation}
			bundle := &share.JoinBundle{Version: 1, Zone: managed, RootPublicKey: root, Network: network}
			dir := t.TempDir()
			dbPath := filepath.Join(dir, "photon.db")
			configPath := filepath.Join(dir, "config.yaml")
			config := fmt.Sprintf("schema_version: 1\ntrusted_root_public_key: %s\nmanaged_zone: laptop.\nstate:\n  path: '%s'\noverlay:\n  id: main\n  split_routes: [10.42.0.0/16]\ngateway:\n  allowed_zones: [gateway.]\n", base64.StdEncoding.EncodeToString(root), dbPath)
			write := func(path string, data []byte) {
				t.Helper()
				if err := os.WriteFile(path, data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			write(configPath, []byte(config))
			data, err := json.Marshal(bundle)
			if err != nil {
				t.Fatal(err)
			}
			if format == "base64" {
				encoded, err := share.EncodeBase64JSON(bundle)
				if err != nil {
					t.Fatal(err)
				}
				data = []byte(encoded + "\n")
			}
			bundlePath := filepath.Join(dir, "bundle")
			write(bundlePath, data)
			keyPath := filepath.Join(dir, "key.json")
			data, err = json.Marshal(&share.PrivateKeyFile{Type: "photon.ed25519.private.v1", PublicKey: public, PrivateKey: private})
			if err != nil {
				t.Fatal(err)
			}
			write(keyPath, data)
			args := []string{"state", "import", "--config", configPath, "--bundle", bundlePath, "--key", keyPath}
			var stdout, stderr bytes.Buffer
			if code := run(args, &stdout, &stderr); code != 0 {
				t.Fatalf("import exit %d: %s", code, &stderr)
			}
			state, err := photonwindows.OpenState(dbPath, managed, root, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			if err := state.Close(); err != nil {
				t.Fatal(err)
			}
			stdout.Reset()
			if code := run([]string{"gateways", "--config", configPath}, &stdout, &stderr); code != 0 {
				t.Fatalf("gateways exit %d: %s", code, &stderr)
			}
			var report struct {
				Revision        uint64                           `json:"revision"`
				RouteAuthorized bool                             `json:"route_authorized"`
				Candidates      []photonwindows.GatewayCandidate `json:"candidates"`
			}
			if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
				t.Fatal(err)
			}
			if report.Revision != 1 || report.RouteAuthorized || len(report.Candidates) != 1 || report.Candidates[0].Rejected == "" {
				t.Fatalf("unexpected gateway diagnosis: %s", &stdout)
			}
			if code := run(args, &stdout, &stderr); code != 1 {
				t.Fatalf("second import exit %d", code)
			}
		})
	}
}
