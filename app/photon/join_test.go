package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

func TestJoinFlow(t *testing.T) {
	dir := t.TempDir()
	adminConfig := filepath.Join(dir, "admin.yaml")
	catofesConfig := filepath.Join(dir, "catofes.yaml")
	nodeConfig := filepath.Join(dir, "node.yaml")
	catofesKeyPath := filepath.Join(dir, "catofes.key.json")
	catofesRequestPath := filepath.Join(dir, "catofes.request.b64")
	catofesBundlePath := filepath.Join(dir, "catofes.bundle.b64")
	keyPath := filepath.Join(dir, "node-b.key.json")
	requestPath := filepath.Join(dir, "node-b.request.b64")
	bundlePath := filepath.Join(dir, "node-b.bundle.b64")
	siblingKeyPath := filepath.Join(dir, "node-a.key.json")
	siblingRequestPath := filepath.Join(dir, "node-a.request.b64")
	siblingBundlePath := filepath.Join(dir, "node-a.bundle.b64")

	writeConfig(t, adminConfig, filepath.Join(dir, "admin"))
	t.Setenv("PHOTON_CONFIG", adminConfig)
	if err := runRootInit(); err != nil {
		t.Fatalf("runRootInit(admin): %v", err)
	}

	writeConfig(t, catofesConfig, filepath.Join(dir, "catofes"))
	t.Setenv("PHOTON_CONFIG", catofesConfig)
	if err := keygen(catofesKeyPath); err != nil {
		t.Fatalf("keygen(catofes): %v", err)
	}
	if err := createJoinRequest("catofes.", catofesKeyPath, catofesRequestPath); err != nil {
		t.Fatalf("createJoinRequest(catofes): %v", err)
	}
	t.Setenv("PHOTON_CONFIG", adminConfig)
	if err := issueDelegation(catofesRequestPath, catofesBundlePath, nil, true); err != nil {
		t.Fatalf("issueDelegation(catofes): %v", err)
	}
	t.Setenv("PHOTON_CONFIG", catofesConfig)
	if err := acceptJoinBundle(catofesBundlePath, catofesKeyPath, true); err != nil {
		t.Fatalf("acceptJoinBundle(catofes): %v", err)
	}

	t.Setenv("PHOTON_CONFIG", nodeConfig)
	writeConfig(t, nodeConfig, filepath.Join(dir, "node-b"))
	if err := keygen(keyPath); err != nil {
		t.Fatalf("keygen: %v", err)
	}
	if err := createJoinRequest("node-b.catofes.", keyPath, requestPath); err != nil {
		t.Fatalf("createJoinRequest: %v", err)
	}
	t.Setenv("PHOTON_CONFIG", catofesConfig)
	if err := putRecord("catofes.", "admin-note", []byte("kept-out-of-bundle"), "policy.string", true); err != nil {
		t.Fatalf("putRecord(catofes): %v", err)
	}
	if err := keygen(siblingKeyPath); err != nil {
		t.Fatalf("keygen(node-a): %v", err)
	}
	if err := createJoinRequest("node-a.catofes.", siblingKeyPath, siblingRequestPath); err != nil {
		t.Fatalf("createJoinRequest(node-a): %v", err)
	}
	if err := issueDelegation(siblingRequestPath, siblingBundlePath, nil, true); err != nil {
		t.Fatalf("issueDelegation(node-a): %v", err)
	}
	if err := issueDelegation(requestPath, bundlePath, nil, true); err != nil {
		t.Fatalf("issueDelegation: %v", err)
	}
	var bundle joinBundle
	if err := readBase64JSONOrJSON(bundlePath, &bundle); err != nil {
		t.Fatalf("read node-b bundle: %v", err)
	}
	assertMinimalJoinBundle(t, &bundle, "node-b.catofes.", []zone.ZonePath{zone.RootZone, "catofes.", "node-b.catofes."})
	var siblingBundle joinBundle
	if err := readBase64JSONOrJSON(siblingBundlePath, &siblingBundle); err != nil {
		t.Fatalf("read node-a bundle: %v", err)
	}
	nodeBSnapshot, err := corestate.Snapshot(bundle.Network, "node-b.catofes.")
	if err != nil {
		t.Fatalf("Snapshot(node-b): %v", err)
	}
	nextNetwork, _, err := corestate.ApplySnapshot(siblingBundle.Network, nodeBSnapshot, time.Now(), corestate.DefaultSyncLimits())
	if err != nil {
		t.Fatalf("ApplySnapshot(node-b into node-a bundle): %v", err)
	}
	siblingBundle.Network = nextNetwork

	t.Setenv("PHOTON_CONFIG", nodeConfig)
	if err := acceptJoinBundle(bundlePath, keyPath, true); err != nil {
		t.Fatalf("acceptJoinBundle: %v", err)
	}
	state, err := loadConfiguredVerifiedState()
	if err != nil {
		t.Fatalf("loadState(node-b): %v", err)
	}
	if state.ManagedZone != zone.ZonePath("node-b.catofes.") {
		t.Fatalf("ManagedZone = %s, want node-b.catofes.", state.ManagedZone)
	}
	if len(state.RootPrivateKey) != 0 {
		t.Fatalf("joined node unexpectedly has root private key")
	}
	if err := putRecord("node-b.catofes.", "identity", []byte("node-b"), "node.identity", true); err != nil {
		t.Fatalf("putRecord(node-b): %v", err)
	}
	if err := verifyChain("node-b.catofes."); err != nil {
		t.Fatalf("verifyChain(node-b): %v", err)
	}
}

func TestJoinFlowAcceptsBase64PayloadArgs(t *testing.T) {
	dir := t.TempDir()
	adminConfig := filepath.Join(dir, "admin.yaml")
	nodeConfig := filepath.Join(dir, "node.yaml")
	keyPath := filepath.Join(dir, "node-b.key.json")

	writeConfig(t, adminConfig, filepath.Join(dir, "admin"))
	t.Setenv("PHOTON_CONFIG", adminConfig)
	if err := runRootInit(); err != nil {
		t.Fatalf("runRootInit(admin): %v", err)
	}

	writeConfig(t, nodeConfig, filepath.Join(dir, "node-b"))
	t.Setenv("PHOTON_CONFIG", nodeConfig)
	if err := keygen(keyPath); err != nil {
		t.Fatalf("keygen: %v", err)
	}
	key, err := readPrivateKeyFile(keyPath)
	if err != nil {
		t.Fatalf("readPrivateKeyFile: %v", err)
	}
	requestText, err := encodeBase64JSON(&joinRequest{
		Version:   1,
		Zone:      "node-b.",
		PublicKey: key.PublicKey,
	})
	if err != nil {
		t.Fatalf("encode request: %v", err)
	}

	t.Setenv("PHOTON_CONFIG", adminConfig)
	rt, err := NewAppContext()
	if err != nil {
		t.Fatalf("NewAppContext(admin): %v", err)
	}
	var request joinRequest
	if err := readBase64JSONOrJSON(requestText, &request); err != nil {
		t.Fatalf("read request payload: %v", err)
	}
	result, err := issueDelegationDirect(rt, &request, nil)
	if err != nil {
		t.Fatalf("issueDelegationDirect: %v", err)
	}
	bundleText, err := encodeBase64JSON(result.Bundle)
	if err != nil {
		t.Fatalf("encode bundle: %v", err)
	}

	t.Setenv("PHOTON_CONFIG", nodeConfig)
	if err := acceptJoinBundle(bundleText, keyPath, true); err != nil {
		t.Fatalf("acceptJoinBundle(base64): %v", err)
	}
	joined, err := loadConfiguredVerifiedState()
	if err != nil {
		t.Fatalf("loadState(node): %v", err)
	}
	if joined.ManagedZone != zone.ZonePath("node-b.") {
		t.Fatalf("ManagedZone = %s, want node-b.", joined.ManagedZone)
	}
}

func TestValidatePrivateKeyFileRejectsPrePhotonType(t *testing.T) {
	key := &privateKeyFile{Type: "higgs.ed25519.private.v1"}
	if err := validatePrivateKeyFile(key); err == nil || err.Error() != "unsupported key file type" {
		t.Fatalf("validatePrivateKeyFile(pre-Photon type) = %v, want unsupported key file type", err)
	}
}

func assertMinimalJoinBundle(t *testing.T, bundle *joinBundle, target zone.ZonePath, wantZones []zone.ZonePath) {
	t.Helper()
	if bundle.Zone != target {
		t.Fatalf("bundle zone = %s, want %s", bundle.Zone, target)
	}
	if bundle.Network == nil {
		t.Fatalf("bundle network is nil")
	}
	if len(bundle.Network.Zones) != len(wantZones) {
		t.Fatalf("bundle zones = %d, want %d: %#v", len(bundle.Network.Zones), len(wantZones), bundle.Network.Zones)
	}
	for _, path := range wantZones {
		zs := bundle.Network.Zones[path]
		if zs == nil || zs.Authority == nil {
			t.Fatalf("bundle missing authority for %s", path)
		}
		if len(zs.Records) != 0 {
			t.Fatalf("bundle zone %s carried records: %#v", path, zs.Records)
		}
		if len(zs.RecordHistory) != 0 {
			t.Fatalf("bundle zone %s carried record history: %#v", path, zs.RecordHistory)
		}
		if len(zs.Delegations) != 0 {
			t.Fatalf("bundle zone %s carried delegation table: %#v", path, zs.Delegations)
		}
		if path == zone.RootZone {
			if len(zs.ParentProof) != 0 {
				t.Fatalf("root bundle zone carried parent proof: %#v", zs.ParentProof)
			}
			continue
		}
		if len(zs.ParentProof) != 1 || zs.ParentProof[0].ZoneName != path {
			t.Fatalf("bundle zone %s parent proof = %#v, want direct proof", path, zs.ParentProof)
		}
	}
}

func writeConfig(t *testing.T, path string, dataDir string) {
	t.Helper()
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	content := "data_dir: " + dataDir + "\ngossip:\n  listen_addr: 127.0.0.1:0\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}
