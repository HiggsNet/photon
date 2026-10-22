//go:build linux

package photonwindows

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	"github.com/HiggsNet/photon/pkg/core/share"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

// Public request/bundle checks only. This helper never opens the live Bolt file
// or signs; the production daemon's control endpoint remains the sole writer.
func TestPrepareWindowsAutojoinRequests(t *testing.T) {
	dir := os.Getenv("PHOTON_WINDOWS_FULL_DAEMON_FIXTURE")
	if dir == "" || os.Getenv("PHOTON_WINDOWS_AUTOJOIN_SMOKE") != "1" {
		t.Skip("isolated auto-join fixture only")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("requires disposable container")
	}
	data, err := os.ReadFile(filepath.Join(dir, "autojoin-request.b64"))
	if err != nil {
		t.Fatal(err)
	}
	var request gossip.JoinRequest
	if err := share.DecodeBase64JSON(string(data), &request); err != nil {
		t.Fatal(err)
	}
	if err := gossip.ValidateJoinRequest(&request); err != nil || request.Zone != "node-a.catofes." {
		t.Fatal("unexpected fixture request", err)
	}
	wrong, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	clear(private)
	if bytes.Equal(wrong, request.PublicKey) {
		t.Fatal("wrong-key request accidentally matches")
	}
	wrongRequest, err := gossip.NewJoinRequest(request.Zone, wrong)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := share.EncodeBase64JSON(wrongRequest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "autojoin-wrong-request.b64"), []byte(encoded), 0600); err != nil {
		t.Fatal(err)
	}
	public, _ := json.Marshal(request)
	if err := os.WriteFile(filepath.Join(dir, "autojoin-request.json"), public, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyWindowsAutojoinBundle(t *testing.T) {
	dir := os.Getenv("PHOTON_WINDOWS_FULL_DAEMON_FIXTURE")
	if dir == "" || os.Getenv("PHOTON_WINDOWS_AUTOJOIN_SMOKE") != "1" {
		t.Skip("isolated auto-join fixture only")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("requires disposable container")
	}
	read := func(name string, out any) {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := share.DecodeBase64JSON(string(b), out); err != nil {
			t.Fatal(err)
		}
	}
	var request gossip.JoinRequest
	var bundle share.JoinBundle
	read("autojoin-request.b64", &request)
	read("autojoin-correct-bundle.b64", &bundle)
	configBytes, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var config Config
	if err := json.Unmarshal(configBytes, &config); err != nil {
		t.Fatal(err)
	}
	if bundle.Zone != request.Zone || !bytes.Equal(bundle.RootPublicKey, config.TrustedRootPublicKey) {
		t.Fatal("bundle zone/root does not match fixture")
	}
	if err := photoncrypto.VerifyPinnedRoot(bundle.Network, config.TrustedRootPublicKey); err != nil {
		t.Fatal(err)
	}
	if err := photoncrypto.VerifyChain(bundle.Network, request.Zone, time.Now()); err != nil {
		t.Fatal(err)
	}
	zs := bundle.Network.Zones[request.Zone]
	if zs == nil || zs.Authority == nil || !zs.Authority.HasPublicKey(request.PublicKey) || zs.Authority.Epoch < 2 {
		t.Fatal("corrected delegation does not bind generated Windows identity at a newer epoch")
	}
	// Minimal join bundles carry the child's signed link in ParentProof; the
	// parent's catalog need not include its Delegations map.
	if len(zs.ParentProof) == 0 || zs.ParentProof[0] == nil || zs.ParentProof[0].ZoneName != request.Zone {
		t.Fatal("corrected bundle is missing the child's signed parent proof")
	}
	proof := zs.ParentProof[0]
	parent := bundle.Network.Zones[request.Zone.Parent()]
	if parent == nil || parent.Authority == nil {
		t.Fatal("corrected bundle is missing the parent authority")
	}
	if err := photoncrypto.VerifyDelegation(proof, parent.Authority, request.Zone.Parent(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if proof.AuthorityEpoch != zs.Authority.Epoch || !bytes.Equal(proof.AuthorityHash, photoncrypto.AuthorityHash(zs.Authority)) {
		t.Fatal("parent proof does not bind the corrected authority")
	}
	public, err := json.Marshal(map[string]any{"request": request, "authority": zs.Authority, "delegation": proof, "root_public_key": bundle.RootPublicKey, "chain_verified": true})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "autojoin-authority.json"), public, 0600); err != nil {
		t.Fatal(err)
	}
}
