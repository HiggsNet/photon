package main

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	"github.com/HiggsNet/photon/pkg/core/share"
)

func TestJoinRequestMatchesAdmissionAndLegacyEncoding(t *testing.T) {
	verified, _, keyPath := buildPendingAutoJoinOwners(t, t.TempDir(), "node-b.catofes.", true)
	config := &appConfig{ManagedZone: verified.ManagedZone}
	config.Identity.KeyPath = keyPath
	request, err := configuredJoinRequest(config)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := share.EncodeBase64JSON(request)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	legacy := base64.RawURLEncoding.EncodeToString(data)
	diagnosis := gossip.DiagnoseAutoJoinAdmission(verified, nil, nil, time.Unix(1000, 0))
	if encoded != legacy || encoded != diagnosis.JoinRequestB64 {
		t.Fatal("configured, diagnostic and legacy request encodings differ")
	}
	var decoded gossip.JoinRequest
	if err := share.DecodeBase64JSON(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := gossip.ValidateJoinRequest(&decoded); err != nil {
		t.Fatal(err)
	}
}
