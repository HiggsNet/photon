package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	"github.com/HiggsNet/photon/pkg/core/share"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

func desktopTestJoinRequest(t *testing.T) (*gossip.JoinRequest, string) {
	t.Helper()
	public := make(ed25519.PublicKey, ed25519.PublicKeySize)
	for i := range public {
		public[i] = byte(i + 1)
	}
	request, err := gossip.NewJoinRequest("node-a.example.", public)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := share.EncodeBase64JSON(request)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(encoded, "=") {
		t.Fatal("shared encoder no longer produces raw URL Base64")
	}
	if _, err := base64.StdEncoding.DecodeString(encoded); err == nil {
		t.Fatal("regression fixture must require the shared unpadded decoder")
	}
	return request, encoded
}

func TestDesktopAdmissionPresentation(t *testing.T) {
	request, encoded := desktopTestJoinRequest(t)
	for _, reason := range []string{gossip.AdmissionReasonMissingZoneKey, gossip.AdmissionReasonMissingParentZone, gossip.AdmissionReasonMissingDelegation, gossip.AdmissionReasonDelegationKeyMismatch, gossip.AdmissionReasonVerifyDelegationFailed, gossip.AdmissionReasonNoBootstrapSync, gossip.AdmissionReasonWaitingForAdoption, "future_reason"} {
		view := desktopAdmissionPresentation(gossip.AdmissionDiagnosis{Pending: true, ManagedZone: request.Zone, Reason: reason, JoinRequestB64: encoded}, true)
		if !view.Pending || view.Request != encoded || !strings.Contains(view.Label, "待授权") || view.Tooltip != "Photon · 待授权" {
			t.Fatalf("pending %s lost production request/state: %+v", reason, view)
		}
		if strings.Contains(view.Label, reason) {
			t.Fatalf("raw reason code leaked into Chinese status: %s", view.Label)
		}
	}
	diagnosis := gossip.AdmissionDiagnosis{Pending: true, ManagedZone: request.Zone, Reason: gossip.AdmissionReasonMissingDelegation, JoinRequestB64: encoded}
	if got := desktopAdmissionPresentation(diagnosis, false); got.Request != "" || got.Pending {
		t.Fatalf("unavailable status retained previous request: %+v", got)
	}
	diagnosis.Pending = false
	diagnosis.Reason = gossip.AdmissionReasonAdopted
	if got := desktopAdmissionPresentation(diagnosis, true); got.Request != "" || got.Pending || !strings.Contains(got.Label, "已入网") {
		t.Fatalf("adopted status retained pending material: %+v", got)
	}
}

func TestDesktopAdmissionSharedRequestEncodings(t *testing.T) {
	request, _ := desktopTestJoinRequest(t)
	data, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	for _, encoding := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		encoded := encoding.EncodeToString(data)
		got := desktopAdmissionPresentation(gossip.AdmissionDiagnosis{Pending: true, ManagedZone: request.Zone, JoinRequestB64: encoded}, true)
		if got.Request != encoded {
			t.Fatal("shared-supported encoding was rejected or rewritten")
		}
	}
}

func TestDesktopAdmissionRejectsMalformedRequest(t *testing.T) {
	request, encoded := desktopTestJoinRequest(t)
	unsupported := *request
	unsupported.Version = 2
	shortKey := *request
	shortKey.PublicKey = shortKey.PublicKey[:1]
	root := *request
	root.Zone = zone.RootZone
	invalid := []string{"bad!base64", "abc\x00def", base64.RawURLEncoding.EncodeToString([]byte("not JSON"))}
	for _, value := range []gossip.JoinRequest{unsupported, shortKey, root} {
		text, err := share.EncodeBase64JSON(value)
		if err != nil {
			t.Fatal(err)
		}
		invalid = append(invalid, text)
	}
	for _, text := range invalid {
		got := desktopAdmissionPresentation(gossip.AdmissionDiagnosis{Pending: true, ManagedZone: request.Zone, JoinRequestB64: text}, true)
		if got.Request != "" || !strings.Contains(got.Label, "请求不可用") {
			t.Fatal("invalid request was exposed for copying")
		}
	}
	got := desktopAdmissionPresentation(gossip.AdmissionDiagnosis{Pending: true, ManagedZone: "other.example.", JoinRequestB64: encoded}, true)
	if got.Request != "" {
		t.Fatal("request for another managed zone was exposed")
	}
}

func TestDesktopAdmissionRequestIsBoundedAndComplete(t *testing.T) {
	request, _ := desktopTestJoinRequest(t)
	data, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	// JSON permits trailing whitespace. Keep a real validated request while
	// exercising the encoded size boundary rather than testing random bytes.
	for _, decodedSize := range []int{desktopJoinRequestLimit*3/4 - 1, desktopJoinRequestLimit * 3 / 4} {
		padded := append(append([]byte(nil), data...), []byte(strings.Repeat(" ", decodedSize-len(data)))...)
		encoded := base64.RawURLEncoding.EncodeToString(padded)
		got := desktopAdmissionPresentation(gossip.AdmissionDiagnosis{Pending: true, ManagedZone: request.Zone, JoinRequestB64: encoded}, true)
		if got.Request != encoded {
			t.Fatal("bounded production-shaped request was truncated or rejected")
		}
	}
	tooLarge := strings.Repeat("a", desktopJoinRequestLimit+1)
	if got := desktopAdmissionPresentation(gossip.AdmissionDiagnosis{Pending: true, ManagedZone: request.Zone, JoinRequestB64: tooLarge}, true); got.Request != "" {
		t.Fatal("oversized request was exposed")
	}
}
