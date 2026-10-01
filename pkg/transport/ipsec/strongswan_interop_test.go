package ipsec

import (
	"context"
	"fmt"
	"testing"
	"time"
)

type strongSwanInteropCase struct {
	algorithm string
	ipv4      bool
	candidate bool
	rekey     bool
}

// The candidate models a prospective client proposal, not a Windows IKE
// implementation. The responder always uses Photon's unchanged generator.
func TestStrongSwanAlgorithmInteropSmoke(t *testing.T) {
	for _, candidate := range []bool{false, true} {
		for _, ipv4 := range []bool{false, true} {
			t.Run(fmt.Sprintf("candidate=%t/ipv4=%t", candidate, ipv4), func(t *testing.T) {
				runStrongSwanBringup(t, strongSwanInteropCase{
					algorithm: AlgorithmEd25519, candidate: candidate, ipv4: ipv4, rekey: true,
				})
			})
		}
	}
}

func loadInteropCandidate(t *testing.T, ctx context.Context, driver *StrongSwanDriver, spec TransportLinkSpec) {
	t.Helper()
	msg, err := driver.buildLoadConnMessage(spec)
	if err != nil {
		t.Fatal(err)
	}
	conn := msg[spec.TransportID].(map[string]any)
	conn["proposals"] = []string{"aes128-sha256-prfsha256-ecp256"}
	child := conn["children"].(map[string]any)[ChildSAName(spec)].(map[string]any)
	// 5.9 defaults omit separate CHILD KE; newer defaults can negotiate PFS.
	child["esp_proposals"] = []string{"aes128gcm16-ecp256-none-noesn"}
	if response, err := driver.VICI.Call(ctx, "load-conn", msg); err != nil || stringValue(response["success"]) != "yes" {
		t.Fatalf("load candidate: %v, response=%v", err, response)
	}
}

type interopSA struct {
	ikeID, childID uint64
	ike, child     string
	spiIn, spiOut  string
}

func readInteropSA(ctx context.Context, client *GoviciClient, name string) (interopSA, error) {
	events, err := client.CallStreaming(ctx, "list-sas", "list-sa", map[string]any{"ike": name})
	if err != nil {
		return interopSA{}, err
	}
	var latest interopSA
	for _, event := range events {
		for _, value := range event {
			ike, ok := value.(map[string]any)
			if !ok || stringValue(ike["state"]) != "ESTABLISHED" {
				continue
			}
			children, _ := ike["child-sas"].(map[string]any)
			for _, value := range children {
				child, ok := value.(map[string]any)
				if !ok || stringValue(child["state"]) != "INSTALLED" {
					continue
				}
				candidate := interopSA{
					ikeID: uint64Value(ike["uniqueid"]), childID: uint64Value(child["uniqueid"]),
					ike:   fmt.Sprintf("%s-%s/%s/%s/%s", ike["encr-alg"], ike["encr-keysize"], ike["integ-alg"], ike["prf-alg"], ike["dh-group"]),
					child: fmt.Sprintf("%s-%s/KE=%s", child["encr-alg"], child["encr-keysize"], stringValue(child["dh-group"])),
					spiIn: stringValue(child["spi-in"]), spiOut: stringValue(child["spi-out"]),
				}
				if candidate.ikeID > latest.ikeID || (candidate.ikeID == latest.ikeID && candidate.childID > latest.childID) {
					latest = candidate
				}
			}
		}
	}
	return latest, nil
}

func verifyInteropRekeys(t *testing.T, ctx context.Context, a, b *GoviciClient, specA, specB TransportLinkSpec, candidate bool, ping func()) {
	t.Helper()
	read := func() (interopSA, interopSA) {
		t.Helper()
		left, err := readInteropSA(ctx, a, specA.TransportID)
		if err != nil {
			t.Fatal(err)
		}
		right, err := readInteropSA(ctx, b, specB.TransportID)
		if err != nil {
			t.Fatal(err)
		}
		return left, right
	}
	check := func(left, right interopSA) {
		t.Helper()
		if left.ikeID == 0 || right.ikeID == 0 || left.childID == 0 || right.childID == 0 ||
			left.spiIn == "" || left.spiOut == "" || left.spiIn != right.spiOut || left.spiOut != right.spiIn {
			t.Fatalf("SA pair does not agree: A=%+v B=%+v", left, right)
		}
		if candidate && (left.ike != "AES_CBC-128/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/ECP_256" || left.ike != right.ike ||
			(left.child != "AES_GCM_16-128/KE=" && left.child != "AES_GCM_16-128/KE=ECP_256") || left.child != right.child) {
			t.Fatalf("candidate negotiated unexpected algorithms: A=%+v B=%+v", left, right)
		}
		t.Logf("IKE=%s ESP=%s", left.ike, left.child)
	}
	left, right := read()
	check(left, right)
	for _, side := range []struct {
		label  string
		client *GoviciClient
		spec   TransportLinkSpec
	}{{"A", a, specA}, {"B", b, specB}} {
		for _, kind := range []string{"child", "ike"} {
			beforeA, beforeB := read()
			name := side.spec.TransportID
			if kind == "child" {
				name = ChildSAName(side.spec)
			}
			if response, err := side.client.Call(ctx, "rekey", map[string]any{kind: name}); err != nil || stringValue(response["success"]) != "yes" {
				t.Fatalf("%s %s rekey: %v, response=%v", side.label, kind, err, response)
			}
			deadline := time.Now().Add(10 * time.Second)
			for {
				left, right = read()
				changed := left.ikeID != beforeA.ikeID && right.ikeID != beforeB.ikeID
				if kind == "child" {
					changed = left.childID != beforeA.childID && right.childID != beforeB.childID
				}
				if changed && left.ikeID != 0 && right.ikeID != 0 && left.childID != 0 && right.childID != 0 &&
					left.spiIn != "" && left.spiOut != "" && left.spiIn == right.spiOut && left.spiOut == right.spiIn {
					break
				}
				if time.Now().After(deadline) || ctx.Err() != nil {
					t.Fatalf("%s %s rekey did not replace both SAs: A=%+v B=%+v", side.label, kind, left, right)
				}
				time.Sleep(100 * time.Millisecond)
			}
			t.Logf("%s initiated %s rekey", side.label, kind)
			check(left, right)
			ping()
		}
	}
}
