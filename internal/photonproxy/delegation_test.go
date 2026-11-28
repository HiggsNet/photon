package photonproxy

import (
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/service"
)

func TestDelegationBindsRelayExitAndListenerLifetime(t *testing.T) {
	const issuer, exit, relay = zone.ZonePath("a.example."), zone.ZonePath("c.example."), zone.ZonePath("b.example.")
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	bound := delegationBinding{relay: relay, exit: exit, endpoint: "proxy.example:8443", target: "127.0.0.1:22"}
	access := &zoneAccess{
		allowed: []zone.ZonePath{issuer}, delegates: []zone.ZonePath{relay, "another.example."},
		directory: &proxyDirectory{view: service.ProxyDirectory{
			ManagedZone: exit, ValidUntil: now.Add(time.Minute), Peers: map[zone.ZonePath]service.ProxyCapability{
				issuer: {Active: true, DelegationKey: delegationEncoding.EncodeToString(public), ExpiresAt: now.Add(time.Hour)},
				exit:   {Active: true, Address: bound.endpoint, ExpiresAt: now.Add(time.Hour)},
			},
		}},
	}
	verifier := &delegationVerifier{endpoint: bound.endpoint, started: now.Add(-time.Minute)}
	header, err := issueDelegation(private, issuer, bound, "", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := verifier.verify(access, "another.example.", bound.target, header, now); err == nil {
		t.Fatal("the authorization could be moved to another permitted relay")
	}
	if _, _, err := verifier.verify(access, relay, bound.target, header, now.Add(delegationLifetime)); err == nil {
		t.Fatal("an expired grant was accepted")
	}
	restarted := &delegationVerifier{endpoint: bound.endpoint, started: now.Add(time.Millisecond)}
	if _, _, err := restarted.verify(access, relay, bound.target, header, now.Add(2*time.Millisecond)); err == nil {
		t.Fatal("the old listener's grant worked against a restarted listener")
	}
	if _, _, err := verifier.verify(access, relay, bound.target, header, now); err != nil {
		t.Fatalf("false verification attempts consumed the valid grant: %v", err)
	}
	if _, _, _, err := decodeDelegation(strings.Repeat("A", delegationHeaderLimit+1)); err == nil {
		t.Fatal("an oversized authorization header was accepted")
	}
}
