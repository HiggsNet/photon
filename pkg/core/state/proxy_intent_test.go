package state

import (
	"strings"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/service"
)

func TestProxyCapabilityVersionsAndWithdrawal(t *testing.T) {
	install, _ := identityInstallFixture(t)
	store := NewStore(&VerifiedState{ManagedZone: install.ManagedZone, Network: install.Network, IdentityPrivateKey: install.IdentityPrivateKey}, nil, nil)
	now := time.Unix(1000, 0)
	value := service.ProxyCapability{Active: true, ExpiresAt: now.Add(time.Hour), SPKI: strings.Repeat("ba", 32), Address: "proxy.example:8443", Transport: service.ProxyTransport}
	put := func(record *service.ProxyCapability, expected *uint64) (LocalIntentResult, error) {
		return store.ApplyLocalIntent(t.Context(), ProxyCapabilityIntent{Mutation: service.ProxyMutation{Record: record, ExpectedVersion: expected}}, now)
	}
	first, err := put(&value, nil)
	if err != nil || first.Record.Version != 1 || first.Record.Zone != install.ManagedZone {
		t.Fatalf("initial publication: %+v, %v", first, err)
	}
	if unchanged, err := put(&value, &first.Record.Version); err != nil || unchanged.Committed {
		t.Fatalf("unchanged publication: %+v, %v", unchanged, err)
	}
	value.Address = "proxy.example:8444"
	rotated, err := put(&value, &first.Record.Version)
	if err != nil || rotated.Record.Version != 2 {
		t.Fatalf("port update: %+v, %v", rotated, err)
	}
	if _, err := put(nil, &first.Record.Version); err == nil {
		t.Fatal("a stale withdrawal replaced the current endpoint")
	}
	withdrawn, err := put(nil, &rotated.Record.Version)
	if err != nil {
		t.Fatal(err)
	}
	if parsed, err := service.ParseProxyCapability(withdrawn.Record); err != nil || parsed.Active || withdrawn.Record.Version != 3 {
		t.Fatalf("withdrawal: %+v, %v", parsed, err)
	}
}
