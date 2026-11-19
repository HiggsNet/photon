package state

import (
	"encoding/base64"
	"reflect"
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

func TestProxyRenewalOnlyExtendsMatchingActiveCapability(t *testing.T) {
	install, _ := identityInstallFixture(t)
	store := NewStore(&VerifiedState{ManagedZone: install.ManagedZone, Network: install.Network, IdentityPrivateKey: install.IdentityPrivateKey}, nil, nil)
	now := time.Unix(1000, 0).UTC()
	lifetime := time.Hour
	value := service.ProxyCapability{
		Active: true, ExpiresAt: now.Add(lifetime), SPKI: strings.Repeat("ba", 32),
		Endpoints: map[string]string{"public-v4": "proxy.example:24400"}, Transport: service.ProxyTransport,
		DelegationKey: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	}
	apply := func(t *testing.T, record *service.ProxyCapability, renew bool, at time.Time) LocalIntentResult {
		t.Helper()
		got, err := store.ApplyLocalIntent(t.Context(), ProxyCapabilityIntent{
			Mutation: service.ProxyMutation{Record: record}, Renew: renew,
		}, at)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	if got := apply(t, &value, true, now); got.Committed || got.Record != nil {
		t.Fatalf("renewal created an unpublished capability: %+v", got)
	}
	if got := apply(t, &value, false, now); !got.Committed || got.Record.Version != 1 {
		t.Fatalf("initial publication: %+v", got)
	}
	early := value
	early.ExpiresAt = value.ExpiresAt.Add(time.Minute)
	if got := apply(t, &early, true, now.Add(time.Minute)); got.Committed || got.Record == nil || got.Record.Version != 1 {
		t.Fatalf("early renewal changed the record: %+v", got)
	}

	due := now.Add(31 * time.Minute)
	renewal := value
	renewal.ExpiresAt = due.Add(lifetime)
	for name, change := range map[string]func(*service.ProxyCapability){
		"endpoint":       func(r *service.ProxyCapability) { r.Endpoints = map[string]string{"public-v4": "proxy.example:24401"} },
		"role":           func(r *service.ProxyCapability) { r.Relay = true },
		"certificate":    func(r *service.ProxyCapability) { r.SPKI = strings.Repeat("ab", 32) },
		"delegation key": func(r *service.ProxyCapability) { r.DelegationKey = "" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := renewal
			change(&candidate)
			if got := apply(t, &candidate, true, due); got.Committed || got.Record != nil {
				t.Fatalf("renewal replaced the current capability: %+v", got)
			}
		})
	}
	got := apply(t, &renewal, true, due)
	parsed, err := service.ParseProxyCapability(got.Record)
	if err != nil || !got.Committed || got.Record.Version != 2 || !reflect.DeepEqual(parsed, renewal) {
		t.Fatalf("renewal: record %+v, parsed %+v, error %v", got, parsed, err)
	}
	if got := apply(t, &renewal, true, due); got.Committed || got.Record == nil || got.Record.Version != 2 {
		t.Fatalf("retry changed the record again: %+v", got)
	}

	afterExpiry := renewal
	afterExpiry.ExpiresAt = renewal.ExpiresAt.Add(lifetime)
	if got := apply(t, &afterExpiry, true, renewal.ExpiresAt); got.Committed || got.Record != nil {
		t.Fatalf("renewal restored an expired capability: %+v", got)
	}
	if got := apply(t, nil, false, due.Add(time.Minute)); !got.Committed || got.Record.Version != 3 {
		t.Fatalf("withdrawal: %+v", got)
	}
	if got := apply(t, &renewal, true, due.Add(time.Minute)); got.Committed || got.Record != nil {
		t.Fatalf("renewal restored a withdrawn capability: %+v", got)
	}
}
