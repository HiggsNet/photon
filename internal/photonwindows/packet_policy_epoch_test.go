package photonwindows

import (
	"context"
	"testing"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestPacketPolicyDeadlineDelegationAndParentProof(t *testing.T) {
	config, view, now, _ := gatewayPlanFixture(t)
	now = now.Add(100 * time.Millisecond)
	if got, want := packetPolicyDeadline(view, now), time.Unix(now.Unix()+1, 0); got != want {
		t.Fatalf("integer-second deadline = %s, want %s", got, want)
	}
	// Every zone matters: an unrelated identity or assignment can collide
	// with the selected remote origin. ParentProof is a real chain fallback.
	childDeadline, proofDeadline := now.Add(500*time.Millisecond), now.Add(200*time.Millisecond)
	view.State.Network.Zones[config.Gateway.AllowedZones[0].Parent()].Delegations[config.Gateway.AllowedZones[0]].ExpiresAt = &childDeadline
	view.State.Network.Zones[config.Gateway.AllowedZones[0]].ParentProof = []*zone.Delegation{nil, {ExpiresAt: &proofDeadline}}
	if got := packetPolicyDeadline(view, now); got != proofDeadline {
		t.Fatalf("exact ParentProof deadline = %s, want %s", got, proofDeadline)
	}
	// Past deadlines no longer change immutable policy; each exact equality
	// must already have been reevaluated before calling this helper again.
	if got := packetPolicyDeadline(view, proofDeadline); got != childDeadline {
		t.Fatalf("next delegation transition = %s, want %s", got, childDeadline)
	}
	if got := packetPolicyDeadline(corestate.View{}, now); !got.Equal(now) {
		t.Fatal("absent verified snapshot gained a reusable policy interval")
	}
}

func TestPacketPolicyDeadlineCanonicalContactExpiration(t *testing.T) {
	for _, source := range []string{ipsec.SourceManualAddress, ipsec.SourceManualDNS, ipsec.SourceDiscovery} {
		t.Run(source, func(t *testing.T) {
			config, view, now, put := gatewayPlanFixture(t)
			address := ipsec.AddressAdvertisement{ID: "wrap", Source: source, Family: ipsec.FamilyIPv4, TTLSeconds: 18446744074, LastObserved: now.Unix()}
			if source == ipsec.SourceManualAddress {
				address.Address = "192.0.2.1"
			} else {
				address.Host = "expires.example"
			}
			put(config.Gateway.AllowedZones[0], ipsec.RecordKeyAddresses, ipsec.RecordTypeAddresses, ipsec.AddressRecord{Version: 1, Addresses: []ipsec.AddressAdvertisement{address}})
			record, err := ipsec.ParseAddressRecord(view.State.Network.Zones[config.Gateway.AllowedZones[0]].Records[ipsec.RecordKeyAddresses])
			if err != nil {
				t.Fatal(err)
			}
			candidates, err := ipsec.ResolveAddressCandidates(context.Background(), record, now, ipsec.AddressCandidateOptions{AllowPrivateLocal: true, DNSResolver: packetDeadlineResolver{}})
			if err != nil || len(candidates) != 1 {
				t.Fatalf("canonical candidate = %v: %v", candidates, err)
			}
			expiry := candidates[0].ExpiresAt
			if !expiry.After(now) || !expiry.Before(now.Add(time.Second)) {
				t.Fatal("fixture must exercise an overflowed sub-second contact TTL", expiry)
			}
			if got := packetPolicyDeadline(view, now); !got.Equal(expiry.Add(time.Nanosecond)) {
				t.Fatalf("contact deadline = %s, want %s", got, expiry.Add(time.Nanosecond))
			}
			for _, at := range []time.Time{expiry.Add(-time.Nanosecond), expiry, expiry.Add(time.Nanosecond)} {
				candidates, err := ipsec.ResolveAddressCandidates(context.Background(), record, at, ipsec.AddressCandidateOptions{AllowPrivateLocal: true, DNSResolver: packetDeadlineResolver{}})
				if err != nil || (len(candidates) != 0) != !at.After(expiry) {
					t.Fatal("canonical contact equality changed", at, err)
				}
				if !packetPolicyDeadline(view, at).After(at) {
					t.Fatal("deadline failed to move past a consumed transition")
				}
			}
		})
	}
}

func TestPacketPolicyDeadlinePortEquality(t *testing.T) {
	config, view, now, put := gatewayPlanFixture(t)
	put(config.Gateway.AllowedZones[0], ipsec.RecordKeyPorts, ipsec.RecordTypePorts, ipsec.PortRecord{Version: 1, Mode: ipsec.PortModeFixed, Current: &ipsec.PortSelection{Generation: 1, IKE: ipsec.PortBinding{Advertised: 500}, NATT: ipsec.PortBinding{Advertised: 4500}, ValidUntil: now.Unix()}})
	if got := packetPolicyDeadline(view, now); got != now.Add(time.Nanosecond) {
		t.Fatalf("strict After port deadline = %s, want %s", got, now.Add(time.Nanosecond))
	}
	if got := packetPolicyDeadline(view, now.Add(time.Nanosecond)); got != now.Add(time.Second) {
		t.Fatalf("expired port left a stale transition: %s", got)
	}
}
