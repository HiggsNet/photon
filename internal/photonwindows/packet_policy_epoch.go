package photonwindows

import (
	"context"
	"math"
	"net"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

const packetPolicyMaxAge = time.Minute

// packetPolicyDeadline bounds reuse by actual signed-policy transitions and
// a periodic refresh. Integer-second fields only change at their own boundary.
// The caller
// separately checks current snapshot/config/planner identity, clock rollback,
// the original DNS hint lifetime and mutable SA/Babel/packet gates every event.
func packetPolicyDeadline(view corestate.View, now time.Time) time.Time {
	now = now.Round(0) // wall time; monotonic elapsed time must not hide rollback
	deadline := now.Add(packetPolicyMaxAge)
	earlier := func(at time.Time) {
		at = at.Round(0)
		if at.After(now) && at.Before(deadline) {
			deadline = at
		}
	}
	atUnix := func(second int64) {
		if second != 0 {
			earlier(time.Unix(second, 0))
		}
	}
	authority := func(a *zone.ZoneAuthority) {
		if a == nil {
			return
		}
		for _, key := range a.Keys {
			atUnix(key.NotBefore)
			// Authority keys remain valid throughout their final second.
			if key.NotAfter != 0 && key.NotAfter < math.MaxInt64 {
				atUnix(key.NotAfter + 1)
			}
		}
	}
	if view.State == nil || view.State.Network == nil {
		return now
	}
	for _, zs := range view.State.Network.Zones {
		if zs == nil {
			continue
		}
		authority(zs.Authority)
		for _, revocation := range zs.Revocations {
			if revocation != nil && revocation.RevokedAt > 0 {
				atUnix(revocation.RevokedAt)
			}
		}
		if key, err := ipsec.ParseTransportKeyRecord(zs.Records[ipsec.RecordKeyTransportKey]); err == nil {
			atUnix(key.NotBefore)
			atUnix(key.NotAfter)
		}
		for _, delegation := range zs.Delegations {
			if delegation != nil {
				authority(&delegation.Authority)
			}
			if delegation != nil && delegation.ExpiresAt != nil {
				// In-memory intents may retain monotonic time. One wall-clock
				// epoch cannot bound its progress when the wall clock slows;
				// use ordinary current verification for that rare snapshot.
				if *delegation.ExpiresAt != delegation.ExpiresAt.Round(0) {
					return now
				}
				earlier(*delegation.ExpiresAt)
			}
		}
		for _, proof := range zs.ParentProof {
			if proof != nil {
				authority(&proof.Authority)
			}
			if proof != nil && proof.ExpiresAt != nil {
				if *proof.ExpiresAt != proof.ExpiresAt.Round(0) {
					return now
				}
				earlier(*proof.ExpiresAt)
			}
		}
		// Read the canonical resolver's actual expiration, including its
		// time.Duration arithmetic. A TTL may wrap into a sub-second expiry;
		// reconstructing it with integer seconds would miss that transition.
		if addresses, err := ipsec.ParseAddressRecord(zs.Records[ipsec.RecordKeyAddresses]); err == nil {
			candidates, err := ipsec.ResolveAddressCandidates(context.Background(), addresses, now, ipsec.AddressCandidateOptions{AllowPrivateLocal: true, DNSResolver: packetDeadlineResolver{}})
			if err == nil {
				for _, candidate := range candidates {
					if !candidate.ExpiresAt.IsZero() {
						// Contacts remain valid at equality: expiry uses After.
						earlier(candidate.ExpiresAt.Add(time.Nanosecond))
					}
				}
			}
		}
		if ports, err := ipsec.ParsePortRecord(zs.Records[ipsec.RecordKeyPorts]); err == nil {
			for _, port := range ipsec.PortAdvertisements(ports, now) {
				if !port.ValidUntil.IsZero() {
					earlier(port.ValidUntil.Add(time.Nanosecond))
				}
			}
		}
	}
	return deadline
}

// Expiration is independent of the DNS answer. Supply both documentation
// address families so the canonical resolver exposes every DNS-only lease;
// this performs no network I/O and never supplies a real gateway contact.
type packetDeadlineResolver struct{}

func (packetDeadlineResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return []net.IPAddr{{IP: net.IPv4(192, 0, 2, 1)}, {IP: net.ParseIP("2001:db8::1")}}, nil
}
