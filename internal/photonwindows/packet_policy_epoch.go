package photonwindows

import (
	"context"
	"net"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

// packetPolicyDeadline bounds reuse of immutable signed-policy results. Every
// integer-second check (authority keys, revocations, transport keys and Babel
// identities) is reevaluated at the next second, even without a new revision.
// Exact delegation and contact expiry can end the interval sooner. The caller
// separately checks current snapshot/config/planner identity, clock rollback,
// the original DNS hint lifetime and mutable SA/Babel/packet gates every event.
func packetPolicyDeadline(view corestate.View, now time.Time) time.Time {
	now = now.Round(0) // wall time; monotonic elapsed time must not hide rollback
	deadline := time.Unix(now.Unix(), 0).Add(time.Second)
	earlier := func(at time.Time) {
		at = at.Round(0)
		if at.After(now) && at.Before(deadline) {
			deadline = at
		}
	}
	if view.State == nil || view.State.Network == nil {
		return now
	}
	for _, zs := range view.State.Network.Zones {
		if zs == nil {
			continue
		}
		for _, delegation := range zs.Delegations {
			if delegation != nil && delegation.ExpiresAt != nil {
				earlier(*delegation.ExpiresAt)
			}
		}
		for _, proof := range zs.ParentProof {
			if proof != nil && proof.ExpiresAt != nil {
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
