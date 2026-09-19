package ipsec

import (
	"net/netip"
	"slices"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

// BuildProfileRecord constructs the public capability profile from declared addresses and groups.
func BuildProfileRecord(localZone zone.ZonePath, fingerprint, role string, groups []LinkGroupSpec, addresses AddressRecord) ProfileRecord {
	if role == "" {
		role = RoleBoth
	}
	return ProfileRecord{
		Version: 1, Enabled: true, Provider: ProviderStrongSwan,
		IKEIdentity: string(localZone), TransportKeyFingerprint: fingerprint,
		Role: role, AddressFamilies: addresses.PublicationFamilies(),
		PathModes: profilePathModes(groups), NAT: profileNAT(addresses),
	}
}

// BuildOverlayIntentRecords plans declarations without mutating stored records.
// Unchanged declarations retain their timestamp to avoid periodic republication.
func BuildOverlayIntentRecords(groups []LinkGroupSpec, families []string, existing map[string]*zone.Record, now time.Time) []OverlayIntentRecord {
	var out []OverlayIntentRecord
	for _, group := range groups {
		if err := group.Validate(); err != nil {
			continue
		}
		group = group.Normalized()
		var pathKeys []string
		switch group.DefaultPathMode {
		case PathModeExhaustive:
			pathKeys = []string{DefaultPathKey}
		case PathModeFamilyRedundant:
			for _, family := range families {
				if family == FamilyIPv4 || family == FamilyIPv6 {
					pathKeys = append(pathKeys, "family:"+family)
				}
			}
		}
		if len(pathKeys) == 0 {
			continue
		}
		intent := OverlayIntentRecord{
			Version: 1, OverlayID: group.ID, Provider: group.Provider,
			PathKeys: pathKeys, TunnelAddress: group.TunnelAddressSpec, UpdatedAt: now.Unix(),
		}
		if record := existing[OverlayIntentRecordKey(group.ID)]; record != nil {
			if previous, err := ParseOverlayIntentRecord(record); err == nil && previous.Version == intent.Version &&
				previous.OverlayID == intent.OverlayID && previous.Provider == intent.Provider &&
				slices.Equal(previous.PathKeys, intent.PathKeys) && previous.TunnelAddress == intent.TunnelAddress &&
				slices.Equal(previous.PolicyTags, intent.PolicyTags) {
				intent.UpdatedAt = previous.UpdatedAt
			}
		}
		out = append(out, intent)
	}
	return out
}

// PublicationFamilies returns local declaration families in discovery order, defaulting to IPv4.
// Unlike peer contact-family selection, publication combines singular and plural hints.
func (record AddressRecord) PublicationFamilies() []string {
	seen := map[string]bool{}
	var out []string
	add := func(family string) {
		if (family == FamilyIPv4 || family == FamilyIPv6) && !seen[family] {
			seen[family] = true
			out = append(out, family)
		}
	}
	for _, address := range record.Addresses {
		family := address.Family
		if family == "" {
			if parsed, err := netip.ParseAddr(address.Address); err == nil {
				if parsed.Is4() {
					family = FamilyIPv4
				} else if parsed.Is6() {
					family = FamilyIPv6
				}
			}
		}
		add(family)
		for _, family := range address.Families {
			add(family)
		}
	}
	if len(out) == 0 {
		return []string{FamilyIPv4}
	}
	return out
}

func profilePathModes(groups []LinkGroupSpec) []string {
	seen := map[string]bool{}
	var out []string
	for _, group := range groups {
		mode := group.Normalized().DefaultPathMode
		if mode != "" && !seen[mode] {
			seen[mode] = true
			out = append(out, mode)
		}
	}
	if len(out) == 0 {
		return []string{PathModeFamilyRedundant}
	}
	return out
}

func profileNAT(record AddressRecord) NATProfile {
	// Avoid claiming inbound reachability based solely on having a public
	// address. Reflector-observed public addresses or static public IPs do not
	// prove that IKE/NAT-T can be delivered to this host (firewall, DNAT,
	// provider NAT). Keep the hint conservative and default to unknown.
	hint := NATHintUnknown
	for _, address := range record.Addresses {
		if address.Reachability == ReachabilityPublic {
			hint = NATHintPublic
			break
		}
	}
	return NATProfile{Hint: hint, InboundReachable: NATReachableUnknown}
}
