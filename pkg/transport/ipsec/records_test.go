package ipsec

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

func TestParseIPsecRecordsAndBuildContactPoints(t *testing.T) {
	now := time.Unix(1717171717, 0)
	profileRecord := record(t, "node-a.catofes.", RecordKeyProfile, RecordTypeProfile, ProfileRecord{
		Version:                 1,
		Enabled:                 true,
		Provider:                ProviderStrongSwan,
		IKEIdentity:             "node-a.catofes.",
		TransportKeyFingerprint: "b2",
		Role:                    RoleIn,
		AddressFamilies:         []string{FamilyIPv6, FamilyIPv4},
		PathModes:               []string{PathModeFamilyRedundant, PathModeExhaustive},
		UpdatedAt:               now.Unix(),
	})
	profile, err := ParseProfileRecord(profileRecord)
	if err != nil {
		t.Fatalf("ParseProfileRecord: %v", err)
	}
	if profile.IKEIdentity != "node-a.catofes." {
		t.Fatalf("IKEIdentity = %q", profile.IKEIdentity)
	}

	addressRecord := record(t, "node-a.catofes.", RecordKeyAddresses, RecordTypeAddresses, AddressRecord{
		Version: 1,
		Addresses: []AddressAdvertisement{
			{ID: "dns-main", Source: SourceManualDNS, Host: "node-a.example.com", Families: []string{FamilyIPv6, FamilyIPv4}, Priority: 90, TTLSeconds: 300},
			{ID: "manual-v6", Source: SourceManualAddress, Address: "2001:db8::10", Family: FamilyIPv6, Priority: 100, TTLSeconds: 3600},
			{ID: "old", Source: SourceReflector, Address: "203.0.113.10", Family: FamilyIPv4, Priority: 60, LastObserved: now.Add(-time.Hour).Unix(), TTLSeconds: 60},
		},
		UpdatedAt: now.Unix(),
	})
	addresses, err := ParseAddressRecord(addressRecord)
	if err != nil {
		t.Fatalf("ParseAddressRecord: %v", err)
	}
	candidates, err := ResolveAddressCandidates(context.Background(), addresses, now, AddressCandidateOptions{})
	if err != nil {
		t.Fatalf("ResolveAddressCandidates: %v", err)
	}
	if len(candidates) != 3 {
		t.Fatalf("AddressCandidates len = %d, want 3", len(candidates))
	}
	if candidates[0].ID != "manual-v6" {
		t.Fatalf("first candidate = %s, want manual-v6", candidates[0].ID)
	}

	portRecord := record(t, "node-a.catofes.", RecordKeyPorts, RecordTypePorts, PortRecord{
		Version: 1,
		Mode:    PortModeRange,
		Range:   &PortRange{From: 30000, To: 30999},
		Current: &PortSelection{
			Generation: 42,
			IKE:        PortBinding{Local: 30412, Advertised: 30412, Observed: 30412},
			NATT:       PortBinding{Local: 30413, Advertised: 30413, Observed: 30413},
			ValidUntil: now.Add(time.Hour).Unix(),
		},
		Previous: []PortSelection{{
			Generation: 41,
			IKE:        PortBinding{Advertised: 30100},
			NATT:       PortBinding{Advertised: 30101},
			ValidUntil: now.Add(10 * time.Minute).Unix(),
		}},
		UpdatedAt: now.Unix(),
	})
	ports, err := ParsePortRecord(portRecord)
	if err != nil {
		t.Fatalf("ParsePortRecord: %v", err)
	}
	points, err := ResolveContactPoints(context.Background(), addresses, ports, now, AddressCandidateOptions{
		DNSResolver: staticDNSResolver{
			"node-a.example.com": {
				{IP: net.ParseIP("2001:db8::20")},
				{IP: net.ParseIP("198.51.100.20")},
			},
		},
	})
	if err != nil {
		t.Fatalf("ResolveContactPoints: %v", err)
	}
	if len(points) != 6 {
		t.Fatalf("ContactPoints len = %d, want 6", len(points))
	}
	selected := SelectContactPointsWithOptions(points, PathModeFamilyRedundant, AddressCandidateOptions{})
	if len(selected) != 2 {
		t.Fatalf("family redundant len = %d, want 2", len(selected))
	}
	if selected[0].IKEPort != 30412 || !selected[0].Current {
		t.Fatalf("selected current port = %+v", selected[0])
	}
}

func TestResolveAddressCandidatesExpandsManualDNSRuntimeOnly(t *testing.T) {
	now := time.Unix(1717171717, 0)
	addresses := &AddressRecord{
		Version: 1,
		Addresses: []AddressAdvertisement{{
			ID:             "dns-main",
			Source:         SourceManualDNS,
			Host:           "node-a.example.com",
			Families:       []string{FamilyIPv6},
			RefreshSeconds: 30,
			Priority:       80,
			Reachability:   ReachabilityPublic,
			TTLSeconds:     300,
		}},
		UpdatedAt: now.Unix(),
	}
	candidates, err := ResolveAddressCandidates(context.Background(), addresses, now, AddressCandidateOptions{
		DNSResolver: staticDNSResolver{
			"node-a.example.com": {
				{IP: net.ParseIP("2001:db8::20")},
				{IP: net.ParseIP("198.51.100.20")},
			},
		},
	})
	if err != nil {
		t.Fatalf("ResolveAddressCandidates: %v", err)
	}
	if len(candidates) != 1 {
		t.Fatalf("candidates len = %d, want 1", len(candidates))
	}
	if candidates[0].Host != "node-a.example.com" || candidates[0].Address != "2001:db8::20" || candidates[0].Family != FamilyIPv6 {
		t.Fatalf("candidate = %+v", candidates[0])
	}
	if candidates[0].RefreshAt != now.Add(30*time.Second) {
		t.Fatalf("RefreshAt = %s", candidates[0].RefreshAt)
	}
}

func TestResolveAddressCandidatesDeterministicDespiteDNSOrder(t *testing.T) {
	now := time.Unix(1717171717, 0)
	addresses := &AddressRecord{
		Version: 1,
		Addresses: []AddressAdvertisement{{
			ID:           "dns-main",
			Source:       SourceManualDNS,
			Host:         "node-a.example.com",
			Families:     []string{FamilyIPv4},
			Priority:     80,
			Reachability: ReachabilityPublic,
			TTLSeconds:   300,
		}},
		UpdatedAt: now.Unix(),
	}
	// Resolver returns two IPv4 addresses in one order.
	first, err := ResolveAddressCandidates(context.Background(), addresses, now, AddressCandidateOptions{
		DNSResolver: staticDNSResolver{
			"node-a.example.com": {
				{IP: net.ParseIP("198.51.100.20")},
				{IP: net.ParseIP("198.51.100.10")},
			},
		},
	})
	if err != nil {
		t.Fatalf("ResolveAddressCandidates: %v", err)
	}
	// Resolver returns the same two IPv4 addresses in reverse order.
	second, err := ResolveAddressCandidates(context.Background(), addresses, now, AddressCandidateOptions{
		DNSResolver: staticDNSResolver{
			"node-a.example.com": {
				{IP: net.ParseIP("198.51.100.10")},
				{IP: net.ParseIP("198.51.100.20")},
			},
		},
	})
	if err != nil {
		t.Fatalf("ResolveAddressCandidates: %v", err)
	}
	// After sorting resolved IPs, the first candidate should be the same
	// regardless of the order returned by the resolver.
	if len(first) != 2 || len(second) != 2 {
		t.Fatalf("unexpected candidate counts: %d / %d", len(first), len(second))
	}
	if first[0].Address != second[0].Address {
		t.Fatalf("first candidate depends on DNS order: %q vs %q", first[0].Address, second[0].Address)
	}
}

func TestContactPointSelectionFallsBackFromBackoffCurrentPort(t *testing.T) {
	now := time.Unix(1717171717, 0)
	addresses := &AddressRecord{
		Version: 1,
		Addresses: []AddressAdvertisement{{
			ID:           "public-v4",
			Source:       SourceManualAddress,
			Address:      "198.51.100.20",
			Family:       FamilyIPv4,
			Priority:     100,
			Reachability: ReachabilityPublic,
			TTLSeconds:   300,
		}},
		UpdatedAt: now.Unix(),
	}
	ports := &PortRecord{
		Version: 1,
		Mode:    PortModeFixed,
		Current: &PortSelection{
			Generation: 2,
			IKE:        PortBinding{Advertised: 500},
			NATT:       PortBinding{Advertised: 4500},
			ValidUntil: now.Add(time.Hour).Unix(),
		},
		Previous: []PortSelection{{
			Generation: 1,
			IKE:        PortBinding{Advertised: 1500},
			NATT:       PortBinding{Advertised: 14500},
			ValidUntil: now.Add(10 * time.Minute).Unix(),
		}},
		UpdatedAt: now.Unix(),
	}
	currentKey := ContactPoint{
		AddressID:  "public-v4",
		Address:    "198.51.100.20",
		Generation: 2,
		IKEPort:    500,
		NATTPort:   4500,
	}.Key()
	points, err := ResolveContactPoints(context.Background(), addresses, ports, now, AddressCandidateOptions{
		Now: now,
		ContactQuality: map[string]ContactPointQuality{
			currentKey: {
				Failures:     3,
				BackoffUntil: now.Add(time.Minute),
			},
		},
	})
	if err != nil {
		t.Fatalf("ResolveContactPoints: %v", err)
	}
	selected := SelectContactPointsWithOptions(points, PathModeFamilyRedundant, AddressCandidateOptions{Now: now})
	if len(selected) != 1 {
		t.Fatalf("selected len = %d, want 1", len(selected))
	}
	if selected[0].Current || selected[0].Generation != 1 || selected[0].IKEPort != 1500 {
		t.Fatalf("selected = %+v, want previous grace port", selected[0])
	}
	current := points[1]
	if current.Failures != 3 || current.RankReason == "" {
		t.Fatalf("current quality not annotated: %+v", current)
	}
}

func TestResolveAddressCandidatesAppliesSourcePolicyAndDiscoveryDNS(t *testing.T) {
	now := time.Unix(1717171717, 0)
	addresses := &AddressRecord{
		Version: 1,
		Addresses: []AddressAdvertisement{
			{ID: "local-private", Source: SourceLocal, Address: "192.168.8.10", Priority: 100, TTLSeconds: 300},
			{ID: "manual-low", Source: SourceManualAddress, Address: "203.0.113.10", Priority: 1, TTLSeconds: 300},
			{ID: "discovery-host", Source: SourceDiscovery, Host: "disc.example.com", Families: []string{FamilyIPv4}, Priority: 50, TTLSeconds: 300},
			{ID: "reflector", Source: SourceReflector, Address: "198.51.100.30", Priority: 90, TTLSeconds: 300},
		},
		UpdatedAt: now.Unix(),
	}
	candidates, err := ResolveAddressCandidates(context.Background(), addresses, now, AddressCandidateOptions{
		DNSResolver: staticDNSResolver{
			"disc.example.com": {{IP: net.ParseIP("198.51.100.20")}},
		},
		SourceOrder:    []string{SourceDiscovery, SourceReflector, SourceManualAddress},
		AllowedSources: []string{SourceManualAddress, SourceDiscovery, SourceReflector, SourceLocal},
	})
	if err != nil {
		t.Fatalf("ResolveAddressCandidates: %v", err)
	}
	if len(candidates) != 3 {
		t.Fatalf("candidates len = %d, want 3: %+v", len(candidates), candidates)
	}
	if candidates[0].ID != "discovery-host" || candidates[0].Address != "198.51.100.20" {
		t.Fatalf("first candidate = %+v", candidates[0])
	}
	if candidates[1].ID != "reflector" || candidates[2].ID != "manual-low" {
		t.Fatalf("source ordering not applied: %+v", candidates)
	}
}

func TestResolveAddressCandidatesCanAllowLocalPrivateForLAN(t *testing.T) {
	now := time.Unix(1717171717, 0)
	addresses := &AddressRecord{
		Version: 1,
		Addresses: []AddressAdvertisement{{
			ID:         "local-private",
			Source:     SourceLocal,
			Address:    "192.168.8.10",
			TTLSeconds: 300,
		}},
		UpdatedAt: now.Unix(),
	}
	candidates, err := ResolveAddressCandidates(context.Background(), addresses, now, AddressCandidateOptions{AllowPrivateLocal: true})
	if err != nil {
		t.Fatalf("ResolveAddressCandidates: %v", err)
	}
	if len(candidates) != 1 || candidates[0].ID != "local-private" {
		t.Fatalf("local private candidate = %+v", candidates)
	}
}

func TestTransportKeyAndLinkSpec(t *testing.T) {
	now := time.Unix(1717171717, 0)
	keyRecord := record(t, "node-a.catofes.", RecordKeyTransportKey, RecordTypeTransportKey, TransportKeyRecord{
		Version:     1,
		Kind:        TransportKeyRawPublicKey,
		Algorithm:   AlgorithmEd25519,
		PublicKey:   "base64",
		Fingerprint: "b2",
		NotBefore:   now.Unix(),
		NotAfter:    now.Add(time.Hour).Unix(),
		UpdatedAt:   now.Unix(),
	})
	key, err := ParseTransportKeyRecord(keyRecord)
	if err != nil {
		t.Fatalf("ParseTransportKeyRecord: %v", err)
	}
	records := &NodeRecords{
		Zone: "node-a.catofes.",
		Profile: &ProfileRecord{
			Version:                 1,
			Enabled:                 true,
			Provider:                ProviderStrongSwan,
			IKEIdentity:             "node-a.catofes.",
			TransportKeyFingerprint: "b2",
			Role:                    RoleIn,
			AddressFamilies:         []string{FamilyIPv4},
			PathModes:               []string{PathModeFamilyRedundant},
		},
		TransportKey: key,
	}
	spec, err := NewTransportLinkSpec("node-b.catofes.", "node-a.catofes.", "ipsec-main", "", records, nil)
	if err != nil {
		t.Fatalf("NewTransportLinkSpec: %v", err)
	}
	if spec.Provider != ProviderStrongSwan || spec.AuthRef != "b2" {
		t.Fatalf("spec = %+v", spec)
	}
	if spec.XFRMIfID == 0 {
		t.Fatalf("XFRMIfID is zero")
	}
	if len(spec.InterfaceName) > 15 {
		t.Fatalf("interface name %q exceeds Linux limit", spec.InterfaceName)
	}
	again, err := NewTransportLinkSpec("node-b.catofes.", "node-a.catofes.", "ipsec-main", "", records, nil)
	if err != nil {
		t.Fatalf("NewTransportLinkSpec(second): %v", err)
	}
	if spec.TransportID != again.TransportID || spec.XFRMIfID != again.XFRMIfID || spec.InterfaceName != again.InterfaceName {
		t.Fatalf("stable derivation changed: %+v vs %+v", spec, again)
	}
}

func TestLinkGroupSpecDefaultsAndTunnelAddresses(t *testing.T) {
	group := LinkGroupSpec{
		ID:                "ipsec-main",
		Name:              "main ipsec overlay",
		NetNS:             NetNSSpec{Kind: "name", Name: "photon-ipsec"},
		TunnelAddressPool: netip.MustParsePrefix("fd00:1234::/120"),
		Reconcile: ReconcilePolicy{
			IntervalSeconds: 30,
			Backoff:         BackoffPolicy{InitialSeconds: 1, MaxSeconds: 60},
		},
	}
	if err := group.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	normalized := group.Normalized()
	if normalized.Provider != ProviderStrongSwan {
		t.Fatalf("provider = %q", normalized.Provider)
	}
	if normalized.DefaultPathMode != PathModeFamilyRedundant {
		t.Fatalf("path mode = %q", normalized.DefaultPathMode)
	}
	if normalized.MaxPeers != 0 {
		t.Fatalf("max peers = %d, want unlimited default", normalized.MaxPeers)
	}
	if normalized.Reconcile.RotateRetentionSeconds != 3600 {
		t.Fatalf("rotate retention = %d, want 3600", normalized.Reconcile.RotateRetentionSeconds)
	}
	if len(normalized.AddressSourceOrder) != len(defaultAddressSourceOrder) {
		t.Fatalf("address source order = %+v", normalized.AddressSourceOrder)
	}
	if normalized.NetNS.Target() != "photon-ipsec" || normalized.NetNS.Create {
		t.Fatalf("netns = %+v", normalized.NetNS)
	}
	local, peer, err := group.TunnelAddresses(1)
	if err != nil {
		t.Fatalf("TunnelAddresses: %v", err)
	}
	if local.String() != "fd00:1234::3" || peer.String() != "fd00:1234::4" {
		t.Fatalf("tunnel addresses = %s, %s", local, peer)
	}
}

func TestNewTransportLinkSpecForGroupInheritsGroupBoundary(t *testing.T) {
	group := LinkGroupSpec{
		ID:                "ipsec-main",
		Provider:          ProviderStrongSwan,
		NetNS:             NetNSSpec{Kind: "path", Path: "/run/netns/photon-ipsec"},
		TunnelAddressPool: netip.MustParsePrefix("10.44.0.0/29"),
		MaxPeers:          16,
		MaxLinksPerPeer:   2,
	}
	records := &NodeRecords{
		Zone: "node-a.catofes.",
		Profile: &ProfileRecord{
			Version:                 1,
			Enabled:                 true,
			Provider:                ProviderStrongSwan,
			IKEIdentity:             "node-a.catofes.",
			TransportKeyFingerprint: "b2",
			Role:                    RoleIn,
			AddressFamilies:         []string{FamilyIPv4},
			PathModes:               []string{PathModeFamilyRedundant},
		},
		TransportKey: &TransportKeyRecord{
			Version:     1,
			Kind:        TransportKeyRawPublicKey,
			Algorithm:   AlgorithmEd25519,
			PublicKey:   "base64",
			Fingerprint: "b2",
		},
	}
	spec, err := NewTransportLinkSpecForGroup("node-b.catofes.", "node-a.catofes.", group, records, nil, 0)
	if err != nil {
		t.Fatalf("NewTransportLinkSpecForGroup: %v", err)
	}
	if spec.OverlayID != group.ID || spec.Provider != ProviderStrongSwan {
		t.Fatalf("spec group fields = %+v", spec)
	}
	if spec.PathMode != PathModeFamilyRedundant {
		t.Fatalf("spec planner fields = %+v", spec)
	}
	if spec.NetNS != "/run/netns/photon-ipsec" {
		t.Fatalf("NetNS = %q", spec.NetNS)
	}
	if spec.LocalTunnelAddr.String() != "10.44.0.2" || spec.PeerTunnelAddr.String() != "10.44.0.1" {
		t.Fatalf("tunnel addresses = %s, %s", spec.LocalTunnelAddr, spec.PeerTunnelAddr)
	}
}

func TestLinkGroupSpecDefaultsToCreatedH2NetNS(t *testing.T) {
	group := LinkGroupSpec{
		ID: "ipsec-main",
	}
	if err := group.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	normalized := group.Normalized()
	if normalized.NetNS.Kind != NetNSName || normalized.NetNS.Name != DefaultNetNSName || !normalized.NetNS.Create {
		t.Fatalf("NetNS default = %+v", normalized.NetNS)
	}
	spec, err := NewTransportLinkSpecForGroup("node-b.catofes.", "node-a.catofes.", group, validNodeRecords(), nil, 0)
	if err != nil {
		t.Fatalf("NewTransportLinkSpecForGroup: %v", err)
	}
	if spec.NetNS != DefaultNetNSName {
		t.Fatalf("spec NetNS = %q, want %q", spec.NetNS, DefaultNetNSName)
	}
}

func TestLinkGroupSpecValidationRejectsAmbiguousNetNSAndTinyPool(t *testing.T) {
	group := LinkGroupSpec{
		ID:    "ipsec-main",
		NetNS: NetNSSpec{Kind: NetNSHost, Create: true},
	}
	if err := group.Validate(); err == nil {
		t.Fatalf("Validate should reject host netns with create")
	}
	group = LinkGroupSpec{
		ID:                "ipsec-main",
		TunnelAddressPool: netip.MustParsePrefix("192.0.2.0/31"),
	}
	if _, _, err := group.TunnelAddresses(0); err == nil {
		t.Fatalf("TunnelAddresses should reject a pool without two usable offsets")
	}
	group = LinkGroupSpec{
		ID:              "ipsec-main",
		DefaultPathMode: "single-best",
	}
	if err := group.Validate(); err == nil {
		t.Fatalf("Validate should reject unsupported path mode")
	}
}

func TestDeriveTunnelAddressesLinkLocalMirror(t *testing.T) {
	group := LinkGroupSpec{
		ID: "ipsec-main",
		TunnelAddressSpec: TunnelAddressSpec{
			Mode:   TunnelAddressDerivedLinkLocal,
			Family: FamilyIPv6,
		},
	}
	aLocal, aPeer, err := group.DeriveTunnelAddresses("node-a.catofes.", "node-b.catofes.", 0)
	if err != nil {
		t.Fatalf("derive A: %v", err)
	}
	bLocal, bPeer, err := group.DeriveTunnelAddresses("node-b.catofes.", "node-a.catofes.", 0)
	if err != nil {
		t.Fatalf("derive B: %v", err)
	}
	if aLocal != bPeer || aPeer != bLocal {
		t.Fatalf("addresses not mirrored: A=%s/%s B=%s/%s", aLocal, aPeer, bLocal, bPeer)
	}
	prefix := netip.MustParsePrefix("fe80::/64")
	for _, addr := range []netip.Addr{aLocal, aPeer, bLocal, bPeer} {
		if !prefix.Contains(addr) {
			t.Fatalf("address %s is not link-local", addr)
		}
		if addr == prefix.Masked().Addr() {
			t.Fatalf("address %s is subnet-router anycast", addr)
		}
	}
}

func TestDeriveTunnelAddressesDerivedPoolMirror(t *testing.T) {
	group := LinkGroupSpec{
		ID: "ipsec-main",
		TunnelAddressSpec: TunnelAddressSpec{
			Mode:   TunnelAddressDerivedPool,
			Family: FamilyIPv4,
			Pool:   netip.MustParsePrefix("10.44.0.0/24"),
		},
	}
	aLocal, aPeer, err := group.DeriveTunnelAddresses("node-a.catofes.", "node-b.catofes.", 0)
	if err != nil {
		t.Fatalf("derive A: %v", err)
	}
	bLocal, bPeer, err := group.DeriveTunnelAddresses("node-b.catofes.", "node-a.catofes.", 0)
	if err != nil {
		t.Fatalf("derive B: %v", err)
	}
	if aLocal != bPeer || aPeer != bLocal {
		t.Fatalf("addresses not mirrored: A=%s/%s B=%s/%s", aLocal, aPeer, bLocal, bPeer)
	}
	pool := netip.MustParsePrefix("10.44.0.0/24")
	for _, addr := range []netip.Addr{aLocal, aPeer, bLocal, bPeer} {
		if !pool.Contains(addr) {
			t.Fatalf("address %s not in pool", addr)
		}
		if addr == pool.Masked().Addr() || addr == netip.MustParseAddr("10.44.0.255") {
			t.Fatalf("address %s is network/broadcast", addr)
		}
	}
}

func TestDeriveTunnelAddressesDerivedPoolGenerationEpochsDoNotReuseAddresses(t *testing.T) {
	group := LinkGroupSpec{
		ID: "ipsec-main",
		TunnelAddressSpec: TunnelAddressSpec{
			Mode:   TunnelAddressDerivedPool,
			Family: FamilyIPv4,
			Pool:   netip.MustParsePrefix("10.44.0.0/24"),
		},
	}
	local := zone.ZonePath("node-a.catofes.")
	peer := zone.ZonePath("node-b.catofes.")
	pathKey := DefaultPathKey
	linkID := StableLinkID(local, peer, group.ID, pathKey)

	baseLocal, basePeer, err := group.DeriveTunnelAddressesForLink(local, peer, linkID, pathKey, 0, 0)
	if err != nil {
		t.Fatalf("derive base: %v", err)
	}
	stagedLocal, stagedPeer, err := group.DeriveTunnelAddressesForLink(local, peer, linkID, pathKey, 2, 0)
	if err != nil {
		t.Fatalf("derive staged: %v", err)
	}
	mirrorLocal, mirrorPeer, err := group.DeriveTunnelAddressesForLink(peer, local, linkID, pathKey, 2, 0)
	if err != nil {
		t.Fatalf("derive staged mirror: %v", err)
	}
	if stagedLocal != mirrorPeer || stagedPeer != mirrorLocal {
		t.Fatalf("staged addresses not mirrored: A=%s/%s B=%s/%s", stagedLocal, stagedPeer, mirrorLocal, mirrorPeer)
	}
	if baseLocal == stagedLocal || baseLocal == stagedPeer || basePeer == stagedLocal || basePeer == stagedPeer {
		t.Fatalf("derived-pool reused base/staged addresses: base=%s/%s staged=%s/%s", baseLocal, basePeer, stagedLocal, stagedPeer)
	}
	pool := group.TunnelAddressSpec.Pool
	broadcast := netip.MustParseAddr("10.44.0.255")
	for _, addr := range []netip.Addr{baseLocal, basePeer, stagedLocal, stagedPeer} {
		if !pool.Contains(addr) {
			t.Fatalf("address %s not in pool", addr)
		}
		if addr == pool.Masked().Addr() || addr == broadcast {
			t.Fatalf("address %s is network/broadcast", addr)
		}
	}
}

func TestDeriveTunnelAddressesDependsOnInputs(t *testing.T) {
	group := LinkGroupSpec{
		ID: "ipsec-main",
		TunnelAddressSpec: TunnelAddressSpec{
			Mode:   TunnelAddressDerivedLinkLocal,
			Family: FamilyIPv6,
		},
	}
	base, _, err := group.DeriveTunnelAddresses("node-a.catofes.", "node-b.catofes.", 0)
	if err != nil {
		t.Fatalf("base: %v", err)
	}
	group2 := group
	group2.ID = "ipsec-other"
	other, _, err := group2.DeriveTunnelAddresses("node-a.catofes.", "node-b.catofes.", 0)
	if err != nil {
		t.Fatalf("other: %v", err)
	}
	if base == other {
		t.Fatalf("overlay id change did not affect address: %s vs %s", base, other)
	}
	idx1, _, err := group.DeriveTunnelAddresses("node-a.catofes.", "node-b.catofes.", 1)
	if err != nil {
		t.Fatalf("index 1: %v", err)
	}
	if base == idx1 {
		t.Fatalf("link index change did not affect address: %s vs %s", base, idx1)
	}
}

func TestDeriveTunnelAddressesSequentialPoolLegacy(t *testing.T) {
	group := LinkGroupSpec{
		ID:                "ipsec-main",
		TunnelAddressPool: netip.MustParsePrefix("10.44.0.0/29"),
	}
	local, peer, err := group.DeriveTunnelAddresses("node-a.catofes.", "node-b.catofes.", 0)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if local.String() != "10.44.0.1" || peer.String() != "10.44.0.2" {
		t.Fatalf("addresses = %s/%s", local, peer)
	}
}

func TestPlanApplyShowsScopedLinkLocalAddress(t *testing.T) {
	spec := TransportLinkSpec{
		TransportID:     "ipsec-1",
		InterfaceName:   "phx1234",
		XFRMIfID:        1234,
		NetNS:           "photontesth2",
		LocalTunnelAddr: netip.MustParseAddr("fe80::1"),
		PeerTunnelAddr:  netip.MustParseAddr("fe80::2"),
	}
	plan := PlanApply(spec, NetNSSpec{Kind: NetNSName, Name: "photontesth2", Create: true})
	var assign *ApplyOperation
	for i := range plan.Operations {
		if plan.Operations[i].Action == "assign_address" {
			assign = &plan.Operations[i]
			break
		}
	}
	if assign == nil {
		t.Fatalf("assign_address operation missing: %+v", plan.Operations)
	}
	if !strings.Contains(assign.Detail, "fe80::1%phx1234") {
		t.Fatalf("assign_address detail %q missing scoped link-local address", assign.Detail)
	}
	if !strings.Contains(assign.Detail, "netns=photontesth2") {
		t.Fatalf("assign_address detail %q missing netns scope", assign.Detail)
	}
}

func TestGenerateTransportKeyRecordUsesIndependentEd25519Key(t *testing.T) {
	now := time.Unix(1717171717, 0)
	zonePub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(zone): %v", err)
	}
	key, record, err := GenerateTransportKeyRecord("", now, time.Hour, zonePub)
	if err != nil {
		t.Fatalf("GenerateTransportKeyRecord: %v", err)
	}
	if key.Algorithm != AlgorithmEd25519 || record.Algorithm != AlgorithmEd25519 {
		t.Fatalf("algorithm = %s / %s", key.Algorithm, record.Algorithm)
	}
	if len(key.PrivateKey) == 0 {
		t.Fatalf("private key is empty")
	}
	if _, err := PEMEncodePrivateKey(key.PrivateKey); err != nil {
		t.Fatalf("PEMEncodePrivateKey: %v", err)
	}
	publicKey, err := DecodeTransportPublicKey(*record)
	if err != nil {
		t.Fatalf("DecodeTransportPublicKey: %v", err)
	}
	publicPEM, err := PEMEncodePublicKey(publicKey)
	if err != nil {
		t.Fatalf("PEMEncodePublicKey: %v", err)
	}
	block, _ := pem.Decode(publicPEM)
	if block == nil {
		t.Fatalf("public key PEM did not decode")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("ParsePKIXPublicKey: %v", err)
	}
	if _, ok := parsed.(ed25519.PublicKey); !ok {
		t.Fatalf("parsed public key type = %T, want ed25519.PublicKey", parsed)
	}
	if string(publicKey) == string(zonePub) {
		t.Fatalf("transport key reused zone signing key")
	}
	if record.NotBefore != now.Unix() || record.NotAfter != now.Add(time.Hour).Unix() {
		t.Fatalf("validity = %+v", record)
	}
	if err := record.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestGenerateTransportKeyRecordSupportsECDSAP256Fallback(t *testing.T) {
	now := time.Unix(1717171717, 0)
	key, record, err := GenerateTransportKeyRecord(AlgorithmECDSAP256, now, 0)
	if err != nil {
		t.Fatalf("GenerateTransportKeyRecord(ECDSA): %v", err)
	}
	if key.Algorithm != AlgorithmECDSAP256 || record.Algorithm != AlgorithmECDSAP256 {
		t.Fatalf("algorithm = %s / %s", key.Algorithm, record.Algorithm)
	}
	if len(key.PublicKey) == 0 || len(key.PrivateKey) == 0 {
		t.Fatalf("empty key material")
	}
	if _, err := DecodeTransportPublicKey(*record); err != nil {
		t.Fatalf("DecodeTransportPublicKey: %v", err)
	}
	if record.NotAfter != 0 {
		t.Fatalf("NotAfter = %d, want 0", record.NotAfter)
	}
}

func TestTransportKeyRecordRejectsZoneSigningKeyReuseAndFingerprintMismatch(t *testing.T) {
	now := time.Unix(1717171717, 0)
	zonePub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(zone): %v", err)
	}
	if _, err := NewTransportKeyRecord(AlgorithmEd25519, zonePub, now, 0, zonePub); err == nil {
		t.Fatalf("NewTransportKeyRecord should reject zone signing key reuse")
	}
	_, record, err := GenerateTransportKeyRecord(AlgorithmEd25519, now, 0)
	if err != nil {
		t.Fatalf("GenerateTransportKeyRecord: %v", err)
	}
	record.Fingerprint = "wrong"
	if _, err := DecodeTransportPublicKey(*record); err == nil {
		t.Fatalf("DecodeTransportPublicKey should reject fingerprint mismatch")
	}
}

func TestExtractNodeRecordsSkipsRevokedZone(t *testing.T) {
	ns := zone.NewNetworkState()
	ns.Zones["node-a.catofes."] = zone.NewZoneState("node-a.catofes.", nil)
	ns.Zones["catofes."] = zone.NewZoneState("catofes.", nil)
	ns.Zones["catofes."].Revocations["node-a.catofes."] = &zone.DelegationRevocation{
		ChildZone:  "node-a.catofes.",
		ParentZone: "catofes.",
		RevokedAt:  time.Now().Unix(),
	}
	if _, err := ExtractNodeRecords(ns, "node-a.catofes.", time.Now()); err == nil {
		t.Fatalf("ExtractNodeRecords should reject revoked peer")
	}
}

func TestShouldInitiateBidirectionalTieBreak(t *testing.T) {
	if InitiatorRoleForPeer("node-a.catofes.", "node-b.catofes.", RoleBoth, RoleBoth) != InitiatorRolePrimary {
		t.Fatalf("node-a should initiate toward node-b")
	}
	if InitiatorRoleForPeer("node-b.catofes.", "node-a.catofes.", RoleBoth, RoleBoth) == InitiatorRolePrimary {
		t.Fatalf("node-b should not initiate toward node-a")
	}
	if InitiatorRoleForPeer("node-a.catofes.", "node-b.catofes.", RoleBoth, RoleOut) == InitiatorRolePrimary {
		t.Fatalf("role=both should not initiate toward role=out")
	}
}

func TestDryRunDriverRecordsApplyOrderInputs(t *testing.T) {
	driver := &DryRunDriver{}
	spec := TransportLinkSpec{TransportID: "ipsec-1", InterfaceName: "phx1"}
	if err := driver.EnsureNamespace(context.Background(), NetNSSpec{}); err != nil {
		t.Fatalf("EnsureNamespace: %v", err)
	}
	if err := driver.LoadConnection(context.Background(), spec); err != nil {
		t.Fatalf("LoadConnection: %v", err)
	}
	if err := driver.EnsureInterface(context.Background(), spec); err != nil {
		t.Fatalf("EnsureInterface: %v", err)
	}
	if err := driver.AssignAddress(context.Background(), spec, "fd00::1/64"); err != nil {
		t.Fatalf("AssignAddress: %v", err)
	}
	if len(driver.Namespaces) != 1 || len(driver.Connections) != 1 || len(driver.Interfaces) != 1 || len(driver.Addresses) != 1 {
		t.Fatalf("driver = %+v", driver)
	}
	if driver.Namespaces[0].Name != DefaultNetNSName || !driver.Namespaces[0].Create {
		t.Fatalf("namespace = %+v", driver.Namespaces[0])
	}
}

func TestApplyTransportLinkRecordsAuditablePlanAndOrder(t *testing.T) {
	driver := &DryRunDriver{}
	spec := TransportLinkSpec{
		LocalZone:       "node-a.catofes.",
		PeerZone:        "node-b.catofes.",
		TransportID:     "ipsec-1",
		InterfaceName:   "phx1",
		XFRMIfID:        42,
		NetNS:           DefaultNetNSName,
		LocalTunnelAddr: netip.MustParseAddr("fd00:1234::1"),
	}
	plan, err := ApplyTransportLink(context.Background(), driver, driver, spec, NetNSSpec{})
	if err != nil {
		t.Fatalf("ApplyTransportLink: %v", err)
	}
	if len(plan.Operations) != 4 {
		t.Fatalf("plan = %+v", plan)
	}
	if plan.Operations[0].Action != "ensure_namespace" ||
		plan.Operations[1].Action != "load_connection" ||
		plan.Operations[2].Action != "ensure_interface" ||
		plan.Operations[3].Action != "assign_address" {
		t.Fatalf("operation order = %+v", plan.Operations)
	}
	if len(driver.Namespaces) != 1 || len(driver.Connections) != 1 || len(driver.Interfaces) != 1 || len(driver.Addresses) != 1 {
		t.Fatalf("driver = %+v", driver)
	}
	if driver.Addresses[0] != "phx1=fd00:1234::1/128" {
		t.Fatalf("address assignment = %+v", driver.Addresses)
	}
}

func TestApplyTransportLinkAssignsLinkLocalPrefixForBabel(t *testing.T) {
	driver := &DryRunDriver{}
	spec := TransportLinkSpec{
		LocalZone:       "node-a.catofes.",
		PeerZone:        "node-b.catofes.",
		TransportID:     "ipsec-1",
		InterfaceName:   "phx1",
		XFRMIfID:        42,
		NetNS:           DefaultNetNSName,
		LocalTunnelAddr: netip.MustParseAddr("fe80::1234"),
	}
	if _, err := ApplyTransportLink(context.Background(), driver, driver, spec, NetNSSpec{}); err != nil {
		t.Fatalf("ApplyTransportLink: %v", err)
	}
	if len(driver.Addresses) != 1 || driver.Addresses[0] != "phx1=fe80::1234/64" {
		t.Fatalf("address assignment = %+v", driver.Addresses)
	}
}

func TestBuildStrongSwanConnectionUsesRouteBasedChildSA(t *testing.T) {
	spec := TransportLinkSpec{
		LocalZone:       "node-a.catofes.",
		PeerZone:        "node-b.catofes.",
		TransportID:     "ipsec-main",
		IKEIdentity:     "node-b.catofes.",
		XFRMIfID:        77,
		LocalTunnelAddr: netip.MustParseAddr("fd00:1234::1"),
		PeerTunnelAddr:  netip.MustParseAddr("fd00:1234::2"),
		ContactPoints: []ContactPoint{{
			Address:    "2001:db8::20",
			Family:     FamilyIPv6,
			Priority:   10,
			Generation: 2,
			Current:    true,
			IKEPort:    4500,
		}},
	}
	msg, err := BuildLoadConnMessage(spec)
	if err != nil {
		t.Fatalf("BuildLoadConnMessage: %v", err)
	}
	conn := msg["ipsec-main"].(map[string]any)
	if conn["remote_port"] != "4500" {
		t.Fatalf("remote_port = %v", conn["remote_port"])
	}
	if conn["unique"] != "never" {
		t.Fatalf("unique = %v, want never", conn["unique"])
	}
	children := conn["children"].(map[string]any)
	child := children["ipsec-main-child"].(map[string]any)
	if child["mode"] != StrongSwanChildMode || child["if_id_in"] != "77" || child["if_id_out"] != "77" {
		t.Fatalf("child = %+v", child)
	}
	if child["start_action"] != "none" {
		t.Fatalf("start_action = %#v, want none", child["start_action"])
	}
	if got := child["local_ts"].([]string); len(got) != 1 || got[0] != "::/0" {
		t.Fatalf("local_ts = %+v", got)
	}
	if got := child["remote_ts"].([]string); len(got) != 1 || got[0] != "::/0" {
		t.Fatalf("remote_ts = %+v", got)
	}
}

func TestBuildStrongSwanConnectionAllowsInboundWithoutContactPoint(t *testing.T) {
	spec := TransportLinkSpec{
		LocalZone:     "node-a.catofes.",
		PeerZone:      "node-b.catofes.",
		TransportID:   "ipsec-main",
		InitiatorRole: "",
		XFRMIfID:      77,
	}
	msg, err := BuildLoadConnMessage(spec)
	if err != nil {
		t.Fatalf("BuildLoadConnMessage: %v", err)
	}
	conn := msg["ipsec-main"].(map[string]any)
	addrs := conn["remote_addrs"].([]string)
	if len(addrs) != 1 || addrs[0] != "%any" {
		t.Fatalf("remote_addrs = %+v", addrs)
	}
	if _, ok := conn["remote_port"]; ok {
		t.Fatalf("inbound connection should not force remote_port: %+v", conn)
	}
	children := conn["children"].(map[string]any)
	child := children[ChildSAName(spec)].(map[string]any)
	if child["start_action"] != "none" {
		t.Fatalf("start_action = %#v, want none", child["start_action"])
	}
}

func TestBuildStrongSwanConnectionRestrictsInboundFamilyPath(t *testing.T) {
	tests := []struct {
		pathKey string
		want    string
	}{
		{"family:ipv4", "%any4"},
		{"family:ipv6", "%any6"},
	}
	for _, tc := range tests {
		t.Run(tc.pathKey, func(t *testing.T) {
			spec := TransportLinkSpec{
				LocalZone:     "node-a.catofes.",
				PeerZone:      "node-b.catofes.",
				PathKey:       tc.pathKey,
				TransportID:   "ipsec-main",
				InitiatorRole: "",
				XFRMIfID:      77,
			}
			msg, err := BuildLoadConnMessage(spec)
			if err != nil {
				t.Fatalf("BuildLoadConnMessage: %v", err)
			}
			conn := msg["ipsec-main"].(map[string]any)
			addrs := conn["remote_addrs"].([]string)
			if len(addrs) != 1 || addrs[0] != tc.want {
				t.Fatalf("remote_addrs = %+v, want %s", addrs, tc.want)
			}
			if _, ok := conn["remote_port"]; ok {
				t.Fatalf("inbound connection should not force remote_port: %+v", conn)
			}
		})
	}
}

func TestStrongSwanDriverCallsVICIWithoutSwanctlParsing(t *testing.T) {
	client := &recordingVICIClient{}
	driver := &StrongSwanDriver{VICI: client}
	spec := TransportLinkSpec{
		LocalZone:   "node-a.catofes.",
		PeerZone:    "node-b.catofes.",
		TransportID: "ipsec-main",
		XFRMIfID:    77,
		ContactPoints: []ContactPoint{{
			Address: "198.51.100.20",
			Current: true,
			IKEPort: 500,
		}},
	}
	if err := driver.LoadConnection(context.Background(), spec); err != nil {
		t.Fatalf("LoadConnection: %v", err)
	}
	if err := driver.InitiateChild(context.Background(), ChildSAName(spec)); err != nil {
		t.Fatalf("InitiateChild: %v", err)
	}
	if err := driver.TerminateSA(context.Background(), spec.TransportID); err != nil {
		t.Fatalf("TerminateSA: %v", err)
	}
	if err := driver.UnloadConnection(context.Background(), spec.TransportID); err != nil {
		t.Fatalf("UnloadConnection: %v", err)
	}
	got := client.commands
	want := []string{"load-conn", "initiate", "terminate", "unload-conn"}
	if len(got) != len(want) {
		t.Fatalf("commands = %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("command[%d] = %s, want %s", i, got[i], want[i])
		}
	}
}

func TestTeardownTransportLinkRecordsOrder(t *testing.T) {
	driver := &DryRunDriver{}
	spec := TransportLinkSpec{
		TransportID:   "ipsec-main",
		PeerZone:      "node-b.catofes.",
		InterfaceName: "phx1",
		XFRMIfID:      77,
		NetNS:         DefaultNetNSName,
	}
	plan, err := TeardownTransportLink(context.Background(), driver, driver, spec)
	if err != nil {
		t.Fatalf("TeardownTransportLink: %v", err)
	}
	if len(plan.Operations) != 3 {
		t.Fatalf("plan = %+v", plan)
	}
	if plan.Operations[0].Action != "terminate_sa" ||
		plan.Operations[1].Action != "unload_connection" ||
		plan.Operations[2].Action != "delete_interface" {
		t.Fatalf("operation order = %+v", plan.Operations)
	}
	if len(driver.Terminated) != 1 || len(driver.Unloaded) != 1 || len(driver.DeletedIFs) != 1 {
		t.Fatalf("driver = %+v", driver)
	}
}

func validNodeRecords() *NodeRecords {
	return &NodeRecords{
		Zone: "node-a.catofes.",
		Profile: &ProfileRecord{
			Version:                 1,
			Enabled:                 true,
			Provider:                ProviderStrongSwan,
			IKEIdentity:             "node-a.catofes.",
			TransportKeyFingerprint: "b2",
			Role:                    RoleIn,
			AddressFamilies:         []string{FamilyIPv4},
			PathModes:               []string{PathModeFamilyRedundant},
		},
		TransportKey: &TransportKeyRecord{
			Version:     1,
			Kind:        TransportKeyRawPublicKey,
			Algorithm:   AlgorithmEd25519,
			PublicKey:   "base64",
			Fingerprint: "b2",
		},
	}
}

func record(t *testing.T, owner zone.ZonePath, key, recordType string, value any) *zone.Record {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return &zone.Record{
		Zone:  owner,
		Key:   key,
		Type:  recordType,
		Value: data,
	}
}

type staticDNSResolver map[string][]net.IPAddr

func (r staticDNSResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	return append([]net.IPAddr(nil), r[host]...), nil
}

type recordingVICIClient struct {
	commands []string
}

func (c *recordingVICIClient) Call(_ context.Context, command string, _ map[string]any) (map[string]any, error) {
	c.commands = append(c.commands, command)
	return map[string]any{"success": "yes"}, nil
}

func (c *recordingVICIClient) CallStreaming(_ context.Context, command, _ string, _ map[string]any) ([]map[string]any, error) {
	c.commands = append(c.commands, command)
	return nil, nil
}
