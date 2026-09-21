package main

import (
	"context"
	"encoding/json"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	photonlinux "github.com/HiggsNet/photon/internal/photonlinux"
	photonstate "github.com/HiggsNet/photon/internal/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

type batchObservedIPsecDriver struct {
	observedIPsecDriver
	inventory []ipsec.XFRMLinkState
}

func (d *batchObservedIPsecDriver) InspectLinks(_ context.Context, specs []ipsec.TransportLinkSpec, _ []ipsec.NetNSSpec) ([]ipsec.XFRMLinkState, []ipsec.XFRMLinkState, error) {
	states := make([]ipsec.XFRMLinkState, len(specs))
	for i, spec := range specs {
		states[i] = healthyObservedXFRMState(spec)
	}
	inventory := append([]ipsec.XFRMLinkState(nil), states...)
	inventory = append(inventory, d.inventory...)
	return states, inventory, nil
}

func (d *batchObservedIPsecDriver) EnsureObservedInterfaces(context.Context, []ipsec.XFRMObservedInterface) error {
	return nil
}

func healthyObservedXFRMState(spec ipsec.TransportLinkSpec) ipsec.XFRMLinkState {
	state := ipsec.XFRMLinkState{
		NetNS:                    ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: spec.NetNS}.Normalized(),
		NamespaceExists:          true,
		InterfaceExists:          true,
		FlagsKnown:               true,
		InterfaceUp:              true,
		Multicast:                true,
		IPv6AddrGenModeKnown:     true,
		IPv6AddrGenDisabled:      true,
		NamespaceForwardingKnown: true,
		NamespaceForwarding:      true,
		InterfaceForwardingKnown: true,
		InterfaceForwarding:      true,
	}
	if spec.LocalTunnelAddr.IsValid() {
		state.Addresses = []netip.Prefix{netip.PrefixFrom(spec.LocalTunnelAddr, 128)}
	}
	return state
}

type observedIPsecDriver struct {
	ipsec.DryRunDriver
	sas        []ipsec.SAState
	linkState  *ipsec.XFRMLinkState
	linkStates map[string]ipsec.XFRMLinkState
	listCalls  int
}

func (d *observedIPsecDriver) ListSAs(context.Context) ([]ipsec.SAState, error) {
	d.listCalls++
	return d.sas, nil
}

func (d *observedIPsecDriver) InspectLink(_ context.Context, spec ipsec.TransportLinkSpec) (ipsec.XFRMLinkState, error) {
	if d.linkStates != nil {
		if state, ok := d.linkStates[spec.InterfaceName]; ok {
			return state, nil
		}
		return ipsec.XFRMLinkState{
			NetNS:           ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: spec.NetNS}.Normalized(),
			NamespaceExists: true,
			InterfaceExists: false,
		}, nil
	}
	if d.linkState != nil {
		return *d.linkState, nil
	}
	state := ipsec.XFRMLinkState{
		NetNS:           ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: spec.NetNS}.Normalized(),
		NamespaceExists: true,
		InterfaceExists: true,
	}
	if spec.LocalTunnelAddr.IsValid() {
		state.Addresses = []netip.Prefix{netip.PrefixFrom(spec.LocalTunnelAddr, 128)}
	}
	return state, nil
}

func (d *observedIPsecDriver) FilterSAsWithMissingLinks(ctx context.Context, desired []ipsec.TransportLinkSpec, sas []ipsec.SAState) ([]ipsec.SAState, map[string]ipsec.TransportLinkSpec, error) {
	missing := make(map[string]ipsec.TransportLinkSpec)
	for _, spec := range desired {
		state, err := d.InspectLink(ctx, spec)
		if err != nil {
			return nil, nil, err
		}
		if matches, _ := photonlinux.XFRMLinkStateMatchReason(state, spec); matches {
			continue
		}
		missing[ipsec.LinkInstanceID(spec)] = spec
	}
	if len(missing) == 0 {
		return sas, missing, nil
	}
	filtered := sas[:0]
	for _, sa := range sas {
		drop := false
		for _, spec := range missing {
			if sa.Name == spec.TransportID || sa.ChildSA == ipsec.ChildSAName(spec) || sa.XFRMIfID == spec.XFRMIfID {
				drop = true
				break
			}
		}
		if !drop {
			filtered = append(filtered, sa)
		}
	}
	return filtered, missing, nil
}

type countingIPsecDriver struct {
	ipsec.DryRunDriver
	listCalls int
}

func (d *countingIPsecDriver) ListSAs(context.Context) ([]ipsec.SAState, error) {
	d.listCalls++
	return d.DryRunDriver.ListSAs(context.Background())
}

type staleCommitIPsecDriver struct {
	ipsec.DryRunDriver
	onLoadConnection func(ipsec.TransportLinkSpec)
	loadedOnce       bool
}

func (d *staleCommitIPsecDriver) LoadConnection(ctx context.Context, spec ipsec.TransportLinkSpec) error {
	if !d.loadedOnce {
		d.loadedOnce = true
		if d.onLoadConnection != nil {
			d.onLoadConnection(spec)
		}
	}
	return d.DryRunDriver.LoadConnection(ctx, spec)
}

func testIPsecLinkGroup() ipsec.LinkGroupSpec {
	return ipsec.LinkGroupSpec{
		ID:                 "main",
		Provider:           ipsec.ProviderStrongSwan,
		NetNS:              ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "photontesth2", Create: true},
		DefaultPathMode:    ipsec.PathModeFamilyRedundant,
		AddressSourceOrder: []string{ipsec.SourceManualAddress},
		TunnelAddressSpec: ipsec.TunnelAddressSpec{
			Mode:   ipsec.TunnelAddressSequentialPool,
			Family: ipsec.FamilyIPv4,
			Pool:   netip.MustParsePrefix("10.44.0.0/29"),
		},
		ConnectRules: []string{"strongswan://node-*.catofes.?role=in"},
	}
}

func singleDesiredSpec(t *testing.T, managedZone zone.ZonePath, reconcile *ipsecObservationSummary) ipsec.TransportLinkSpec {
	t.Helper()
	if reconcile == nil || len(reconcile.Desired) != 1 {
		t.Fatalf("desired snapshot = %+v, want one desired link", reconcile)
	}
	desired := reconcile.Desired[0]
	localTunnel := netip.MustParseAddr("10.44.0.1")
	peerTunnel := netip.MustParseAddr("10.44.0.2")
	if desired.PeerZone < managedZone {
		localTunnel, peerTunnel = peerTunnel, localTunnel
	}
	return ipsec.TransportLinkSpec{
		LocalZone:       managedZone,
		PeerZone:        desired.PeerZone,
		OverlayID:       desired.GroupID,
		Provider:        ipsec.ProviderStrongSwan,
		LinkID:          desired.LinkID,
		PathKey:         desired.PathKey,
		TransportID:     desired.TransportID,
		InterfaceName:   desired.InterfaceName,
		XFRMIfID:        desired.XFRMIfID,
		LocalTunnelAddr: localTunnel,
		PeerTunnelAddr:  peerTunnel,
		NetNS:           "photontesth2",
		ContactPoints: []ipsec.ContactPoint{{
			Address:  desired.Endpoint,
			IKEPort:  ipsec.DefaultIKEPort,
			NATTPort: ipsec.DefaultNATTPort,
		}},
	}
}

func assertDryRunApply(t *testing.T, driver *observedIPsecDriver, spec ipsec.TransportLinkSpec, netns ipsec.NetNSSpec) {
	t.Helper()
	if len(driver.Namespaces) != 1 || driver.Namespaces[0] != netns.Normalized() {
		t.Fatalf("namespaces = %+v, want %s", driver.Namespaces, netns.Target())
	}
	if len(driver.Connections) != 1 || driver.Connections[0].TransportID != spec.TransportID {
		t.Fatalf("connections = %+v, want one %s", driver.Connections, spec.TransportID)
	}
	if len(driver.Interfaces) == 0 {
		t.Fatalf("interfaces = %+v, want %s/%d", driver.Interfaces, spec.InterfaceName, spec.XFRMIfID)
	}
	for _, iface := range driver.Interfaces {
		if iface.InterfaceName != spec.InterfaceName || iface.XFRMIfID != spec.XFRMIfID {
			t.Fatalf("interfaces = %+v, want only %s/%d", driver.Interfaces, spec.InterfaceName, spec.XFRMIfID)
		}
	}
	wantAddr := spec.InterfaceName + "=" + netip.PrefixFrom(spec.LocalTunnelAddr, 32).String()
	if len(driver.Addresses) == 0 {
		t.Fatalf("addresses = %+v, want %s", driver.Addresses, wantAddr)
	}
	for _, addr := range driver.Addresses {
		if addr != wantAddr {
			t.Fatalf("addresses = %+v, want only %s", driver.Addresses, wantAddr)
		}
	}
}

func testDaemonIPsecAppConfig(dataDir, advertiseAddr string, group ipsec.LinkGroupSpec) *appConfig {
	config := defaultAppConfig()
	config.DataDir = dataDir
	config.StatePath = filepath.Join(dataDir, "photon.db")
	config.ListenAddr = advertiseAddr
	config.AdvertiseAddrs = []string{advertiseAddr}
	config.PublishEndpoints = false
	config.IPsec.LinkGroups = []ipsec.LinkGroupSpec{group}
	return config
}

func assertGossipedIPsecRecords(t *testing.T, network *zone.NetworkState, peer zone.ZonePath) {
	t.Helper()
	zs := network.Zones[peer]
	if zs == nil {
		t.Fatalf("zone %s missing after gossip", peer)
	}
	for _, key := range []string{ipsec.RecordKeyProfile, ipsec.RecordKeyAddresses, ipsec.RecordKeyPorts, ipsec.RecordKeyTransportKey, ipsec.OverlayIntentRecordKey("main")} {
		if zs.Records[key] == nil {
			t.Fatalf("%s missing for %s after gossip", key, peer)
		}
	}
}

func hasDebugSkip(skips []photonstate.LinkSkipObservation, peer zone.ZonePath, reason string) bool {
	for _, skip := range skips {
		if skip.Peer == peer && skip.Reason == reason {
			return true
		}
	}
	return false
}

func addTestIPsecRecords(t *testing.T, zs *zone.ZoneState, peer zone.ZonePath, now time.Time, accept string) {
	t.Helper()
	if zs == nil {
		t.Fatalf("missing zone state for %s", peer)
	}
	fingerprint := "fp-" + string(peer)
	zs.Records[ipsec.RecordKeyProfile] = unsignedIPsecRecord(t, peer, ipsec.RecordKeyProfile, ipsec.RecordTypeProfile, ipsec.ProfileRecord{
		Version:                 1,
		Enabled:                 true,
		Provider:                ipsec.ProviderStrongSwan,
		IKEIdentity:             string(peer),
		TransportKeyFingerprint: fingerprint,
		Role:                    accept,
		AddressFamilies:         []string{ipsec.FamilyIPv4},
		PathModes:               []string{ipsec.PathModeFamilyRedundant},
		UpdatedAt:               now.Unix(),
	})
	zs.Records[ipsec.RecordKeyAddresses] = unsignedIPsecRecord(t, peer, ipsec.RecordKeyAddresses, ipsec.RecordTypeAddresses, ipsec.AddressRecord{
		Version: 1,
		Addresses: []ipsec.AddressAdvertisement{{
			ID:           "public-v4",
			Source:       ipsec.SourceManualAddress,
			Address:      "203.0.113.10",
			Family:       ipsec.FamilyIPv4,
			Reachability: ipsec.ReachabilityPublic,
		}},
		UpdatedAt: now.Unix(),
	})
	zs.Records[ipsec.RecordKeyPorts] = unsignedIPsecRecord(t, peer, ipsec.RecordKeyPorts, ipsec.RecordTypePorts, ipsec.PortRecord{
		Version: 1,
		Mode:    ipsec.PortModeFixed,
		Current: &ipsec.PortSelection{
			Generation: 1,
			IKE:        ipsec.PortBinding{Advertised: ipsec.DefaultIKEPort},
			NATT:       ipsec.PortBinding{Advertised: ipsec.DefaultNATTPort},
			ValidUntil: now.Add(time.Hour).Unix(),
		},
		UpdatedAt: now.Unix(),
	})
	zs.Records[ipsec.RecordKeyTransportKey] = unsignedIPsecRecord(t, peer, ipsec.RecordKeyTransportKey, ipsec.RecordTypeTransportKey, ipsec.TransportKeyRecord{
		Version:     1,
		Kind:        ipsec.TransportKeyRawPublicKey,
		Algorithm:   ipsec.AlgorithmEd25519,
		PublicKey:   "base64",
		Fingerprint: fingerprint,
		UpdatedAt:   now.Unix(),
	})
	zs.Records[ipsec.OverlayIntentRecordKey("main")] = unsignedIPsecRecord(t, peer, ipsec.OverlayIntentRecordKey("main"), ipsec.RecordTypeOverlayIntent, ipsec.OverlayIntentRecord{
		Version:       1,
		OverlayID:     "main",
		Provider:      ipsec.ProviderStrongSwan,
		PathKeys:      []string{"family:ipv4"},
		TunnelAddress: ipsec.TunnelAddressSpec{Mode: ipsec.TunnelAddressDerivedLinkLocal, Family: ipsec.FamilyIPv6},
		UpdatedAt:     now.Unix(),
	})
}

func unsignedIPsecRecord(t *testing.T, peer zone.ZonePath, key, recordType string, value any) *zone.Record {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("Marshal(%s): %v", key, err)
	}
	return &zone.Record{
		Zone:      peer,
		Key:       key,
		Type:      recordType,
		Value:     data,
		Version:   1,
		Timestamp: time.Unix(4000, 0).Unix(),
	}
}

func daemonTestTransportKey(t *testing.T, now time.Time) (*photonstate.IPsecTransportKeyState, *ipsec.TransportKeyRecord) {
	t.Helper()
	key, record, err := ipsec.GenerateTransportKeyRecord(ipsec.AlgorithmECDSAP256, now, 0)
	if err != nil {
		t.Fatalf("GenerateTransportKeyRecord: %v", err)
	}
	return &photonstate.IPsecTransportKeyState{
		Kind:        key.Kind,
		Algorithm:   key.Algorithm,
		PublicKey:   append([]byte(nil), key.PublicKey...),
		PrivateKey:  append([]byte(nil), key.PrivateKey...),
		Fingerprint: record.Fingerprint,
		NotBefore:   record.NotBefore,
		NotAfter:    record.NotAfter,
		UpdatedAt:   record.UpdatedAt,
	}, record
}

func addDaemonTestIPsecRecords(t *testing.T, zs *zone.ZoneState, peer zone.ZonePath, address string, key *ipsec.TransportKeyRecord, accept string, now time.Time) {
	t.Helper()
	if zs == nil {
		t.Fatalf("missing zone state for %s", peer)
	}
	zs.Records[ipsec.RecordKeyProfile] = unsignedIPsecRecord(t, peer, ipsec.RecordKeyProfile, ipsec.RecordTypeProfile, ipsec.ProfileRecord{
		Version:                 1,
		Enabled:                 true,
		Provider:                ipsec.ProviderStrongSwan,
		IKEIdentity:             string(peer),
		TransportKeyFingerprint: key.Fingerprint,
		Role:                    accept,
		AddressFamilies:         []string{ipsec.FamilyIPv4},
		PathModes:               []string{ipsec.PathModeFamilyRedundant},
		UpdatedAt:               now.Unix(),
	})
	zs.Records[ipsec.RecordKeyAddresses] = unsignedIPsecRecord(t, peer, ipsec.RecordKeyAddresses, ipsec.RecordTypeAddresses, ipsec.AddressRecord{
		Version: 1,
		Addresses: []ipsec.AddressAdvertisement{{
			ID:           "underlay-v4",
			Source:       ipsec.SourceManualAddress,
			Address:      address,
			Family:       ipsec.FamilyIPv4,
			Reachability: ipsec.ReachabilityPublic,
		}},
		UpdatedAt: now.Unix(),
	})
	zs.Records[ipsec.RecordKeyPorts] = unsignedIPsecRecord(t, peer, ipsec.RecordKeyPorts, ipsec.RecordTypePorts, ipsec.PortRecord{
		Version: 1,
		Mode:    ipsec.PortModeFixed,
		Current: &ipsec.PortSelection{
			Generation: 1,
			IKE:        ipsec.PortBinding{Advertised: ipsec.DefaultIKEPort},
			NATT:       ipsec.PortBinding{Advertised: ipsec.DefaultNATTPort},
			ValidUntil: now.Add(time.Hour).Unix(),
		},
		UpdatedAt: now.Unix(),
	})
	zs.Records[ipsec.RecordKeyTransportKey] = unsignedIPsecRecord(t, peer, ipsec.RecordKeyTransportKey, ipsec.RecordTypeTransportKey, *key)
	zs.Records[ipsec.OverlayIntentRecordKey("main")] = unsignedIPsecRecord(t, peer, ipsec.OverlayIntentRecordKey("main"), ipsec.RecordTypeOverlayIntent, ipsec.OverlayIntentRecord{
		Version:       1,
		OverlayID:     "main",
		Provider:      ipsec.ProviderStrongSwan,
		PathKeys:      []string{"family:ipv4"},
		TunnelAddress: ipsec.TunnelAddressSpec{Mode: ipsec.TunnelAddressDerivedLinkLocal, Family: ipsec.FamilyIPv6},
		UpdatedAt:     now.Unix(),
	})
}

func setTestIPsecOverlayIntent(t *testing.T, zs *zone.ZoneState, peer zone.ZonePath, group ipsec.LinkGroupSpec, now time.Time) {
	t.Helper()
	if zs == nil {
		t.Fatalf("missing zone state for %s", peer)
	}
	group = group.Normalized()
	zs.Records[ipsec.OverlayIntentRecordKey(group.ID)] = unsignedIPsecRecord(t, peer, ipsec.OverlayIntentRecordKey(group.ID), ipsec.RecordTypeOverlayIntent, ipsec.OverlayIntentRecord{
		Version:       1,
		OverlayID:     group.ID,
		Provider:      group.Provider,
		PathKeys:      []string{"family:ipv4"},
		TunnelAddress: group.TunnelAddressSpec,
		UpdatedAt:     now.Unix(),
	})
}

func updateDaemonTestPortRecord(t *testing.T, zs *zone.ZoneState, peer zone.ZonePath, generation uint64, ikePort uint16, now time.Time) {
	t.Helper()
	if zs == nil {
		t.Fatalf("missing zone state for %s", peer)
	}
	if ikePort == 0 {
		ikePort = ipsec.DefaultIKEPort
	}
	nattPort := ikePort
	previous := ipsec.PortSelection{
		Generation: 1,
		IKE:        ipsec.PortBinding{Advertised: ipsec.DefaultIKEPort},
		NATT:       ipsec.PortBinding{Advertised: ipsec.DefaultNATTPort},
		ValidUntil: now.Add(time.Hour).Unix(),
	}
	zs.Records[ipsec.RecordKeyPorts] = unsignedIPsecRecord(t, peer, ipsec.RecordKeyPorts, ipsec.RecordTypePorts, ipsec.PortRecord{
		Version: 1,
		Mode:    ipsec.PortModeFixed,
		Current: &ipsec.PortSelection{
			Generation: generation,
			IKE:        ipsec.PortBinding{Local: ikePort, Advertised: ikePort},
			NATT:       ipsec.PortBinding{Local: nattPort, Advertised: nattPort},
			ValidUntil: now.Add(time.Hour).Unix(),
		},
		Previous:  []ipsec.PortSelection{previous},
		UpdatedAt: now.Unix(),
	})
}
