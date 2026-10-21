package main

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestPublishIPsecRecordsSignsStableLocalCapability(t *testing.T) {
	state, config := buildTestNetworkState(t)
	state.ManagedZone = "node-b.catofes."
	config.PeerID = string(state.ManagedZone)
	now := time.Unix(5000, 0)
	appConfig := defaultAppConfig()
	appConfig.ListenAddr = "198.51.100.10:4500"
	appConfig.AdvertiseAddrs = []string{"198.51.100.10:4500"}
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{testIPsecLinkGroup()}
	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	sr := newSyncRuntime(config, nil, rt)

	if err := sr.publishIPsecRecords(state); err != nil {
		t.Fatalf("publishIPsecRecords: %v", err)
	}
	zs := state.Network.Zones[state.ManagedZone]
	for _, key := range []string{ipsec.RecordKeyProfile, ipsec.RecordKeyAddresses, ipsec.RecordKeyPorts, ipsec.RecordKeyTransportKey, ipsec.OverlayIntentRecordKey("main")} {
		if zs.Records[key] == nil {
			t.Fatalf("%s record missing", key)
		}
		if zs.Records[key].Version != 1 {
			t.Fatalf("%s version = %d, want 1", key, zs.Records[key].Version)
		}
	}
	if state.IPsecTransportKey == nil || len(state.IPsecTransportKey.PrivateKey) == 0 {
		t.Fatalf("transport key state = %+v, want persisted private key", state.IPsecTransportKey)
	}
	profile, err := ipsec.ParseProfileRecord(zs.Records[ipsec.RecordKeyProfile])
	if err != nil {
		t.Fatalf("ParseProfileRecord: %v", err)
	}
	key, err := ipsec.ParseTransportKeyRecord(zs.Records[ipsec.RecordKeyTransportKey])
	if err != nil {
		t.Fatalf("ParseTransportKeyRecord: %v", err)
	}
	if profile.TransportKeyFingerprint != key.Fingerprint {
		t.Fatalf("profile fingerprint = %q, key fingerprint = %q", profile.TransportKeyFingerprint, key.Fingerprint)
	}
	if profile.Role != ipsec.RoleBoth {
		t.Fatalf("profile role = %q, want both", profile.Role)
	}
	addresses, err := ipsec.ParseAddressRecord(zs.Records[ipsec.RecordKeyAddresses])
	if err != nil {
		t.Fatalf("ParseAddressRecord: %v", err)
	}
	if len(addresses.Addresses) != 1 || addresses.Addresses[0].Address != "198.51.100.10" {
		t.Fatalf("addresses = %+v, want advertised IP", addresses.Addresses)
	}
	ports, err := ipsec.ParsePortRecord(zs.Records[ipsec.RecordKeyPorts])
	if err != nil {
		t.Fatalf("ParsePortRecord: %v", err)
	}
	if ports.Current == nil || ports.Current.NATT.Advertised != 4500 {
		t.Fatalf("ports = %+v, want natt 4500", ports)
	}
	intent, err := ipsec.ParseOverlayIntentRecord(zs.Records[ipsec.OverlayIntentRecordKey("main")])
	if err != nil {
		t.Fatalf("ParseOverlayIntentRecord: %v", err)
	}
	if intent.OverlayID != "main" || len(intent.PathKeys) == 0 {
		t.Fatalf("overlay intent = %+v, want main path keys", intent)
	}
	if intent.TunnelAddress.Mode != ipsec.TunnelAddressSequentialPool || intent.TunnelAddress.Family != ipsec.FamilyIPv4 || intent.TunnelAddress.Pool.String() != "10.44.0.0/29" {
		t.Fatalf("overlay tunnel address = %+v, want sequential-pool ipv4 10.44.0.0/29", intent.TunnelAddress)
	}

	latest, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if latest.IPsecTransportKey == nil || len(latest.IPsecTransportKey.PrivateKey) == 0 {
		t.Fatalf("loaded transport key state = %+v, want persisted private key", latest.IPsecTransportKey)
	}
	rt.Clock = func() time.Time { return now.Add(time.Hour) }
	state = latest
	if err := sr.publishIPsecRecords(state); err != nil {
		t.Fatalf("publishIPsecRecords(second): %v", err)
	}
	again := latest.Network.Zones[latest.ManagedZone].Records[ipsec.RecordKeyProfile]
	if again.Version != 1 {
		t.Fatalf("second profile version = %d, want unchanged 1", again.Version)
	}
}

func TestPublishIPsecRecordsMigratesDeprecatedAcceptProfileToRole(t *testing.T) {
	state, config := buildTestNetworkState(t)
	state.ManagedZone = "node-b.catofes."
	config.PeerID = string(state.ManagedZone)
	now := time.Unix(5000, 0)
	appConfig := defaultAppConfig()
	appConfig.ListenAddr = "198.51.100.10:4500"
	appConfig.AdvertiseAddrs = []string{"198.51.100.10:4500"}
	appConfig.IPsec.Role = ipsec.RoleBoth
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{testIPsecLinkGroup()}
	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	oldValue, err := json.Marshal(map[string]any{
		"version":                   1,
		"enabled":                   true,
		"provider":                  ipsec.ProviderStrongSwan,
		"ike_identity":              string(state.ManagedZone),
		"transport_key_fingerprint": "old-fingerprint",
		"accept":                    "both",
		"address_families":          []string{ipsec.FamilyIPv4},
		"path_modes":                []string{ipsec.PathModeFamilyRedundant},
	})
	if err != nil {
		t.Fatalf("Marshal old profile: %v", err)
	}
	oldRecord, err := buildSignedRecordAt(state, state.ManagedZone, ipsec.RecordKeyProfile, oldValue, ipsec.RecordTypeProfile, now.Add(-time.Minute))
	if err != nil {
		t.Fatalf("build old profile: %v", err)
	}
	if err := state.Network.Put(oldRecord); err != nil {
		t.Fatalf("put old profile: %v", err)
	}

	sr := newSyncRuntime(config, nil, rt)
	if err := sr.publishIPsecRecords(state); err != nil {
		t.Fatalf("publishIPsecRecords: %v", err)
	}
	record := state.Network.Zones[state.ManagedZone].Records[ipsec.RecordKeyProfile]
	profile, err := ipsec.ParseProfileRecord(record)
	if err != nil {
		t.Fatalf("ParseProfileRecord: %v", err)
	}
	if profile.Role != ipsec.RoleBoth {
		t.Fatalf("profile role = %q, want both", profile.Role)
	}
	var raw map[string]any
	if err := json.Unmarshal(record.Value, &raw); err != nil {
		t.Fatalf("Unmarshal profile: %v", err)
	}
	if _, ok := raw["accept"]; ok {
		t.Fatalf("profile still contains deprecated accept field: %s", record.Value)
	}
	if _, ok := raw["role"]; !ok {
		t.Fatalf("profile missing role field: %s", record.Value)
	}
	if record.Version != oldRecord.Version+1 {
		t.Fatalf("profile version = %d, want migrated version %d", record.Version, oldRecord.Version+1)
	}
}

func TestDaemonEndpointTimerPublishesRoleProfileFromReloadedState(t *testing.T) {
	state, config := buildTestNetworkState(t)
	state.ManagedZone = "node-b.catofes."
	config.PeerID = string(state.ManagedZone)
	now := time.Unix(5000, 0)
	appConfig := defaultAppConfig()
	appConfig.ListenAddr = "198.51.100.10:4500"
	appConfig.AdvertiseAddrs = []string{"198.51.100.10:4500"}
	appConfig.IPsec.Role = ipsec.RoleBoth
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{testIPsecLinkGroup()}
	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now },
	}
	oldValue, err := json.Marshal(map[string]any{
		"version":                   1,
		"enabled":                   true,
		"provider":                  ipsec.ProviderStrongSwan,
		"ike_identity":              string(state.ManagedZone),
		"transport_key_fingerprint": "old-fingerprint",
		"accept":                    "bidirectional",
		"address_families":          []string{ipsec.FamilyIPv4, ipsec.FamilyIPv6},
		"path_modes":                []string{ipsec.PathModeFamilyRedundant},
	})
	if err != nil {
		t.Fatalf("Marshal old profile: %v", err)
	}
	oldRecord, err := buildSignedRecordAt(state, state.ManagedZone, ipsec.RecordKeyProfile, oldValue, ipsec.RecordTypeProfile, now.Add(-time.Minute))
	if err != nil {
		t.Fatalf("build old profile: %v", err)
	}
	if err := state.Network.Put(oldRecord); err != nil {
		t.Fatalf("put old profile: %v", err)
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	loaded, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	service := newDaemonService(rt, loaded, config, time.Minute)

	result, syncNow, shutdown := service.handleEvent(daemonEvent{Type: daemonEventEndpointTimer})
	if result.Error != nil {
		t.Fatalf("handleEvent(endpoint): %v", result.Error)
	}
	if !syncNow || shutdown {
		t.Fatalf("syncNow/shutdown = %v/%v, want true/false", syncNow, shutdown)
	}
	latest, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState(latest): %v", err)
	}
	record := latest.Network.Zones[latest.ManagedZone].Records[ipsec.RecordKeyProfile]
	if record.Version != oldRecord.Version+1 {
		t.Fatalf("profile version = %d, want %d", record.Version, oldRecord.Version+1)
	}
	var raw map[string]any
	if err := json.Unmarshal(record.Value, &raw); err != nil {
		t.Fatalf("Unmarshal profile: %v", err)
	}
	if raw["role"] != ipsec.RoleBoth {
		t.Fatalf("profile role = %v, want both; raw=%s", raw["role"], record.Value)
	}
	if _, ok := raw["accept"]; ok {
		t.Fatalf("profile still contains deprecated accept field: %s", record.Value)
	}
}

func TestPublishIPsecRecordsRotatesPortGenerationByInterval(t *testing.T) {
	state, config := buildTestNetworkState(t)
	state.ManagedZone = "node-b.catofes."
	config.PeerID = string(state.ManagedZone)
	now := time.Unix(5000, 0)
	appConfig := defaultAppConfig()
	appConfig.ListenAddr = "198.51.100.10:4500"
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{testIPsecLinkGroup()}
	appConfig.IPsec.PortMode = ipsec.PortModeRange
	appConfig.IPsec.PortRange = ipsec.PortRange{From: 30000, To: 30099}
	appConfig.IPsec.PortRotateInterval = time.Hour
	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	sr := newSyncRuntime(config, nil, rt)
	if err := sr.publishIPsecRecords(state); err != nil {
		t.Fatalf("publishIPsecRecords: %v", err)
	}
	first, err := ipsec.ParsePortRecord(state.Network.Zones[state.ManagedZone].Records[ipsec.RecordKeyPorts])
	if err != nil {
		t.Fatalf("ParsePortRecord: %v", err)
	}
	if first.Current.Generation != 1 {
		t.Fatalf("first generation = %d, want 1", first.Current.Generation)
	}
	if state.IPsecPortRecord == nil || state.IPsecPortRecord.Generation != 1 {
		t.Fatalf("port state not persisted")
	}

	latest, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	state = latest
	for i, offset := range []time.Duration{30 * time.Minute, 55 * time.Minute} {
		rt.Clock = func() time.Time { return now.Add(offset) }
		if err := sr.publishIPsecRecords(state); err != nil {
			t.Fatalf("publishIPsecRecords(refresh %d): %v", i, err)
		}
		refreshed, err := ipsec.ParsePortRecord(latest.Network.Zones[latest.ManagedZone].Records[ipsec.RecordKeyPorts])
		if err != nil {
			t.Fatalf("ParsePortRecord(refresh %d): %v", i, err)
		}
		if refreshed.Current.Generation != 1 {
			t.Fatalf("generation advanced within interval = %d", refreshed.Current.Generation)
		}
		if refreshed.UpdatedAt != first.UpdatedAt {
			t.Fatalf("unchanged generation updated_at = %d, want stable %d", refreshed.UpdatedAt, first.UpdatedAt)
		}
	}

	rt.Clock = func() time.Time { return now.Add(2 * time.Hour) }
	if err := sr.publishIPsecRecords(state); err != nil {
		t.Fatalf("publishIPsecRecords(third): %v", err)
	}
	third, err := ipsec.ParsePortRecord(latest.Network.Zones[latest.ManagedZone].Records[ipsec.RecordKeyPorts])
	if err != nil {
		t.Fatalf("ParsePortRecord(third): %v", err)
	}
	if third.Current.Generation != 2 {
		t.Fatalf("generation = %d, want 2", third.Current.Generation)
	}
	if len(third.Previous) == 0 || third.Previous[0].Generation != 1 {
		t.Fatalf("previous grace missing: %+v", third.Previous)
	}
}

func TestPublishIPsecRecordsRotatesFromExistingPortRecordWhenMetaMissing(t *testing.T) {
	state, config := buildTestNetworkState(t)
	state.ManagedZone = "node-b.catofes."
	config.PeerID = string(state.ManagedZone)
	now := time.Unix(5000, 0)
	appConfig := defaultAppConfig()
	appConfig.ListenAddr = "198.51.100.10:4500"
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{testIPsecLinkGroup()}
	appConfig.IPsec.PortMode = ipsec.PortModeRange
	appConfig.IPsec.PortRange = ipsec.PortRange{From: 30000, To: 30099}
	appConfig.IPsec.PortRotateInterval = time.Hour
	appConfig.IPsec.PortPreviousGrace = 2 * time.Hour
	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now },
	}
	sr := newSyncRuntime(config, nil, rt)
	if err := sr.publishIPsecRecords(state); err != nil {
		t.Fatalf("publishIPsecRecords(first): %v", err)
	}
	first, err := ipsec.ParsePortRecord(state.Network.Zones[state.ManagedZone].Records[ipsec.RecordKeyPorts])
	if err != nil {
		t.Fatalf("ParsePortRecord(first): %v", err)
	}
	state.IPsecPortRecord = nil

	rt.Clock = func() time.Time { return now.Add(2 * time.Hour) }
	if err := sr.publishIPsecRecords(state); err != nil {
		t.Fatalf("publishIPsecRecords(second): %v", err)
	}
	rotated, err := ipsec.ParsePortRecord(state.Network.Zones[state.ManagedZone].Records[ipsec.RecordKeyPorts])
	if err != nil {
		t.Fatalf("ParsePortRecord(rotated): %v", err)
	}
	if rotated.Current.Generation != first.Current.Generation+1 {
		t.Fatalf("generation = %d, want %d", rotated.Current.Generation, first.Current.Generation+1)
	}
	if len(rotated.Previous) == 0 || rotated.Previous[0].Generation != first.Current.Generation {
		t.Fatalf("previous grace missing: %+v", rotated.Previous)
	}
	if state.IPsecPortRecord == nil || state.IPsecPortRecord.Generation != rotated.Current.Generation {
		t.Fatalf("port meta not restored: %+v", state.IPsecPortRecord)
	}
}

func TestForceLocalIPsecPortRotateAdvancesRangeGeneration(t *testing.T) {
	state, config := buildTestNetworkState(t)
	state.ManagedZone = "node-b.catofes."
	config.PeerID = string(state.ManagedZone)
	now := time.Unix(5000, 0)
	appConfig := defaultAppConfig()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{testIPsecLinkGroup()}
	appConfig.IPsec.PortMode = ipsec.PortModeRange
	appConfig.IPsec.PortRange = ipsec.PortRange{From: 30000, To: 30099}
	appConfig.IPsec.PortPreviousGrace = 2 * time.Hour
	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now },
	}
	sr := newSyncRuntime(config, nil, rt)
	if err := sr.publishIPsecRecords(state); err != nil {
		t.Fatalf("publishIPsecRecords(first): %v", err)
	}
	first, err := ipsec.ParsePortRecord(state.Network.Zones[state.ManagedZone].Records[ipsec.RecordKeyPorts])
	if err != nil {
		t.Fatalf("ParsePortRecord(first): %v", err)
	}

	result, err := forceLocalIPsecPortRotate(appConfig, state, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("forceLocalIPsecPortRotate: %v", err)
	}
	rotated, err := ipsec.ParsePortRecord(state.Network.Zones[state.ManagedZone].Records[ipsec.RecordKeyPorts])
	if err != nil {
		t.Fatalf("ParsePortRecord(rotated): %v", err)
	}
	if rotated.Current.Generation != first.Current.Generation+1 {
		t.Fatalf("generation = %d, want %d", rotated.Current.Generation, first.Current.Generation+1)
	}
	if len(rotated.Previous) != 1 || rotated.Previous[0].Generation != first.Current.Generation {
		t.Fatalf("previous grace = %+v, want generation %d", rotated.Previous, first.Current.Generation)
	}
	if rotated.Previous[0].ValidUntil != now.Add(time.Minute).Add(2*time.Hour).Unix() {
		t.Fatalf("previous valid_until = %d, want %d", rotated.Previous[0].ValidUntil, now.Add(time.Minute).Add(2*time.Hour).Unix())
	}
	if state.IPsecPortRecord == nil || state.IPsecPortRecord.Generation != rotated.Current.Generation {
		t.Fatalf("port meta = %+v, want generation %d", state.IPsecPortRecord, rotated.Current.Generation)
	}
	if result.PreviousGeneration != first.Current.Generation || result.CurrentGeneration != rotated.Current.Generation {
		t.Fatalf("result = %+v, want previous %d current %d", result, first.Current.Generation, rotated.Current.Generation)
	}
	if result.CurrentIKE != rotated.Current.IKE.Advertised || result.CurrentNATT != rotated.Current.NATT.Advertised {
		t.Fatalf("result ports = %+v, rotated = %+v", result, rotated.Current)
	}
}

func TestForceLocalIPsecPortRotateRejectsFixedMode(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	state.ManagedZone = "node-b.catofes."
	appConfig := defaultAppConfig()
	appConfig.IPsec.PortMode = ipsec.PortModeFixed

	if _, err := forceLocalIPsecPortRotate(appConfig, state, time.Unix(5000, 0)); err == nil {
		t.Fatalf("forceLocalIPsecPortRotate error = nil, want fixed mode rejection")
	}
}

func TestPublishIPsecRecordsSkipsWithoutLinkGroups(t *testing.T) {
	state, config := buildTestNetworkState(t)
	state.ManagedZone = "node-b.catofes."
	config.PeerID = string(state.ManagedZone)
	rt := &Runtime{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return time.Unix(5100, 0) },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	sr := newSyncRuntime(config, nil, rt)

	if err := sr.publishIPsecRecords(state); err != nil {
		t.Fatalf("publishIPsecRecords: %v", err)
	}
	zs := state.Network.Zones[state.ManagedZone]
	if zs == nil {
		t.Fatalf("zone %s missing", state.ManagedZone)
	}
	if zs.Records[ipsec.RecordKeyProfile] != nil {
		t.Fatalf("ipsec records unexpectedly published: %+v", zs.Records[ipsec.RecordKeyProfile])
	}
}

func TestLocalIPsecAddressRecordAnnounceAddrs(t *testing.T) {
	config := defaultAppConfig()
	config.IPsec.AnnounceAddrs = []string{"203.0.113.5", "2001:db8::5"}
	config.ListenAddr = "0.0.0.0:4500"

	record := localIPsecAddressRecord(config, nil, time.Now())
	if len(record.Addresses) != 2 {
		t.Fatalf("got %d addresses, want 2: %+v", len(record.Addresses), record.Addresses)
	}
	for i, addr := range record.Addresses {
		if addr.Source != ipsec.SourceManualAddress {
			t.Fatalf("address %d source = %q, want manual-address", i, addr.Source)
		}
	}
	if record.Addresses[0].Address != "203.0.113.5" {
		t.Fatalf("first address = %q, want 203.0.113.5", record.Addresses[0].Address)
	}
	if record.Addresses[1].Address != "2001:db8::5" {
		t.Fatalf("second address = %q, want 2001:db8::5", record.Addresses[1].Address)
	}
}

func TestLocalIPsecAddressRecordAnnounceDNS(t *testing.T) {
	config := defaultAppConfig()
	config.IPsec.AnnounceDNS = []string{"vpn.example.com"}
	config.ListenAddr = "0.0.0.0:4500"

	record := localIPsecAddressRecord(config, nil, time.Now())
	if len(record.Addresses) != 1 {
		t.Fatalf("got %d addresses, want 1: %+v", len(record.Addresses), record.Addresses)
	}
	ad := record.Addresses[0]
	if ad.Source != ipsec.SourceManualDNS {
		t.Fatalf("source = %q, want manual-dns", ad.Source)
	}
	if ad.Host != "vpn.example.com" {
		t.Fatalf("host = %q, want vpn.example.com", ad.Host)
	}
	if len(ad.Families) != 2 || ad.Families[0] != ipsec.FamilyIPv4 || ad.Families[1] != ipsec.FamilyIPv6 {
		t.Fatalf("families = %v, want [ipv4 ipv6]", ad.Families)
	}
}

func TestLocalIPsecOverlayIntentUsesDNSFamilies(t *testing.T) {
	now := time.Unix(5000, 0)
	config := defaultAppConfig()
	config.ListenAddr = "0.0.0.0:4500"
	config.IPsec.AnnounceDNS = []string{"vpn.example.com"}
	config.IPsec.LinkGroups = []ipsec.LinkGroupSpec{testIPsecLinkGroup()}

	records, err := localIPsecRecords(config, &stateFile{}, "node-a.catofes.", &ipsec.TransportKeyRecord{
		Version:     1,
		Kind:        ipsec.TransportKeyRawPublicKey,
		Algorithm:   ipsec.AlgorithmEd25519,
		Fingerprint: "sha256:test",
		UpdatedAt:   now.Unix(),
	}, now)
	if err != nil {
		t.Fatalf("localIPsecRecords: %v", err)
	}

	var profile *ipsec.ProfileRecord
	var intent *ipsec.OverlayIntentRecord
	for _, record := range records {
		switch value := record.value.(type) {
		case ipsec.ProfileRecord:
			profile = &value
		case ipsec.OverlayIntentRecord:
			if record.key == ipsec.OverlayIntentRecordKey("main") {
				intent = &value
			}
		}
	}
	if profile == nil {
		t.Fatalf("profile record missing")
	}
	if !reflect.DeepEqual(profile.AddressFamilies, []string{ipsec.FamilyIPv4, ipsec.FamilyIPv6}) {
		t.Fatalf("profile address families = %v, want [ipv4 ipv6]", profile.AddressFamilies)
	}
	if intent == nil {
		t.Fatalf("overlay intent record missing")
	}
	wantPathKeys := []string{"family:" + ipsec.FamilyIPv4, "family:" + ipsec.FamilyIPv6}
	if !reflect.DeepEqual(intent.PathKeys, wantPathKeys) {
		t.Fatalf("overlay path keys = %v, want %v", intent.PathKeys, wantPathKeys)
	}
	if intent.TunnelAddress.Mode != ipsec.TunnelAddressSequentialPool || intent.TunnelAddress.Family != ipsec.FamilyIPv4 || intent.TunnelAddress.Pool.String() != "10.44.0.0/29" {
		t.Fatalf("overlay tunnel address = %+v, want sequential-pool ipv4 10.44.0.0/29", intent.TunnelAddress)
	}
}

func TestLocalIPsecAddressRecordFollowsGossipEndpoints(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	state.ManagedZone = "node-b.catofes."
	now := time.Unix(5000, 0)

	er := gossip.EndpointRecord{
		Endpoints: []gossip.EndpointEntry{
			{Address: "203.0.113.10", Port: 33434, Source: "advertise", Scope: "advertise", Priority: 100, LastObserved: now.Unix()},
			{Address: "198.51.100.20", Port: 33434, Source: "reflector", Scope: "global", Priority: 50, LastObserved: now.Unix()},
			{Address: "10.0.0.5", Port: 33434, Source: "interface", Scope: "site", Priority: 10, LastObserved: now.Unix()},
			{Address: "203.0.113.50", Port: 33434, Source: "interface", Scope: "global", Priority: 20, LastObserved: now.Unix()},
		},
		TTL:       int64(time.Hour / time.Second),
		UpdatedAt: now.Unix(),
	}
	data, _ := json.Marshal(er)
	state.Network.Zones[state.ManagedZone].Records[gossip.EndpointRecordKeyUDP] = &zone.Record{
		Zone:      state.ManagedZone,
		Key:       gossip.EndpointRecordKeyUDP,
		Type:      "sync.endpoint",
		Value:     data,
		Timestamp: now.Unix(),
	}

	config := defaultAppConfig()
	config.ListenAddr = "0.0.0.0:33434"
	// AnnounceGossipEndpoints defaults to true.

	record := localIPsecAddressRecord(config, state, now)
	if len(record.Addresses) != 4 {
		t.Fatalf("got %d addresses, want 4: %+v", len(record.Addresses), record.Addresses)
	}

	byID := make(map[string]ipsec.AddressAdvertisement)
	for _, ad := range record.Addresses {
		byID[ad.ID] = ad
	}

	if ad, ok := byID["endpoint-1"]; !ok || ad.Source != ipsec.SourceManualAddress || ad.Address != "203.0.113.10" {
		t.Fatalf("advertise endpoint mapping unexpected: %+v", byID["endpoint-1"])
	}
	if ad, ok := byID["endpoint-2"]; !ok || ad.Source != ipsec.SourceReflector || ad.Address != "198.51.100.20" {
		t.Fatalf("reflector endpoint mapping unexpected: %+v", byID["endpoint-2"])
	}
	if ad, ok := byID["endpoint-3"]; !ok || ad.Source != ipsec.SourceLocal || ad.Address != "10.0.0.5" || ad.Reachability != ipsec.ReachabilityPrivate {
		t.Fatalf("private interface mapping unexpected: %+v", byID["endpoint-3"])
	}
	if ad, ok := byID["endpoint-4"]; !ok || ad.Source != ipsec.SourceDiscovery || ad.Address != "203.0.113.50" || ad.Reachability != ipsec.ReachabilityPublic {
		t.Fatalf("public interface mapping unexpected: %+v", byID["endpoint-4"])
	}
	for _, ad := range record.Addresses {
		if ad.TTLSeconds != 0 || ad.LastObserved != 0 {
			t.Fatalf("ipsec address %s carried endpoint lease fields: ttl=%d last_observed=%d", ad.ID, ad.TTLSeconds, ad.LastObserved)
		}
	}
}

func TestLocalIPsecAddressRecordStableWhenGossipRefreshes(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	state.ManagedZone = "node-b.catofes."
	now := time.Unix(5000, 0)

	er := gossip.EndpointRecord{
		Endpoints: []gossip.EndpointEntry{
			{Address: "203.0.113.10", Port: 33434, Source: "advertise", Scope: "advertise", Priority: 100, LastObserved: now.Unix()},
			{Address: "198.51.100.20", Port: 33434, Source: "reflector", Scope: "global", Priority: 50, LastObserved: now.Unix()},
		},
		TTL:       int64(time.Hour / time.Second),
		UpdatedAt: now.Unix(),
	}
	data, _ := json.Marshal(er)
	state.Network.Zones[state.ManagedZone].Records[gossip.EndpointRecordKeyUDP] = &zone.Record{
		Zone:      state.ManagedZone,
		Key:       gossip.EndpointRecordKeyUDP,
		Type:      "sync.endpoint",
		Value:     data,
		Timestamp: now.Unix(),
	}

	config := defaultAppConfig()
	config.ListenAddr = "0.0.0.0:33434"

	record1 := localIPsecAddressRecord(config, state, now)
	first, _ := json.Marshal(record1)

	// Simulate gossip endpoint record being refreshed 5 minutes later with the
	// same addresses but newer LastObserved/UpdatedAt timestamps.
	later := now.Add(5 * time.Minute)
	er.UpdatedAt = later.Unix()
	for i := range er.Endpoints {
		er.Endpoints[i].LastObserved = later.Unix()
	}
	data, _ = json.Marshal(er)
	state.Network.Zones[state.ManagedZone].Records[gossip.EndpointRecordKeyUDP].Value = data
	state.Network.Zones[state.ManagedZone].Records[gossip.EndpointRecordKeyUDP].Timestamp = later.Unix()

	record2 := localIPsecAddressRecord(config, state, later)
	second, _ := json.Marshal(record2)

	if !bytes.Equal(first, second) {
		t.Fatalf("ipsec address record changed after gossip refresh:\nfirst:  %s\nsecond: %s", first, second)
	}
}

func TestLocalIPsecAddressRecordDedupsManualAndEndpoint(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	state.ManagedZone = "node-b.catofes."
	now := time.Unix(5000, 0)

	config := defaultAppConfig()
	config.AdvertiseAddrs = []string{"203.0.113.10:33434"}
	config.IPsec.AnnounceAddrs = []string{"203.0.113.10"}
	config.ListenAddr = "0.0.0.0:33434"

	er := gossip.EndpointRecord{
		Endpoints: []gossip.EndpointEntry{
			{Address: "203.0.113.10", Port: 33434, Source: "advertise", Scope: "advertise", Priority: 100, LastObserved: now.Unix()},
			{Address: "198.51.100.20", Port: 33434, Source: "reflector", Scope: "global", Priority: 50, LastObserved: now.Unix()},
		},
		TTL:       int64(time.Hour / time.Second),
		UpdatedAt: now.Unix(),
	}
	data, _ := json.Marshal(er)
	state.Network.Zones[state.ManagedZone].Records[gossip.EndpointRecordKeyUDP] = &zone.Record{
		Zone:      state.ManagedZone,
		Key:       gossip.EndpointRecordKeyUDP,
		Type:      "sync.endpoint",
		Value:     data,
		Timestamp: now.Unix(),
	}

	record := localIPsecAddressRecord(config, state, now)
	if len(record.Addresses) != 2 {
		t.Fatalf("got %d addresses, want 2: %+v", len(record.Addresses), record.Addresses)
	}
	if record.Addresses[0].Address != "203.0.113.10" || record.Addresses[0].Source != ipsec.SourceManualAddress {
		t.Fatalf("first address unexpected: %+v", record.Addresses[0])
	}
	if record.Addresses[1].Address != "198.51.100.20" || record.Addresses[1].Source != ipsec.SourceReflector {
		t.Fatalf("second address unexpected: %+v", record.Addresses[1])
	}
}

func TestPublishIPsecOverlayIntentStableWhenUnchanged(t *testing.T) {
	state, config := buildTestNetworkState(t)
	state.ManagedZone = "node-b.catofes."
	config.PeerID = string(state.ManagedZone)
	now := time.Unix(5000, 0)
	appConfig := defaultAppConfig()
	appConfig.ListenAddr = "198.51.100.10:4500"
	appConfig.AdvertiseAddrs = []string{"198.51.100.10:4500"}
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{testIPsecLinkGroup()}
	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	sr := newSyncRuntime(config, nil, rt)

	if err := sr.publishIPsecRecords(state); err != nil {
		t.Fatalf("publishIPsecRecords: %v", err)
	}
	key := ipsec.OverlayIntentRecordKey("main")
	first := state.Network.Zones[state.ManagedZone].Records[key]
	if first == nil {
		t.Fatalf("overlay intent record missing")
	}
	firstIntent, err := ipsec.ParseOverlayIntentRecord(first)
	if err != nil {
		t.Fatalf("ParseOverlayIntentRecord: %v", err)
	}

	latest, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	state = latest
	rt.Clock = func() time.Time { return now.Add(5 * time.Minute) }
	if err := sr.publishIPsecRecords(state); err != nil {
		t.Fatalf("publishIPsecRecords(second): %v", err)
	}
	second := latest.Network.Zones[latest.ManagedZone].Records[key]
	if second == nil {
		t.Fatalf("overlay intent record missing after re-publish")
	}
	secondIntent, err := ipsec.ParseOverlayIntentRecord(second)
	if err != nil {
		t.Fatalf("ParseOverlayIntentRecord(second): %v", err)
	}
	if second.Timestamp != first.Timestamp {
		t.Fatalf("overlay intent timestamp changed from %d to %d", first.Timestamp, second.Timestamp)
	}
	if secondIntent.UpdatedAt != firstIntent.UpdatedAt {
		t.Fatalf("overlay intent updated_at changed from %d to %d", firstIntent.UpdatedAt, secondIntent.UpdatedAt)
	}

	appConfig.IPsec.LinkGroups[0].TunnelAddressSpec.Pool = netip.MustParsePrefix("10.45.0.0/29")
	rt.Clock = func() time.Time { return now.Add(10 * time.Minute) }
	if err := sr.publishIPsecRecords(state); err != nil {
		t.Fatalf("publishIPsecRecords(third): %v", err)
	}
	third := latest.Network.Zones[latest.ManagedZone].Records[key]
	if third == nil {
		t.Fatalf("overlay intent record missing after config change")
	}
	thirdIntent, err := ipsec.ParseOverlayIntentRecord(third)
	if err != nil {
		t.Fatalf("ParseOverlayIntentRecord(third): %v", err)
	}
	if third.Timestamp <= second.Timestamp {
		t.Fatalf("overlay intent timestamp did not advance after config change: %d -> %d", second.Timestamp, third.Timestamp)
	}
	if thirdIntent.UpdatedAt <= secondIntent.UpdatedAt {
		t.Fatalf("overlay intent updated_at did not advance after config change: %d -> %d", secondIntent.UpdatedAt, thirdIntent.UpdatedAt)
	}
}

func TestPortRecordMatchesConfigRepublishesListenerChangeInRangeMode(t *testing.T) {
	config := defaultAppConfig()
	config.IPsec.PortMode = ipsec.PortModeRange
	config.IPsec.PortRange = ipsec.PortRange{From: 40000, To: 40007}
	config.IPsec.FixedIKEPort = 500
	config.IPsec.FixedNATTPort = 4500
	record, err := localIPsecPortRecord(config, nil, time.Unix(5000, 0))
	if err != nil {
		t.Fatalf("localIPsecPortRecord: %v", err)
	}
	if !portRecordMatchesConfig(record, ipsec.PortModeRange, &config.IPsec.PortRange, config) {
		t.Fatal("unchanged range-mode record should match")
	}
	config.IPsec.FixedIKEPort = 33700
	config.IPsec.FixedNATTPort = 33701
	if portRecordMatchesConfig(record, ipsec.PortModeRange, &config.IPsec.PortRange, config) {
		t.Fatal("range mode reused the old record after the local listener ports changed")
	}
	republished, err := localIPsecPortRecord(config, &stateFile{
		Network:     &zone.NetworkState{Zones: map[zone.ZonePath]*zone.ZoneState{}},
		ManagedZone: "node.test.",
	}, time.Unix(5000, 0))
	if err != nil {
		t.Fatalf("republish: %v", err)
	}
	if republished.Current.IKE.Local != 33700 || republished.Current.NATT.Local != 33701 {
		t.Fatalf("listener ports = %d/%d, want 33700/33701", republished.Current.IKE.Local, republished.Current.NATT.Local)
	}
	if republished.Current.IKE.Advertised == republished.Current.IKE.Local {
		t.Fatalf("range mode advertised the listener port %d", republished.Current.IKE.Local)
	}
}

func TestLocalIPsecAddressRecordAnnounceGossipEndpointsDisabled(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	state.ManagedZone = "node-b.catofes."
	now := time.Unix(5000, 0)

	er := gossip.EndpointRecord{
		Endpoints: []gossip.EndpointEntry{
			{Address: "203.0.113.10", Port: 33434, Source: "reflector", Scope: "global", Priority: 50, LastObserved: now.Unix()},
		},
		TTL:       int64(time.Hour / time.Second),
		UpdatedAt: now.Unix(),
	}
	data, _ := json.Marshal(er)
	state.Network.Zones[state.ManagedZone].Records[gossip.EndpointRecordKeyUDP] = &zone.Record{
		Zone:      state.ManagedZone,
		Key:       gossip.EndpointRecordKeyUDP,
		Type:      "sync.endpoint",
		Value:     data,
		Timestamp: now.Unix(),
	}

	config := defaultAppConfig()
	config.IPsec.AnnounceGossipEndpoints = false
	config.ListenAddr = "198.51.100.10:33434"

	record := localIPsecAddressRecord(config, state, now)
	if len(record.Addresses) != 1 || record.Addresses[0].Address != "198.51.100.10" {
		t.Fatalf("expected only listen fallback, got: %+v", record.Addresses)
	}
}
