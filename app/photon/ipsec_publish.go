package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/HiggsNet/photon/internal/photonlinux"
	photonstate "github.com/HiggsNet/photon/internal/state"
	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

type localIPsecPublishPlan struct {
	Intents      []corestate.LocalIntent
	TransportKey *photonstate.IPsecTransportKeyState
}

func (d *Daemon) ipsecProtocolPlan(verified *corestate.VerifiedState, runtime *photonlinux.LinuxState) (localIPsecPublishPlan, error) {
	var plan localIPsecPublishPlan
	if d == nil || verified == nil || verified.Network == nil || runtime == nil || d.App == nil || d.App.Config == nil {
		if d != nil {
			d.logDebug("ipsec", "publish_skipped", map[string]any{"reason": "runtime_incomplete"})
		}
		return plan, nil
	}
	config := d.App.Config
	if verified.ManagedZone == zone.RootZone {
		d.logDebug("ipsec", "publish_skipped", map[string]any{"reason": "root_zone"})
		return plan, nil
	}
	if !verified.ManagedZone.Valid() {
		d.logDebug("ipsec", "publish_skipped", map[string]any{"reason": "invalid_managed_zone", "managed_zone": verified.ManagedZone})
		return plan, nil
	}
	if len(verified.IdentityPrivateKey) == 0 {
		d.logDebug("ipsec", "publish_skipped", map[string]any{"reason": "missing_zone_private_key", "managed_zone": verified.ManagedZone})
		return plan, nil
	}
	if autoJoinPendingVerified(verified) {
		d.logDebug("ipsec", "publish_skipped", map[string]any{"reason": "auto_join_pending", "managed_zone": verified.ManagedZone})
		return plan, nil
	}
	if len(config.IPsec.LinkGroups) == 0 {
		d.logDebug("ipsec", "publish_skipped", map[string]any{"reason": "no_link_groups", "managed_zone": verified.ManagedZone})
		return plan, nil
	}
	d.logDebug("ipsec", "publish_started", map[string]any{
		"managed_zone": verified.ManagedZone,
		"role":         config.IPsec.Role,
		"link_groups":  len(config.IPsec.LinkGroups),
	})
	now := d.now()
	key, keyRecord, err := ensureIPsecTransportKey(runtime, verified.IdentityPrivateKey, now)
	if err != nil {
		return plan, err
	}
	plan.TransportKey = photonstate.CloneIPsecTransportKeyState(key)
	records, err := localIPsecRecords(config, verified, keyRecord, now)
	if err != nil {
		return plan, err
	}
	for _, item := range records {
		value, err := json.Marshal(item.value)
		if err != nil {
			return localIPsecPublishPlan{}, err
		}
		if zs := verified.Network.Zones[verified.ManagedZone]; zs != nil {
			if current := zs.Records[item.key]; current != nil && current.Type == item.recordType && bytes.Equal(current.Value, value) {
				continue
			}
		}
		plan.Intents = append(plan.Intents, corestate.PutProtocolRecordIntent{
			Kind: corestate.ProtocolRecordIPsec, Zone: verified.ManagedZone, Key: item.key, Type: item.recordType, Value: value,
		})
		d.logDebug("ipsec", "publish_record_decision", map[string]any{
			"managed_zone": verified.ManagedZone,
			"key":          item.key,
			"updated":      true,
		})
	}
	for _, item := range records {
		if item.key != ipsec.RecordKeyPorts {
			continue
		}
		var portRecord *ipsec.PortRecord
		switch v := item.value.(type) {
		case ipsec.PortRecord:
			portRecord = &v
		case *ipsec.PortRecord:
			portRecord = v
		default:
			continue
		}
		d.logDebug("ipsec", "port_publish_decision", ipsecPortPublishLogFields(config, existingIPsecPortRecord(verified), portRecord, now))
	}
	if len(plan.Intents) > 0 || !sameIPsecPublishRuntime(runtime, plan) {
		d.logDebug("ipsec", "publish_saved", map[string]any{"managed_zone": verified.ManagedZone, "records": len(records)})
		return plan, nil
	}
	d.logDebug("ipsec", "publish_unchanged", map[string]any{"managed_zone": verified.ManagedZone, "records": len(records)})
	return plan, nil
}

func sameIPsecPublishRuntime(runtime *photonlinux.LinuxState, plan localIPsecPublishPlan) bool {
	return runtime != nil && ipsecTransportKeyStateEqual(runtime.IPsecTransportKey, plan.TransportKey)
}

func ipsecTransportKeyStateEqual(a, b *photonstate.IPsecTransportKeyState) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Kind == b.Kind && a.Algorithm == b.Algorithm && bytes.Equal(a.PublicKey, b.PublicKey) &&
		bytes.Equal(a.PrivateKey, b.PrivateKey) && a.Fingerprint == b.Fingerprint && a.NotBefore == b.NotBefore &&
		a.NotAfter == b.NotAfter && a.UpdatedAt == b.UpdatedAt
}

func ipsecPortPublishLogFields(config *appConfig, previous *ipsec.PortRecord, record *ipsec.PortRecord, now time.Time) map[string]any {
	fields := map[string]any{
		"now": now.Unix(),
	}
	if config != nil {
		fields["rotate_interval_seconds"] = int64(config.IPsec.PortRotateInterval.Seconds())
		fields["previous_grace_seconds"] = int64(config.IPsec.PortPreviousGrace.Seconds())
	}
	if previous != nil {
		fields["existing_mode"] = previous.Mode
		if previous.Current != nil {
			fields["existing_generation"] = previous.Current.Generation
		}
		fields["existing_updated_at"] = previous.UpdatedAt
		if previous.Range != nil {
			fields["existing_range"] = fmt.Sprintf("%d-%d", previous.Range.From, previous.Range.To)
		}
		if config != nil && config.IPsec.PortRotateInterval > 0 && previous.UpdatedAt > 0 {
			dueAt := time.Unix(previous.UpdatedAt, 0).Add(config.IPsec.PortRotateInterval)
			fields["rotate_due_at"] = dueAt.Unix()
			fields["rotate_due"] = !now.Before(dueAt)
		}
	} else {
		fields["existing_generation"] = 0
	}
	if record != nil {
		fields["record_mode"] = record.Mode
		fields["record_updated_at"] = record.UpdatedAt
		if record.Range != nil {
			fields["record_range"] = fmt.Sprintf("%d-%d", record.Range.From, record.Range.To)
		}
		if record.Current != nil {
			fields["record_generation"] = record.Current.Generation
			fields["record_ike_advertised"] = record.Current.IKE.Advertised
			fields["record_natt_advertised"] = record.Current.NATT.Advertised
		}
		if len(record.Previous) > 0 {
			fields["previous_count"] = len(record.Previous)
			fields["previous_generation"] = record.Previous[0].Generation
			fields["previous_valid_until"] = record.Previous[0].ValidUntil
		}
	}
	return fields
}

type localIPsecRecord struct {
	key        string
	recordType string
	value      any
}

func ensureIPsecTransportKey(linuxState *photonlinux.LinuxState, identityPrivateKey ed25519.PrivateKey, now time.Time) (*photonstate.IPsecTransportKeyState, *ipsec.TransportKeyRecord, error) {
	if linuxState == nil {
		return nil, nil, fmt.Errorf("LinuxState is nil")
	}
	if key := linuxState.IPsecTransportKey; key != nil && len(key.PublicKey) > 0 && len(key.PrivateKey) > 0 {
		record := buildTransportKeyRecord(key)
		return key, record, nil
	}
	generated, record, err := ipsec.GenerateTransportKeyRecord(ipsec.AlgorithmEd25519, now, 0, zonePublicKey(identityPrivateKey)...)
	if err != nil {
		return nil, nil, err
	}
	return &photonstate.IPsecTransportKeyState{
		Kind:        generated.Kind,
		Algorithm:   generated.Algorithm,
		PublicKey:   append([]byte(nil), generated.PublicKey...),
		PrivateKey:  append([]byte(nil), generated.PrivateKey...),
		Fingerprint: record.Fingerprint,
		NotBefore:   record.NotBefore,
		NotAfter:    record.NotAfter,
		UpdatedAt:   record.UpdatedAt,
	}, record, nil
}

func buildTransportKeyRecord(key *photonstate.IPsecTransportKeyState) *ipsec.TransportKeyRecord {
	record := &ipsec.TransportKeyRecord{
		Version:     1,
		Kind:        key.Kind,
		Algorithm:   key.Algorithm,
		Fingerprint: key.Fingerprint,
		NotBefore:   key.NotBefore,
		NotAfter:    key.NotAfter,
		UpdatedAt:   key.UpdatedAt,
	}
	if record.Kind == "" {
		record.Kind = ipsec.TransportKeyRawPublicKey
	}
	if record.Algorithm == "" {
		record.Algorithm = ipsec.AlgorithmEd25519
	}
	if record.Fingerprint == "" {
		record.Fingerprint = ipsec.TransportKeyFingerprint(record.Algorithm, key.PublicKey)
	}
	if record.UpdatedAt == 0 {
		record.UpdatedAt = record.NotBefore
	}
	record.PublicKey = ipsecPublicKeyString(key.PublicKey)
	return record
}

func ipsecPublicKeyString(publicKey []byte) string {
	return base64.StdEncoding.EncodeToString(publicKey)
}

func zonePublicKey(identityPrivateKey ed25519.PrivateKey) [][]byte {
	if len(identityPrivateKey) != ed25519.PrivateKeySize {
		return nil
	}
	pub := identityPrivateKey.Public().(ed25519.PublicKey)
	return [][]byte{append([]byte(nil), pub...)}
}

func localIPsecRecords(config *appConfig, verified *corestate.VerifiedState, key *ipsec.TransportKeyRecord, now time.Time) ([]localIPsecRecord, error) {
	if config == nil {
		return nil, fmt.Errorf("config is nil")
	}
	if key == nil {
		return nil, fmt.Errorf("transport key record is required")
	}
	addresses := localIPsecAddressRecord(config, verified, now)
	ports, err := localIPsecPortRecord(config, verified, now)
	if err != nil {
		return nil, err
	}
	role := config.IPsec.Role
	if role == "" {
		role = ipsec.RoleBoth
	}
	families := localIPsecFamilies(addresses)
	profile := ipsec.ProfileRecord{
		Version:                 1,
		Enabled:                 true,
		Provider:                ipsec.ProviderStrongSwan,
		IKEIdentity:             string(verified.ManagedZone),
		TransportKeyFingerprint: key.Fingerprint,
		Role:                    role,
		AddressFamilies:         families,
		PathModes:               localIPsecPathModes(config.IPsec.LinkGroups),
		NAT:                     localIPsecNATProfile(addresses),
	}
	records := []localIPsecRecord{
		{key: ipsec.RecordKeyTransportKey, recordType: ipsec.RecordTypeTransportKey, value: *key},
		{key: ipsec.RecordKeyProfile, recordType: ipsec.RecordTypeProfile, value: profile},
		{key: ipsec.RecordKeyAddresses, recordType: ipsec.RecordTypeAddresses, value: addresses},
		{key: ipsec.RecordKeyPorts, recordType: ipsec.RecordTypePorts, value: ports},
	}
	records = append(records, localIPsecOverlayIntentRecords(config, verified, addresses, now)...)
	return records, nil
}

func localIPsecOverlayIntentRecords(config *appConfig, verified *corestate.VerifiedState, addresses ipsec.AddressRecord, now time.Time) []localIPsecRecord {
	if config == nil {
		return nil
	}
	families := localIPsecFamilies(addresses)
	var out []localIPsecRecord
	for _, group := range config.IPsec.LinkGroups {
		if err := group.Validate(); err != nil {
			continue
		}
		group = group.Normalized()
		pathKeys := localOverlayIntentPathKeys(group, families)
		if len(pathKeys) == 0 {
			continue
		}
		intent := ipsec.OverlayIntentRecord{
			Version:       1,
			OverlayID:     group.ID,
			Provider:      group.Provider,
			PathKeys:      pathKeys,
			TunnelAddress: group.TunnelAddressSpec,
			UpdatedAt:     now.Unix(),
		}
		// Preserve the existing timestamp when the overlay intent has not
		// actually changed. Otherwise the record would be re-published on every
		// reconcile cycle just because UpdatedAt moved forward.
		if existing := existingOverlayIntentRecord(verified, group.ID); existing != nil && overlayIntentContentEqual(existing, &intent) {
			intent.UpdatedAt = existing.UpdatedAt
		}
		out = append(out, localIPsecRecord{
			key:        ipsec.OverlayIntentRecordKey(group.ID),
			recordType: ipsec.RecordTypeOverlayIntent,
			value:      intent,
		})
	}
	return out
}

func existingOverlayIntentRecord(verified *corestate.VerifiedState, overlayID string) *ipsec.OverlayIntentRecord {
	if verified == nil || verified.Network == nil || !verified.ManagedZone.Valid() {
		return nil
	}
	zs := verified.Network.Zones[verified.ManagedZone]
	if zs == nil {
		return nil
	}
	record := zs.Records[ipsec.OverlayIntentRecordKey(overlayID)]
	if record == nil {
		return nil
	}
	intent, err := ipsec.ParseOverlayIntentRecord(record)
	if err != nil {
		return nil
	}
	return intent
}

func overlayIntentContentEqual(a, b *ipsec.OverlayIntentRecord) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.Version != b.Version || a.OverlayID != b.OverlayID || a.Provider != b.Provider {
		return false
	}
	if !slices.Equal(a.PathKeys, b.PathKeys) {
		return false
	}
	if a.TunnelAddress != b.TunnelAddress {
		return false
	}
	if !slices.Equal(a.PolicyTags, b.PolicyTags) {
		return false
	}
	return true
}

func localOverlayIntentPathKeys(group ipsec.LinkGroupSpec, families []string) []string {
	switch group.DefaultPathMode {
	case ipsec.PathModeExhaustive:
		return []string{ipsec.DefaultPathKey}
	case ipsec.PathModeFamilyRedundant:
		var out []string
		for _, family := range families {
			if family == ipsec.FamilyIPv4 || family == ipsec.FamilyIPv6 {
				out = append(out, "family:"+family)
			}
		}
		return out
	default:
		return nil
	}
}

func localIPsecAddressRecord(config *appConfig, verified *corestate.VerifiedState, now time.Time) ipsec.AddressRecord {
	record := ipsec.AddressRecord{Version: 1}
	seen := map[string]bool{}
	priority := 100
	nextID := 1

	addAddress := func(ad ipsec.AddressAdvertisement) {
		if ad.ID == "" {
			ad.ID = fmt.Sprintf("addr-%d", nextID)
			nextID++
		}
		record.Addresses = append(record.Addresses, ad)
		priority--
	}

	// 1. IPsec-specific manual addresses (highest priority).
	for _, candidate := range config.IPsec.AnnounceAddrs {
		parsed, err := netip.ParseAddr(strings.TrimSpace(candidate))
		if err != nil {
			continue
		}
		addr := parsed.String()
		if seen[addr] {
			continue
		}
		family := ipsecFamily(addr)
		if family == "" {
			continue
		}
		seen[addr] = true
		addAddress(ipsec.AddressAdvertisement{
			ID:           fmt.Sprintf("announce-%d", nextID),
			Source:       ipsec.SourceManualAddress,
			Address:      addr,
			Family:       family,
			Priority:     priority,
			Reachability: ipsecReachability(addr),
		})
	}

	// 2. Top-level advertise addresses (backward compatibility).
	for _, candidate := range config.AdvertiseAddrs {
		addr, _ := splitAdvertiseAddress(candidate)
		if addr == "" || seen[addr] {
			continue
		}
		family := ipsecFamily(addr)
		if family == "" {
			continue
		}
		seen[addr] = true
		addAddress(ipsec.AddressAdvertisement{
			ID:           fmt.Sprintf("advertise-%d", nextID),
			Source:       ipsec.SourceManualAddress,
			Address:      addr,
			Family:       family,
			Priority:     priority,
			Reachability: ipsecReachability(addr),
		})
	}

	// 3. Manual DNS names.
	for _, host := range config.IPsec.AnnounceDNS {
		host = strings.TrimSpace(host)
		if host == "" || seen[host] {
			continue
		}
		seen[host] = true
		addAddress(ipsec.AddressAdvertisement{
			ID:           fmt.Sprintf("dns-%d", nextID),
			Source:       ipsec.SourceManualDNS,
			Host:         host,
			Families:     []string{ipsec.FamilyIPv4, ipsec.FamilyIPv6},
			Priority:     priority,
			Reachability: ipsec.ReachabilityPublic,
		})
	}

	// 4. Follow gossip endpoints (reflector / interface discovery).
	if config.IPsec.AnnounceGossipEndpoints {
		for _, ad := range ipsecAddressesFromGossipEndpoints(verified, seen, now) {
			addAddress(ad)
		}
	}

	// 5. Fallback to listen_addr host.
	if len(record.Addresses) == 0 {
		host, _ := splitAdvertiseAddress(config.ListenAddr)
		if host != "" && host != "0.0.0.0" && host != "::" {
			if family := ipsecFamily(host); family != "" {
				addAddress(ipsec.AddressAdvertisement{
					ID:           "listen",
					Source:       ipsec.SourceLocal,
					Address:      host,
					Family:       family,
					Priority:     priority,
					Reachability: ipsecReachability(host),
				})
			}
		}
	}
	return record
}

// ipsecAddressesFromGossipEndpoints reads the local sync/endpoint/udp record
// and converts its entries into IPsec AddressAdvertisement values.
// The seen set is updated for each converted address.
func ipsecAddressesFromGossipEndpoints(verified *corestate.VerifiedState, seen map[string]bool, now time.Time) []ipsec.AddressAdvertisement {
	if verified == nil || verified.Network == nil || verified.ManagedZone == "" || seen == nil {
		return nil
	}
	zs := verified.Network.Zones[verified.ManagedZone]
	if zs == nil {
		return nil
	}
	record := zs.Records[gossip.EndpointRecordKeyUDP]
	if record == nil {
		return nil
	}
	var er gossip.EndpointRecord
	if err := json.Unmarshal(record.Value, &er); err != nil {
		return nil
	}
	var out []ipsec.AddressAdvertisement
	nextID := 1
	for _, ep := range er.Endpoints {
		addr := ep.Address
		if addr == "" || seen[addr] {
			continue
		}
		family := ipsecFamily(addr)
		if family == "" {
			continue
		}
		// Skip expired grace entries; the endpoint record itself already
		// applies TTL/grace, but re-check here to avoid publishing stale
		// addresses if the record was read before LocalEndpointsToRecord
		// filtered it.
		if ep.LastObserved != 0 {
			ttl := time.Duration(er.TTL) * time.Second
			if ttl <= 0 {
				ttl = gossip.DefaultEndpointTTL
			}
			grace := time.Duration(er.GraceSeconds) * time.Second
			expiresAt := time.Unix(ep.LastObserved, 0).Add(ttl + grace)
			if now.After(expiresAt) {
				continue
			}
		}
		seen[addr] = true
		source, reachability := mapGossipEndpointSourceToIPsec(ep)
		out = append(out, ipsec.AddressAdvertisement{
			ID:           fmt.Sprintf("endpoint-%d", nextID),
			Source:       source,
			Address:      addr,
			Family:       family,
			Priority:     ep.Priority,
			Reachability: reachability,
			// Do not copy LastObserved from gossip endpoints. The IPsec record
			// has declaration semantics; copying endpoint timestamps would make
			// the record change every gossip lease renewal even when the set of
			// addresses is unchanged.
		})
		nextID++
	}
	return out
}

// mapGossipEndpointSourceToIPsec maps a gossip EndpointEntry to an IPsec
// address source and reachability classification.
func mapGossipEndpointSourceToIPsec(ep gossip.EndpointEntry) (source, reachability string) {
	switch strings.Split(ep.Source, "+")[0] {
	case "advertise":
		source = ipsec.SourceManualAddress
	case "reflector":
		source = ipsec.SourceReflector
	case "interface":
		if ep.Scope == "global" {
			source = ipsec.SourceDiscovery
		} else {
			source = ipsec.SourceLocal
		}
	default:
		source = ipsec.SourceDiscovery
	}
	ip := net.ParseIP(ep.Address)
	if ip == nil {
		reachability = ipsec.ReachabilityUnknown
		return
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		reachability = ipsec.ReachabilityPrivate
	} else {
		reachability = ipsec.ReachabilityPublic
	}
	return
}

func localIPsecPortRecord(config *appConfig, verified *corestate.VerifiedState, now time.Time) (*ipsec.PortRecord, error) {
	// IPsec ports are independent of the gossip listen address. Use the IKEv2
	// defaults unless the configuration explicitly requests a different mode.
	ike := uint16(ipsec.DefaultIKEPort)
	natt := uint16(ipsec.DefaultNATTPort)
	existing := existingIPsecPortRecord(verified)
	mode := config.IPsec.PortMode
	if mode == "" {
		mode = ipsec.PortModeFixed
	}
	generation := uint64(1)
	var portRange *ipsec.PortRange
	if mode == ipsec.PortModeRange {
		portRange = &config.IPsec.PortRange
		generation = nextPortGeneration(existing, config, now)
	}
	if existing != nil && existing.Current != nil && existing.Current.Generation == generation && portRecordMatchesConfig(existing, mode, portRange) {
		return existing, nil
	}
	return ipsec.PlanPortRecord(ipsec.PortPlanOptions{
		Mode:          mode,
		Range:         portRange,
		FixedIKE:      ike,
		FixedNATT:     natt,
		Generation:    generation,
		Previous:      existing,
		PreviousGrace: config.IPsec.PortPreviousGrace,
		Now:           now,
	})
}

func existingIPsecPortRecord(verified *corestate.VerifiedState) *ipsec.PortRecord {
	if verified == nil || verified.Network == nil || !verified.ManagedZone.Valid() {
		return nil
	}
	zs := verified.Network.Zones[verified.ManagedZone]
	if zs == nil || zs.Records == nil || zs.Records[ipsec.RecordKeyPorts] == nil {
		return nil
	}
	record, err := ipsec.ParsePortRecord(zs.Records[ipsec.RecordKeyPorts])
	if err != nil {
		return nil
	}
	return record
}

func nextPortGeneration(existing *ipsec.PortRecord, config *appConfig, now time.Time) uint64 {
	if existing == nil || existing.Current == nil {
		return 1
	}
	if config.IPsec.PortRotateInterval <= 0 {
		return existing.Current.Generation
	}
	if existing.UpdatedAt == 0 {
		return existing.Current.Generation + 1
	}
	last := time.Unix(existing.UpdatedAt, 0)
	if now.After(last.Add(config.IPsec.PortRotateInterval)) {
		return existing.Current.Generation + 1
	}
	return existing.Current.Generation
}

func portRecordMatchesConfig(record *ipsec.PortRecord, mode string, r *ipsec.PortRange) bool {
	if record == nil {
		return false
	}
	recordMode := record.Mode
	if recordMode == "" {
		recordMode = ipsec.PortModeFixed
	}
	if recordMode != mode {
		return false
	}
	if mode != ipsec.PortModeRange {
		return true
	}
	return ipsecPortRangesEqual(record.Range, r)
}

func ipsecPortRangesEqual(a, b *ipsec.PortRange) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.From == b.From && a.To == b.To
}

func localIPsecFamilies(record ipsec.AddressRecord) []string {
	seen := map[string]bool{}
	var out []string
	add := func(family string) {
		if (family == ipsec.FamilyIPv4 || family == ipsec.FamilyIPv6) && !seen[family] {
			seen[family] = true
			out = append(out, family)
		}
	}
	for _, address := range record.Addresses {
		family := address.Family
		if family == "" {
			family = ipsecFamily(address.Address)
		}
		add(family)
		for _, family := range address.Families {
			add(family)
		}
	}
	if len(out) == 0 {
		return []string{ipsec.FamilyIPv4}
	}
	return out
}

func localIPsecPathModes(groups []ipsec.LinkGroupSpec) []string {
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
		return []string{ipsec.PathModeFamilyRedundant}
	}
	return out
}

func localIPsecNATProfile(record ipsec.AddressRecord) ipsec.NATProfile {
	// Avoid claiming inbound reachability based solely on having a public
	// address. Reflector-observed public addresses or static public IPs do not
	// prove that IKE/NAT-T can be delivered to this host (firewall, DNAT,
	// provider NAT). Keep the hint conservative and default to unknown.
	hint := ipsec.NATHintUnknown
	for _, address := range record.Addresses {
		if address.Reachability == ipsec.ReachabilityPublic {
			hint = ipsec.NATHintPublic
			break
		}
	}
	return ipsec.NATProfile{Hint: hint, InboundReachable: ipsec.NATReachableUnknown}
}

func splitAdvertiseAddress(value string) (string, uint16) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", 0
	}
	host, portText, err := net.SplitHostPort(value)
	if err == nil {
		port, _ := strconv.ParseUint(portText, 10, 16)
		return strings.Trim(host, "[]"), uint16(port)
	}
	if strings.Count(value, ":") > 1 {
		if addr, err := netip.ParseAddr(strings.Trim(value, "[]")); err == nil {
			return addr.String(), 0
		}
	}
	if strings.Contains(value, ":") {
		host, portText, ok := strings.Cut(value, ":")
		if ok {
			port, _ := strconv.ParseUint(portText, 10, 16)
			return host, uint16(port)
		}
	}
	return strings.Trim(value, "[]"), 0
}

func ipsecFamily(addr string) string {
	parsed, err := netip.ParseAddr(addr)
	if err != nil {
		return ""
	}
	if parsed.Is4() {
		return ipsec.FamilyIPv4
	}
	if parsed.Is6() {
		return ipsec.FamilyIPv6
	}
	return ""
}

func ipsecReachability(addr string) string {
	parsed, err := netip.ParseAddr(addr)
	if err != nil {
		return ipsec.ReachabilityUnknown
	}
	if parsed.IsLoopback() || parsed.IsPrivate() || parsed.IsLinkLocalUnicast() {
		return ipsec.ReachabilityPrivate
	}
	return ipsec.ReachabilityPublic
}
