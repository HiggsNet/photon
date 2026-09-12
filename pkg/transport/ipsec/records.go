package ipsec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

const (
	ProviderStrongSwan = "strongswan"

	RecordKeyProfile       = "ipsec/profile"
	RecordKeyAddresses     = "ipsec/addresses"
	RecordKeyPorts         = "ipsec/ports"
	RecordKeyTransportKey  = "ipsec/transport-key"
	RecordKeyOverlayPrefix = "ipsec/overlays/"

	RecordTypeProfile       = "ipsec.profile.v1"
	RecordTypeAddresses     = "ipsec.addresses.v1"
	RecordTypePorts         = "ipsec.ports.v1"
	RecordTypeTransportKey  = "ipsec.transport_key.v1"
	RecordTypeOverlayIntent = "ipsec.overlay_intent.v1"

	RoleOut  = "out"
	RoleIn   = "in"
	RoleBoth = "both"

	FamilyIPv4 = "ipv4"
	FamilyIPv6 = "ipv6"

	PathModeFamilyRedundant = "family-redundant"
	PathModeExhaustive      = "exhaustive"

	SourceManualAddress = "manual-address"
	SourceManualDNS     = "manual-dns"
	SourceDiscovery     = "discovery"
	SourceReflector     = "reflector"
	SourceLocal         = "local"

	ReachabilityPublic      = "public"
	ReachabilityNATObserved = "nat-observed"
	ReachabilityPrivate     = "private"
	ReachabilityUnknown     = "unknown"

	NATHintPublic       = "public"
	NATHintBehindNAT    = "behind_nat"
	NATHintUnknown      = "unknown"
	NATReachableTrue    = "true"
	NATReachableFalse   = "false"
	NATReachableUnknown = "unknown"

	PortModeFixed = "fixed"
	PortModeRange = "range"

	TransportKeyRawPublicKey = "raw-public-key"
	AlgorithmEd25519         = "ed25519"
	AlgorithmECDSAP256       = "ecdsa-p256"
)

var defaultAddressSourceOrder = []string{
	SourceManualAddress,
	SourceManualDNS,
	SourceDiscovery,
	SourceReflector,
	SourceLocal,
}

type ProfileRecord struct {
	Version                 int        `json:"version"`
	Enabled                 bool       `json:"enabled"`
	Provider                string     `json:"provider"`
	IKEIdentity             string     `json:"ike_identity"`
	TransportKeyFingerprint string     `json:"transport_key_fingerprint"`
	Role                    string     `json:"role"`
	AddressFamilies         []string   `json:"address_families"`
	PathModes               []string   `json:"path_modes"`
	NAT                     NATProfile `json:"nat"`
	UpdatedAt               int64      `json:"updated_at,omitempty"`
}

type NATProfile struct {
	Hint             string `json:"hint,omitempty"`
	InboundReachable string `json:"inbound_reachable,omitempty"`
}

type AddressRecord struct {
	Version   int                    `json:"version"`
	Addresses []AddressAdvertisement `json:"addresses"`
	UpdatedAt int64                  `json:"updated_at,omitempty"`
}

type AddressAdvertisement struct {
	ID             string   `json:"id"`
	Source         string   `json:"source"`
	Host           string   `json:"host,omitempty"`
	Address        string   `json:"address,omitempty"`
	Family         string   `json:"family,omitempty"`
	Families       []string `json:"families,omitempty"`
	RefreshSeconds int64    `json:"refresh_seconds,omitempty"`
	Priority       int      `json:"priority,omitempty"`
	Reachability   string   `json:"reachability,omitempty"`
	TTLSeconds     int64    `json:"ttl_seconds,omitempty"`
	LastObserved   int64    `json:"last_observed,omitempty"`
}

type PortRecord struct {
	Version   int             `json:"version"`
	Mode      string          `json:"mode"`
	Range     *PortRange      `json:"range,omitempty"`
	Current   *PortSelection  `json:"current,omitempty"`
	Previous  []PortSelection `json:"previous,omitempty"`
	UpdatedAt int64           `json:"updated_at,omitempty"`
}

type PortRange struct {
	From uint16 `json:"from"`
	To   uint16 `json:"to"`
}

type PortSelection struct {
	Generation uint64      `json:"generation"`
	IKE        PortBinding `json:"ike"`
	NATT       PortBinding `json:"natt"`
	ValidUntil int64       `json:"valid_until,omitempty"`
}

type PortBinding struct {
	Local      uint16 `json:"local,omitempty"`
	Advertised uint16 `json:"advertised,omitempty"`
	Observed   uint16 `json:"observed,omitempty"`
}

type TransportKeyRecord struct {
	Version     int    `json:"version"`
	Kind        string `json:"kind"`
	Algorithm   string `json:"algorithm"`
	PublicKey   string `json:"public_key,omitempty"`
	Fingerprint string `json:"fingerprint"`
	NotBefore   int64  `json:"not_before,omitempty"`
	NotAfter    int64  `json:"not_after,omitempty"`
	UpdatedAt   int64  `json:"updated_at,omitempty"`
}

type OverlayIntentRecord struct {
	Version       int               `json:"version"`
	OverlayID     string            `json:"overlay_id"`
	Provider      string            `json:"provider"`
	PathKeys      []string          `json:"path_keys"`
	TunnelAddress TunnelAddressSpec `json:"tunnel_address,omitempty"`
	PolicyTags    []string          `json:"policy_tags,omitempty"`
	UpdatedAt     int64             `json:"updated_at,omitempty"`
}

type NodeRecords struct {
	Zone           zone.ZonePath
	Profile        *ProfileRecord
	Addresses      *AddressRecord
	Ports          *PortRecord
	TransportKey   *TransportKeyRecord
	OverlayIntents map[string]*OverlayIntentRecord
}

type AddressCandidate struct {
	ID           string
	Source       string
	Host         string
	Address      string
	Family       string
	Priority     int
	Reachability string
	ExpiresAt    time.Time
	RefreshAt    time.Time
}

type PortAdvertisement struct {
	Generation uint64
	IKE        PortBinding
	NATT       PortBinding
	Current    bool
	ValidUntil time.Time
	Observed   bool
}

type ContactPoint struct {
	AddressID    string
	Source       string
	Host         string
	Address      string
	Family       string
	Reachability string
	Priority     int
	Generation   uint64
	Current      bool
	IKEPort      uint16
	NATTPort     uint16
	ObservedPort bool
	Successes    int
	Failures     int
	BackoffUntil time.Time
	RankReason   string
}

type DNSResolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

type ContactPointQuality struct {
	Successes    int
	Failures     int
	BackoffUntil time.Time
}

type AddressCandidateOptions struct {
	DNSResolver       DNSResolver
	SourceOrder       []string
	AllowedSources    []string
	AllowPrivateLocal bool
	Now               time.Time
	ContactQuality    map[string]ContactPointQuality
}

func ParseProfileRecord(record *zone.Record) (*ProfileRecord, error) {
	var profile ProfileRecord
	if err := parseIPsecRecord(record, RecordKeyProfile, RecordTypeProfile, &profile); err != nil {
		return nil, err
	}
	if err := profile.Validate(record.Zone); err != nil {
		return nil, err
	}
	return &profile, nil
}

func ParseAddressRecord(record *zone.Record) (*AddressRecord, error) {
	var addresses AddressRecord
	if err := parseIPsecRecord(record, RecordKeyAddresses, RecordTypeAddresses, &addresses); err != nil {
		return nil, err
	}
	if err := addresses.Validate(); err != nil {
		return nil, err
	}
	return &addresses, nil
}

func ParsePortRecord(record *zone.Record) (*PortRecord, error) {
	var ports PortRecord
	if err := parseIPsecRecord(record, RecordKeyPorts, RecordTypePorts, &ports); err != nil {
		return nil, err
	}
	if err := ports.Validate(); err != nil {
		return nil, err
	}
	return &ports, nil
}

func ParseTransportKeyRecord(record *zone.Record) (*TransportKeyRecord, error) {
	var key TransportKeyRecord
	if err := parseIPsecRecord(record, RecordKeyTransportKey, RecordTypeTransportKey, &key); err != nil {
		return nil, err
	}
	if err := key.Validate(); err != nil {
		return nil, err
	}
	return &key, nil
}

func OverlayIntentRecordKey(overlayID string) string {
	return RecordKeyOverlayPrefix + overlayID
}

func ParseOverlayIntentRecord(record *zone.Record) (*OverlayIntentRecord, error) {
	if record == nil {
		return nil, errors.New("record is nil")
	}
	if !strings.HasPrefix(record.Key, RecordKeyOverlayPrefix) {
		return nil, fmt.Errorf("unexpected record key %q, want %s<overlay_id>", record.Key, RecordKeyOverlayPrefix)
	}
	var intent OverlayIntentRecord
	if err := parseIPsecRecord(record, record.Key, RecordTypeOverlayIntent, &intent); err != nil {
		return nil, err
	}
	keyOverlay := strings.TrimPrefix(record.Key, RecordKeyOverlayPrefix)
	if err := intent.Validate(keyOverlay); err != nil {
		return nil, err
	}
	return &intent, nil
}

func ExtractNodeRecords(ns *zone.NetworkState, peer zone.ZonePath, now time.Time) (*NodeRecords, error) {
	if ns == nil {
		return nil, errors.New("network state is nil")
	}
	if ns.IsZoneRevoked(peer, now) {
		return nil, fmt.Errorf("zone %s is revoked", peer)
	}
	zs := ns.Zones[peer]
	if zs == nil {
		return nil, fmt.Errorf("zone %s not found", peer)
	}
	out := &NodeRecords{Zone: peer}
	var err error
	if record := zs.Records[RecordKeyProfile]; record != nil {
		out.Profile, err = ParseProfileRecord(record)
		if err != nil {
			return nil, err
		}
	}
	if record := zs.Records[RecordKeyAddresses]; record != nil {
		out.Addresses, err = ParseAddressRecord(record)
		if err != nil {
			return nil, err
		}
	}
	if record := zs.Records[RecordKeyPorts]; record != nil {
		out.Ports, err = ParsePortRecord(record)
		if err != nil {
			return nil, err
		}
	}
	if record := zs.Records[RecordKeyTransportKey]; record != nil {
		out.TransportKey, err = ParseTransportKeyRecord(record)
		if err != nil {
			return nil, err
		}
	}
	for key, record := range zs.Records {
		if !strings.HasPrefix(key, RecordKeyOverlayPrefix) {
			continue
		}
		intent, err := ParseOverlayIntentRecord(record)
		if err != nil {
			return nil, err
		}
		if out.OverlayIntents == nil {
			out.OverlayIntents = map[string]*OverlayIntentRecord{}
		}
		out.OverlayIntents[intent.OverlayID] = intent
	}
	return out, nil
}

func (p ProfileRecord) Validate(owner zone.ZonePath) error {
	if p.Version != 1 {
		return fmt.Errorf("unsupported ipsec profile version %d", p.Version)
	}
	if p.Provider != ProviderStrongSwan {
		return fmt.Errorf("unsupported ipsec provider %q", p.Provider)
	}
	if p.IKEIdentity == "" {
		return errors.New("ike_identity is required")
	}
	if owner.Valid() && p.IKEIdentity != string(owner) {
		return fmt.Errorf("ike_identity %q does not match zone %s", p.IKEIdentity, owner)
	}
	if p.TransportKeyFingerprint == "" {
		return errors.New("transport_key_fingerprint is required")
	}
	if !oneOf(p.Role, RoleOut, RoleIn, RoleBoth) {
		return fmt.Errorf("unsupported ipsec role %q", p.Role)
	}
	if p.NAT.Hint != "" && !oneOf(p.NAT.Hint, NATHintPublic, NATHintBehindNAT, NATHintUnknown) {
		return fmt.Errorf("unsupported nat hint %q", p.NAT.Hint)
	}
	if p.NAT.InboundReachable != "" && !oneOf(p.NAT.InboundReachable, NATReachableTrue, NATReachableFalse, NATReachableUnknown) {
		return fmt.Errorf("unsupported nat inbound_reachable %q", p.NAT.InboundReachable)
	}
	if len(p.AddressFamilies) == 0 {
		return errors.New("address_families is required")
	}
	for _, family := range p.AddressFamilies {
		if !validFamily(family) {
			return fmt.Errorf("unsupported address family %q", family)
		}
	}
	if len(p.PathModes) == 0 {
		return errors.New("path_modes is required")
	}
	for _, mode := range p.PathModes {
		if !oneOf(mode, PathModeFamilyRedundant, PathModeExhaustive) {
			return fmt.Errorf("unsupported path mode %q", mode)
		}
	}
	return nil
}

func (r AddressRecord) Validate() error {
	if r.Version != 1 {
		return fmt.Errorf("unsupported ipsec addresses version %d", r.Version)
	}
	for _, address := range r.Addresses {
		if err := address.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func (a AddressAdvertisement) Validate() error {
	if a.ID == "" {
		return errors.New("address id is required")
	}
	if !oneOf(a.Source, SourceManualAddress, SourceManualDNS, SourceDiscovery, SourceReflector, SourceLocal) {
		return fmt.Errorf("unsupported address source %q", a.Source)
	}
	switch a.Source {
	case SourceManualDNS:
		if a.Host == "" {
			return fmt.Errorf("address %s: host is required for manual-dns", a.ID)
		}
		if len(addressFamilies(a)) == 0 {
			return fmt.Errorf("address %s: families is required for manual-dns", a.ID)
		}
	case SourceManualAddress, SourceReflector, SourceLocal:
		if a.Address == "" {
			return fmt.Errorf("address %s: address is required for %s", a.ID, a.Source)
		}
		if ip := net.ParseIP(a.Address); ip == nil {
			return fmt.Errorf("address %s: invalid IP %q", a.ID, a.Address)
		}
		family := a.Family
		if family == "" {
			family = inferIPFamily(a.Address)
		}
		if !validFamily(family) {
			return fmt.Errorf("address %s: unsupported family %q", a.ID, family)
		}
	case SourceDiscovery:
		if a.Address == "" && a.Host == "" {
			return fmt.Errorf("address %s: discovery source requires address or host", a.ID)
		}
	}
	for _, family := range addressFamilies(a) {
		if !validFamily(family) {
			return fmt.Errorf("address %s: unsupported family %q", a.ID, family)
		}
	}
	return nil
}

func (r PortRecord) Validate() error {
	if r.Version != 1 {
		return fmt.Errorf("unsupported ipsec ports version %d", r.Version)
	}
	if !oneOf(r.Mode, PortModeFixed, PortModeRange) {
		return fmt.Errorf("unsupported port mode %q", r.Mode)
	}
	if r.Mode == PortModeRange {
		if r.Range == nil {
			return errors.New("range mode requires range")
		}
		if r.Range.From == 0 || r.Range.To == 0 || r.Range.From > r.Range.To {
			return fmt.Errorf("invalid port range %d-%d", r.Range.From, r.Range.To)
		}
	}
	if r.Current == nil {
		return errors.New("current port selection is required")
	}
	if err := r.Current.Validate(); err != nil {
		return err
	}
	for i := range r.Previous {
		if err := r.Previous[i].Validate(); err != nil {
			return err
		}
	}
	return nil
}

func (p PortSelection) Validate() error {
	if p.IKE.Advertised == 0 && p.IKE.Observed == 0 {
		return errors.New("ike advertised or observed port is required")
	}
	if p.NATT.Advertised == 0 && p.NATT.Observed == 0 {
		return errors.New("natt advertised or observed port is required")
	}
	return nil
}

func (k TransportKeyRecord) Validate() error {
	if k.Version != 1 {
		return fmt.Errorf("unsupported ipsec transport key version %d", k.Version)
	}
	if k.Kind != TransportKeyRawPublicKey {
		return fmt.Errorf("unsupported transport key kind %q", k.Kind)
	}
	if !oneOf(k.Algorithm, AlgorithmEd25519, AlgorithmECDSAP256) {
		return fmt.Errorf("unsupported transport key algorithm %q", k.Algorithm)
	}
	if k.PublicKey == "" {
		return errors.New("public_key is required")
	}
	if k.Fingerprint == "" {
		return errors.New("fingerprint is required")
	}
	if k.NotAfter != 0 && k.NotBefore != 0 && k.NotAfter <= k.NotBefore {
		return errors.New("not_after must be after not_before")
	}
	return nil
}

func (r OverlayIntentRecord) Validate(keyOverlayID string) error {
	if r.Version != 1 {
		return fmt.Errorf("unsupported ipsec overlay intent version %d", r.Version)
	}
	if r.OverlayID == "" {
		return errors.New("overlay_id is required")
	}
	if keyOverlayID != "" && r.OverlayID != keyOverlayID {
		return fmt.Errorf("overlay_id %q does not match record key overlay %q", r.OverlayID, keyOverlayID)
	}
	provider := r.Provider
	if provider == "" {
		provider = ProviderStrongSwan
	}
	if provider != ProviderStrongSwan {
		return fmt.Errorf("unsupported overlay intent provider %q", provider)
	}
	if len(r.PathKeys) == 0 {
		return errors.New("path_keys is required")
	}
	seen := map[string]bool{}
	for _, pathKey := range r.PathKeys {
		pathKey = strings.TrimSpace(pathKey)
		if pathKey == "" {
			return errors.New("path_keys must not contain empty values")
		}
		if seen[pathKey] {
			return fmt.Errorf("duplicate path_key %q", pathKey)
		}
		seen[pathKey] = true
		if pathKey == DefaultPathKey {
			continue
		}
		if strings.HasPrefix(pathKey, "family:") && validFamily(strings.TrimPrefix(pathKey, "family:")) {
			continue
		}
		return fmt.Errorf("unsupported path_key %q", pathKey)
	}
	switch r.TunnelAddress.Mode {
	case TunnelAddressDisabled, TunnelAddressDerivedLinkLocal, TunnelAddressDerivedPool, TunnelAddressSequentialPool:
		// ok
	case "":
		return errors.New("tunnel_address.mode is required")
	default:
		return fmt.Errorf("unsupported tunnel address mode %q", r.TunnelAddress.Mode)
	}
	if r.TunnelAddress.Mode != TunnelAddressDisabled && r.TunnelAddress.Family == "" {
		return errors.New("tunnel_address.family is required")
	}
	if r.TunnelAddress.Family != "" && !validFamily(r.TunnelAddress.Family) {
		return fmt.Errorf("unsupported tunnel address family %q", r.TunnelAddress.Family)
	}
	if (r.TunnelAddress.Mode == TunnelAddressDerivedPool || r.TunnelAddress.Mode == TunnelAddressSequentialPool) && !r.TunnelAddress.Pool.IsValid() {
		return fmt.Errorf("tunnel address mode %q requires a pool", r.TunnelAddress.Mode)
	}
	if r.TunnelAddress.Pool.IsValid() && r.TunnelAddress.Family != "" {
		if r.TunnelAddress.Pool.Addr().Is4() && r.TunnelAddress.Family != FamilyIPv4 {
			return fmt.Errorf("tunnel address family %q does not match pool %s", r.TunnelAddress.Family, r.TunnelAddress.Pool)
		}
		if r.TunnelAddress.Pool.Addr().Is6() && r.TunnelAddress.Family != FamilyIPv6 {
			return fmt.Errorf("tunnel address family %q does not match pool %s", r.TunnelAddress.Family, r.TunnelAddress.Pool)
		}
	}
	return nil
}

func ResolveAddressCandidates(ctx context.Context, record *AddressRecord, now time.Time, opts AddressCandidateOptions) ([]AddressCandidate, error) {
	if record == nil {
		return nil, nil
	}
	var out []AddressCandidate
	for _, address := range record.Addresses {
		if !sourceAllowed(address.Source, opts.AllowedSources) {
			continue
		}
		if addressExpired(address, record.UpdatedAt, now) {
			continue
		}
		expiresAt := expiryForAddress(address, record.UpdatedAt)
		refreshAt := refreshForAddress(address, record.UpdatedAt)
		if address.Host != "" && opts.DNSResolver != nil && (address.Source == SourceManualDNS || address.Source == SourceDiscovery) {
			resolved, err := opts.DNSResolver.LookupIPAddr(ctx, address.Host)
			if err != nil {
				return nil, fmt.Errorf("resolve address %s host %q: %w", address.ID, address.Host, err)
			}
			// Sort resolved IPs so family-redundant selection is deterministic
			// even if the OS resolver returns addresses in varying order.
			sort.SliceStable(resolved, func(i, j int) bool {
				return resolved[i].String() < resolved[j].String()
			})
			for _, ipAddr := range resolved {
				ip := ipAddr.IP
				if ip == nil {
					continue
				}
				family := inferIPFamily(ip.String())
				if !familyAllowed(family, addressFamilies(address)) {
					continue
				}
				candidate := newAddressCandidate(address, ip.String(), family, expiresAt, refreshAt)
				if candidateAllowed(candidate, opts) {
					out = append(out, candidate)
				}
			}
			continue
		}
		for _, family := range addressFamilies(address) {
			candidate := newAddressCandidate(address, address.Address, family, expiresAt, refreshAt)
			if candidate.Address == "" && address.Source != SourceManualDNS {
				continue
			}
			if !candidateAllowed(candidate, opts) {
				continue
			}
			out = append(out, candidate)
		}
	}
	sortAddressCandidates(out, opts.SourceOrder)
	return out, nil
}

func newAddressCandidate(address AddressAdvertisement, resolvedAddress, family string, expiresAt, refreshAt time.Time) AddressCandidate {
	candidate := AddressCandidate{
		ID:           address.ID,
		Source:       address.Source,
		Host:         address.Host,
		Address:      resolvedAddress,
		Family:       family,
		Priority:     address.Priority,
		Reachability: address.Reachability,
		ExpiresAt:    expiresAt,
		RefreshAt:    refreshAt,
	}
	if candidate.Reachability == "" {
		candidate.Reachability = ReachabilityUnknown
	}
	return candidate
}

func sortAddressCandidates(out []AddressCandidate, sourceOrder []string) {
	sort.SliceStable(out, func(i, j int) bool {
		if sourceRank(out[i].Source, sourceOrder) != sourceRank(out[j].Source, sourceOrder) {
			return sourceRank(out[i].Source, sourceOrder) < sourceRank(out[j].Source, sourceOrder)
		}
		if out[i].Priority != out[j].Priority {
			return out[i].Priority > out[j].Priority
		}
		if out[i].Family != out[j].Family {
			return out[i].Family < out[j].Family
		}
		if out[i].Address != out[j].Address {
			return out[i].Address < out[j].Address
		}
		return out[i].ID < out[j].ID
	})
}

func PortAdvertisements(record *PortRecord, now time.Time) []PortAdvertisement {
	if record == nil {
		return nil
	}
	var out []PortAdvertisement
	if record.Current != nil && !portSelectionExpired(*record.Current, now) {
		out = append(out, portAdvertisement(*record.Current, true))
	}
	for _, previous := range record.Previous {
		if portSelectionExpired(previous, now) {
			continue
		}
		out = append(out, portAdvertisement(previous, false))
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Current != out[j].Current {
			return out[i].Current
		}
		return out[i].Generation > out[j].Generation
	})
	return out
}

func ResolveContactPoints(ctx context.Context, addresses *AddressRecord, ports *PortRecord, now time.Time, opts AddressCandidateOptions) ([]ContactPoint, error) {
	addressCandidates, err := ResolveAddressCandidates(ctx, addresses, now, opts)
	if err != nil {
		return nil, err
	}
	portAds := PortAdvertisements(ports, now)
	out := make([]ContactPoint, 0, len(addressCandidates)*len(portAds))
	for _, address := range addressCandidates {
		if address.Address == "" {
			continue
		}
		for _, port := range portAds {
			out = append(out, ContactPoint{
				AddressID:    address.ID,
				Source:       address.Source,
				Host:         address.Host,
				Address:      address.Address,
				Family:       address.Family,
				Reachability: address.Reachability,
				Priority:     address.Priority,
				Generation:   port.Generation,
				Current:      port.Current,
				IKEPort:      dialPort(port.IKE),
				NATTPort:     dialPort(port.NATT),
				ObservedPort: port.Observed,
			})
		}
	}
	annotateContactPoints(out, opts)
	sortContactPoints(out, opts)
	return out, nil
}

func SelectContactPointsWithOptions(points []ContactPoint, mode string, opts AddressCandidateOptions) []ContactPoint {
	points = append([]ContactPoint(nil), points...)
	annotateContactPoints(points, opts)
	sortContactPoints(points, opts)
	if mode == PathModeExhaustive {
		return points
	}
	if mode != PathModeFamilyRedundant {
		return nil
	}
	seen := map[string]bool{}
	var out []ContactPoint
	for _, point := range points {
		if seen[point.Family] {
			continue
		}
		seen[point.Family] = true
		out = append(out, point)
	}
	return out
}

func (p ContactPoint) Key() string {
	return fmt.Sprintf("%s|%s|%d|%d|%d", p.AddressID, p.Address, p.Generation, p.IKEPort, p.NATTPort)
}

func parseIPsecRecord(record *zone.Record, key, recordType string, into any) error {
	if record == nil {
		return errors.New("record is nil")
	}
	if record.Key != key {
		return fmt.Errorf("unexpected record key %q, want %q", record.Key, key)
	}
	if record.Type != recordType {
		return fmt.Errorf("unexpected record type %q, want %q", record.Type, recordType)
	}
	if err := json.Unmarshal(record.Value, into); err != nil {
		return err
	}
	return nil
}

func addressFamilies(a AddressAdvertisement) []string {
	if len(a.Families) > 0 {
		return normalizedFamilies(a.Families)
	}
	if a.Family != "" {
		return normalizedFamilies([]string{a.Family})
	}
	if a.Address != "" {
		if family := inferIPFamily(a.Address); family != "" {
			return []string{family}
		}
	}
	return nil
}

func normalizedFamilies(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, family := range in {
		family = strings.ToLower(strings.TrimSpace(family))
		if family == "" || seen[family] {
			continue
		}
		seen[family] = true
		out = append(out, family)
	}
	return out
}

func inferIPFamily(address string) string {
	ip := net.ParseIP(address)
	if ip == nil {
		return ""
	}
	if ip.To4() != nil {
		return FamilyIPv4
	}
	return FamilyIPv6
}

func validFamily(family string) bool {
	return family == FamilyIPv4 || family == FamilyIPv6
}

func addressExpired(address AddressAdvertisement, recordUpdatedAt int64, now time.Time) bool {
	expiresAt := expiryForAddress(address, recordUpdatedAt)
	return !expiresAt.IsZero() && now.After(expiresAt)
}

func expiryForAddress(address AddressAdvertisement, recordUpdatedAt int64) time.Time {
	if address.TTLSeconds <= 0 {
		return time.Time{}
	}
	base := address.LastObserved
	if base == 0 {
		base = recordUpdatedAt
	}
	if base == 0 {
		return time.Time{}
	}
	return time.Unix(base, 0).Add(time.Duration(address.TTLSeconds) * time.Second)
}

func refreshForAddress(address AddressAdvertisement, recordUpdatedAt int64) time.Time {
	if address.RefreshSeconds <= 0 || recordUpdatedAt == 0 {
		return time.Time{}
	}
	return time.Unix(recordUpdatedAt, 0).Add(time.Duration(address.RefreshSeconds) * time.Second)
}

func familyAllowed(family string, allowed []string) bool {
	return slices.Contains(allowed, family)
}

func portSelectionExpired(selection PortSelection, now time.Time) bool {
	return selection.ValidUntil != 0 && now.After(time.Unix(selection.ValidUntil, 0))
}

func portAdvertisement(selection PortSelection, current bool) PortAdvertisement {
	out := PortAdvertisement{
		Generation: selection.Generation,
		IKE:        selection.IKE,
		NATT:       selection.NATT,
		Current:    current,
	}
	if selection.ValidUntil != 0 {
		out.ValidUntil = time.Unix(selection.ValidUntil, 0)
	}
	out.Observed = selection.IKE.Observed != 0 || selection.NATT.Observed != 0
	return out
}

func dialPort(binding PortBinding) uint16 {
	if binding.Observed != 0 {
		return binding.Observed
	}
	return binding.Advertised
}

func sortContactPoints(points []ContactPoint, opts AddressCandidateOptions) {
	sort.SliceStable(points, func(i, j int) bool {
		if sourceRank(points[i].Source, opts.SourceOrder) != sourceRank(points[j].Source, opts.SourceOrder) {
			return sourceRank(points[i].Source, opts.SourceOrder) < sourceRank(points[j].Source, opts.SourceOrder)
		}
		if reachabilityRank(points[i].Reachability) != reachabilityRank(points[j].Reachability) {
			return reachabilityRank(points[i].Reachability) < reachabilityRank(points[j].Reachability)
		}
		if points[i].Priority != points[j].Priority {
			return points[i].Priority > points[j].Priority
		}
		if contactInBackoff(points[i], opts.Now) != contactInBackoff(points[j], opts.Now) {
			return !contactInBackoff(points[i], opts.Now)
		}
		if points[i].Current != points[j].Current {
			return points[i].Current
		}
		if points[i].Generation != points[j].Generation {
			return points[i].Generation > points[j].Generation
		}
		if contactSuccessRate(points[i]) != contactSuccessRate(points[j]) {
			return contactSuccessRate(points[i]) > contactSuccessRate(points[j])
		}
		if points[i].Failures != points[j].Failures {
			return points[i].Failures < points[j].Failures
		}
		if points[i].Family != points[j].Family {
			return points[i].Family < points[j].Family
		}
		if points[i].AddressID != points[j].AddressID {
			return points[i].AddressID < points[j].AddressID
		}
		return points[i].Address < points[j].Address
	})
}

func annotateContactPoints(points []ContactPoint, opts AddressCandidateOptions) {
	for i := range points {
		if opts.ContactQuality != nil {
			if quality, ok := opts.ContactQuality[points[i].Key()]; ok {
				points[i].Successes = quality.Successes
				points[i].Failures = quality.Failures
				points[i].BackoffUntil = quality.BackoffUntil
			}
		}
		points[i].RankReason = contactRankReason(points[i], opts.Now)
	}
}

func reachabilityRank(reachability string) int {
	switch reachability {
	case ReachabilityPublic:
		return 0
	case ReachabilityNATObserved:
		return 1
	case ReachabilityUnknown:
		return 2
	case ReachabilityPrivate:
		return 3
	default:
		return 4
	}
}

func contactInBackoff(point ContactPoint, now time.Time) bool {
	return !point.BackoffUntil.IsZero() && !now.IsZero() && now.Before(point.BackoffUntil)
}

func contactSuccessRate(point ContactPoint) float64 {
	total := point.Successes + point.Failures
	if total == 0 {
		return 0
	}
	return float64(point.Successes) / float64(total)
}

func contactRankReason(point ContactPoint, now time.Time) string {
	parts := []string{point.Source}
	if point.Reachability != "" {
		parts = append(parts, point.Reachability)
	}
	if point.Current {
		parts = append(parts, "current-port")
	} else {
		parts = append(parts, "previous-port")
	}
	if contactInBackoff(point, now) {
		parts = append(parts, "backoff")
	}
	if point.Failures > 0 {
		parts = append(parts, fmt.Sprintf("failures=%d", point.Failures))
	}
	if point.Successes > 0 {
		parts = append(parts, fmt.Sprintf("successes=%d", point.Successes))
	}
	return strings.Join(parts, ",")
}

func sourceRank(source string, sourceOrder []string) int {
	if len(sourceOrder) == 0 {
		sourceOrder = defaultAddressSourceOrder
	}
	for i, known := range sourceOrder {
		if source == known {
			return i
		}
	}
	return len(sourceOrder)
}

func sourceAllowed(source string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	return slices.Contains(allowed, source)
}

func candidateAllowed(candidate AddressCandidate, opts AddressCandidateOptions) bool {
	if candidate.Source != SourceLocal || opts.AllowPrivateLocal {
		return true
	}
	ip := net.ParseIP(candidate.Address)
	if ip == nil {
		return true
	}
	return !isPrivateOrLinkLocal(ip)
}

func isPrivateOrLinkLocal(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 10 ||
			(ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31) ||
			(ip4[0] == 192 && ip4[1] == 168)
	}
	return len(ip) == net.IPv6len && ip[0]&0xfe == 0xfc
}

func ValidPortMode(mode string) bool {
	return oneOf(mode, PortModeFixed, PortModeRange)
}

func oneOf(value string, allowed ...string) bool {
	return slices.Contains(allowed, value)
}
