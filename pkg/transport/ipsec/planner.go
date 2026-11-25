package ipsec

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

const (
	SkipLocalZone             = "local_zone"
	SkipRevokedZone           = "revoked_zone"
	SkipLifecycleCleanup      = "lifecycle_cleanup"
	SkipMissingRecords        = "missing_ipsec_records"
	SkipDisabledProfile       = "disabled_profile"
	SkipUnsupportedPathMode   = "unsupported_path_mode"
	SkipUnsupportedFamily     = "unsupported_address_family"
	SkipRoleMismatch          = "role_mismatch"
	SkipNoContactPoints       = "no_contact_points"
	SkipPeerOverrideEndpoint  = "peer_override_endpoint"
	SkipNoInboundNATEvidence  = "no_inbound_nat_evidence"
	SkipMissingOverlayIntent  = "missing_overlay_intent"
	SkipOverlayIntentMismatch = "overlay_intent_mismatch"
	SkipPolicyDenied          = "policy_denied"
	SkipPolicyNoMatch         = "policy_no_match"
	SkipRemotePolicy          = "remote_policy"
	SkipMaxPeers              = "max_peers"
	SkipPlannerError          = "planner_error"
)

type LinkPlannerOptions struct {
	Now time.Time
	// Nil allows MOBIKE as a responder for opted-in outbound peers.
	// Initiating MOBIKE requires an explicit true.
	MOBIKE              *bool
	DNSResolver         DNSResolver
	AllowPrivateLocal   bool
	ContactPointQuality map[zone.ZonePath]map[string]ContactPointQuality
	ExcludedPeers       map[zone.ZonePath]string
	EstablishedSAs      []SAState
	establishedByName   map[string][]SAState
}

type LinkPlan struct {
	Desired []TransportLinkSpec
	Skipped []PlanSkip
	Roles   map[string]string // instance ID -> InitiatorRole
}

type PlanSkip struct {
	GroupID string
	Peer    zone.ZonePath
	Reason  string
	Detail  string
}

func PlanTransportLinks(ctx context.Context, ns *zone.NetworkState, local zone.ZonePath, groups []LinkGroupSpec, opts LinkPlannerOptions) (LinkPlan, error) {
	if ns == nil {
		return LinkPlan{}, fmt.Errorf("network state is nil")
	}
	if !local.Valid() || local.IsRoot() {
		return LinkPlan{}, fmt.Errorf("local zone must be a non-root zone")
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	// Index once per plan rather than scanning every peer's SAs for each address.
	opts.establishedByName = make(map[string][]SAState)
	for _, sa := range opts.EstablishedSAs {
		if sa.Established {
			opts.establishedByName[sa.Name] = append(opts.establishedByName[sa.Name], sa)
		}
	}
	peers := sortedZones(ns)
	plan := LinkPlan{Roles: map[string]string{}}
	for _, group := range groups {
		if err := group.Validate(); err != nil {
			return plan, err
		}
		group = group.Normalized()
		connectRules, err := ParseMeshPolicyRules(group.ConnectRules)
		if err != nil {
			return plan, err
		}
		denyRules, err := ParseMeshPolicyRules(group.DenyRules)
		if err != nil {
			return plan, err
		}
		selectedPeers := 0
		linkIndex := 0
		for _, peer := range peers {
			if peer == local {
				plan.skip(group.ID, peer, SkipLocalZone, "")
				continue
			}
			if ns.IsZoneRevoked(peer, now) {
				plan.skip(group.ID, peer, SkipRevokedZone, "")
				continue
			}
			if detail, excluded := opts.ExcludedPeers[peer]; excluded {
				plan.skip(group.ID, peer, SkipLifecycleCleanup, detail)
				continue
			}
			specs, ok, skip, nextIndex, err := planPeerLink(ctx, ns, local, peer, group, connectRules, denyRules, selectedPeers, linkIndex, now, opts)
			if err != nil {
				plan.skip(group.ID, peer, SkipPlannerError, err.Error())
				continue
			}
			if skip.Reason != "" {
				plan.Skipped = append(plan.Skipped, skip)
			}
			if !ok {
				continue
			}
			for _, spec := range specs {
				plan.Desired = append(plan.Desired, spec)
				plan.Roles[LinkInstanceID(spec)] = spec.InitiatorRole
				if spec.TransportID != "" {
					plan.Roles[spec.TransportID] = spec.InitiatorRole
				}
			}
			selectedPeers++
			linkIndex = nextIndex
		}
	}
	sort.SliceStable(plan.Desired, func(i, j int) bool {
		if plan.Desired[i].OverlayID != plan.Desired[j].OverlayID {
			return plan.Desired[i].OverlayID < plan.Desired[j].OverlayID
		}
		if plan.Desired[i].PeerZone != plan.Desired[j].PeerZone {
			return plan.Desired[i].PeerZone < plan.Desired[j].PeerZone
		}
		if plan.Desired[i].PathKey != plan.Desired[j].PathKey {
			return plan.Desired[i].PathKey < plan.Desired[j].PathKey
		}
		return plan.Desired[i].TransportID < plan.Desired[j].TransportID
	})
	return plan, nil
}

func planPeerLink(ctx context.Context, ns *zone.NetworkState, local, peer zone.ZonePath, group LinkGroupSpec, connectRules, denyRules []MeshPolicyRule, selectedPeers, linkIndex int, now time.Time, opts LinkPlannerOptions) ([]TransportLinkSpec, bool, PlanSkip, int, error) {
	records, err := ExtractNodeRecords(ns, peer, now)
	if err != nil {
		return nil, false, PlanSkip{GroupID: group.ID, Peer: peer, Reason: SkipMissingRecords, Detail: err.Error()}, linkIndex, nil
	}
	if records.Profile == nil || records.Addresses == nil || records.Ports == nil || records.TransportKey == nil {
		return nil, false, PlanSkip{GroupID: group.ID, Peer: peer, Reason: SkipMissingRecords}, linkIndex, nil
	}
	effectiveGroup, ok, skip, err := applyMeshPolicyRules(group, peer, records, connectRules, denyRules)
	if err != nil {
		return nil, false, PlanSkip{}, linkIndex, err
	}
	if !ok {
		return nil, false, skip, linkIndex, nil
	}
	group = effectiveGroup
	intent := records.OverlayIntents[group.ID]
	if intent == nil {
		return nil, false, PlanSkip{GroupID: group.ID, Peer: peer, Reason: SkipMissingOverlayIntent, Detail: group.ID}, linkIndex, nil
	}
	if len(intent.Connect) > 0 || len(intent.Deny) > 0 {
		localRecords, err := ExtractNodeRecords(ns, local, now)
		if err != nil {
			return nil, false, PlanSkip{GroupID: group.ID, Peer: peer, Reason: SkipMissingRecords, Detail: "local policy identity: " + err.Error()}, linkIndex, nil
		}
		if err := intent.CheckPeerPolicy(local, localRecords); err != nil {
			return nil, false, PlanSkip{GroupID: group.ID, Peer: peer, Reason: SkipRemotePolicy, Detail: err.Error()}, linkIndex, nil
		}
	}
	if intent.Provider != "" && intent.Provider != group.Provider {
		return nil, false, PlanSkip{GroupID: group.ID, Peer: peer, Reason: SkipOverlayIntentMismatch, Detail: fmt.Sprintf("provider=%s", intent.Provider)}, linkIndex, nil
	}
	if !overlayIntentTunnelAddressCompatible(group, intent) {
		return nil, false, PlanSkip{GroupID: group.ID, Peer: peer, Reason: SkipOverlayIntentMismatch, Detail: fmt.Sprintf("tunnel_address=%s/%s/%s", intent.TunnelAddress.Mode, intent.TunnelAddress.Family, intent.TunnelAddress.Pool)}, linkIndex, nil
	}
	if group.MaxPeers > 0 && selectedPeers >= group.MaxPeers {
		return nil, false, PlanSkip{GroupID: group.ID, Peer: peer, Reason: SkipMaxPeers}, linkIndex, nil
	}
	if !records.Profile.Enabled {
		return nil, false, PlanSkip{GroupID: group.ID, Peer: peer, Reason: SkipDisabledProfile}, linkIndex, nil
	}
	if !oneOf(group.DefaultPathMode, records.Profile.PathModes...) {
		return nil, false, PlanSkip{GroupID: group.ID, Peer: peer, Reason: SkipUnsupportedPathMode, Detail: group.DefaultPathMode}, linkIndex, nil
	}
	override := group.peerOverride(peer)
	remoteRoleOverride := intent.PeerRoles[local]
	localRole := override.Role
	if localRole == "" {
		localRole = localRoleFromState(ns, local, now)
	}
	remoteRole := firstNonEmptyString(remoteRoleOverride, records.Profile.Role)
	role := InitiatorRoleForPeer(local, peer, localRole, remoteRole)
	bothPassiveOverrides := (override.Role != "" || remoteRoleOverride != "") && localRole == RoleIn && remoteRole == RoleIn
	if role == "" && (!canLoadResponder(localRole) || bothPassiveOverrides) {
		return nil, false, PlanSkip{GroupID: group.ID, Peer: peer, Reason: SkipRoleMismatch, Detail: fmt.Sprintf("local=%s remote=%s", localRole, remoteRole)}, linkIndex, nil
	}
	if role != "" && len(override.Endpoints) == 0 && !familiesOverlap(records.Profile.AddressFamilies, recordFamilies(records.Addresses)) {
		return nil, false, PlanSkip{GroupID: group.ID, Peer: peer, Reason: SkipUnsupportedFamily}, linkIndex, nil
	}

	var contacts []ContactPoint
	var endpointSkip PlanSkip
	// Both primary and secondary-standby need contact points: primary dials
	// immediately, secondary-standby may need them for takeover. Responder-only
	// roles (empty role) do not resolve remote contacts.
	if role != "" {
		candidateOpts := AddressCandidateOptions{
			DNSResolver:       opts.DNSResolver,
			SourceOrder:       group.AddressSourceOrder,
			AllowedSources:    group.AddressSourceOrder,
			AllowPrivateLocal: opts.AllowPrivateLocal,
			Now:               now,
			ContactQuality:    opts.ContactPointQuality[peer],
		}
		allContacts, overrideDetail, err := resolvePeerContactPoints(ctx, records, override, group.AllowedAddressFamilies, now, candidateOpts)
		if err != nil {
			return nil, false, PlanSkip{}, linkIndex, err
		}
		allContacts = filterContactPointsByFamily(allContacts, group.AllowedAddressFamilies)
		if overrideDetail != "" {
			endpointSkip = PlanSkip{GroupID: group.ID, Peer: peer, Reason: SkipPeerOverrideEndpoint, Detail: overrideDetail}
			if len(allContacts) == 0 {
				return nil, false, endpointSkip, linkIndex, nil
			}
		}
		if remoteNeedsInboundNATEvidence(records.Profile) {
			allContacts = filterInboundNATEvidence(allContacts)
			if len(allContacts) == 0 {
				return nil, false, PlanSkip{GroupID: group.ID, Peer: peer, Reason: SkipNoInboundNATEvidence, Detail: natEvidenceDetail(records.Profile)}, linkIndex, nil
			}
		}
		// Retain a current-generation endpoint with an established SA. Only
		// candidates still allowed by local policy and the signed record qualify.
		established := map[string]bool{}
		for _, point := range allContacts {
			if !point.Current {
				continue
			}
			pathKey := DefaultPathKey
			if group.DefaultPathMode == PathModeFamilyRedundant {
				pathKey = "family:" + point.Family
			}
			linkID := StableLinkID(local, peer, group.ID, pathKey)
			generation := runtimeGenerationForPortGeneration(point.Generation)
			name := RuntimeConnectionID(linkID, generation, group.Provider)
			ifID := RuntimeXFRMIfID(linkID, generation, group.Provider)
			for _, sa := range opts.establishedByName[name] {
				if !sa.Established || sa.LocalIdentity != string(local) || sa.RemoteIdentity != string(peer) || sa.XFRMIfID != ifID || sa.Name != name {
					continue
				}
				host, port, err := net.SplitHostPort(firstNonEmptyString(sa.RemoteEndpoint, sa.Endpoint))
				if err == nil && contactHostMatches(host, point) && portMatchesContactPoint(port, point) {
					established[point.Key()] = true
				}
			}
		}
		contacts = SelectContactPointsWithOptions(allContacts, group.DefaultPathMode, AddressCandidateOptions{
			SourceOrder:         group.AddressSourceOrder,
			Now:                 now,
			ContactQuality:      opts.ContactPointQuality[peer],
			EstablishedContacts: established,
		})
		if len(contacts) == 0 {
			return nil, false, PlanSkip{GroupID: group.ID, Peer: peer, Reason: SkipNoContactPoints}, linkIndex, nil
		}
	}

	var specs []TransportLinkSpec
	var specLinkIndexes []int
	nextIndex := linkIndex
	switch group.DefaultPathMode {
	case PathModeFamilyRedundant:
		byFamily := groupContactPointsByFamily(contacts)
		if len(byFamily) == 0 {
			// Responder-only specs do not carry contact points, but still need
			// the same family path key the active side will derive from the
			// group's allowed remote address sources.
			families := responderPathFamilies(records, remoteRole, group.AddressSourceOrder, group.AllowedAddressFamilies)
			if len(families) == 0 {
				families = []string{""}
			}
			for i, family := range families {
				spec, err := newSpecForFamily(local, peer, group, records, nil, family, linkIndex+i)
				if err != nil {
					return nil, false, PlanSkip{}, linkIndex, err
				}
				spec.InitiatorRole = role
				specs = append(specs, spec)
				specLinkIndexes = append(specLinkIndexes, linkIndex+i)
			}
			nextIndex = linkIndex + len(families)
			break
		}
		familyIdx := 0
		for _, family := range sortedFamilies(byFamily) {
			familyContacts := byFamily[family]
			spec, err := newSpecForFamily(local, peer, group, records, familyContacts, family, linkIndex+familyIdx)
			if err != nil {
				return nil, false, PlanSkip{}, linkIndex, err
			}
			spec.InitiatorRole = role
			specs = append(specs, spec)
			specLinkIndexes = append(specLinkIndexes, linkIndex+familyIdx)
			familyIdx++
		}
		nextIndex = linkIndex + len(byFamily)
	default:
		spec, err := newSpecForFamily(local, peer, group, records, contacts, "", linkIndex)
		if err != nil {
			return nil, false, PlanSkip{}, linkIndex, err
		}
		spec.InitiatorRole = role
		specs = append(specs, spec)
		specLinkIndexes = append(specLinkIndexes, linkIndex)
		nextIndex = linkIndex + 1
	}

	localGeneration := localPortGeneration(ns, local, now)
	localIKE := localIKEPortFromState(ns, local, now)
	var mobike bool
	switch {
	case localRole == RoleOut && role == InitiatorRolePrimary:
		mobike = opts.MOBIKE != nil && *opts.MOBIKE
	case role == "" && remoteRole == RoleOut && records.Profile.MOBIKE:
		mobike = opts.MOBIKE == nil || *opts.MOBIKE
	}
	for i := range specs {
		spec := &specs[i]
		spec.MOBIKE = mobike
		for _, point := range spec.ContactPoints {
			if point.Source == SourcePeerOverride {
				spec.MOBIKE = false
				break
			}
		}
		if IsActiveInitiatorRole(spec.InitiatorRole) {
			if point, ok := firstContactPoint(spec.ContactPoints); ok {
				spec.Generation = point.Generation
			}
		} else if localGeneration != 0 {
			spec.Generation = localGeneration
		}
		if localIKE != 0 {
			spec.LocalIKEPort = localIKE
		}
		if err := applyRuntimeGeneration(spec, group, specLinkIndexes[i]); err != nil {
			return nil, false, PlanSkip{}, linkIndex, err
		}
	}
	specs = filterSpecsByOverlayIntent(specs, intent)
	if len(specs) == 0 {
		return nil, false, PlanSkip{GroupID: group.ID, Peer: peer, Reason: SkipOverlayIntentMismatch, Detail: fmt.Sprintf("path_keys=%v", intent.PathKeys)}, linkIndex, nil
	}
	return specs, true, endpointSkip, nextIndex, nil
}

func newSpecForFamily(local, peer zone.ZonePath, group LinkGroupSpec, records *NodeRecords, contacts []ContactPoint, family string, linkIndex int) (TransportLinkSpec, error) {
	pathKey := DefaultPathKey
	if family != "" {
		pathKey = "family:" + family
	}
	linkID := StableLinkID(local, peer, group.ID, pathKey)
	transportID := RuntimeConnectionID(linkID, 0, group.Provider)
	spec, err := NewTransportLinkSpecWithOptions(local, peer, group.ID, records, contacts, TransportLinkOptions{
		LinkID:          linkID,
		PathKey:         pathKey,
		TransportID:     transportID,
		Provider:        group.Provider,
		PathMode:        group.DefaultPathMode,
		NetNS:           group.NetNS.Target(),
		LocalTunnelAddr: netip.Addr{},
		PeerTunnelAddr:  netip.Addr{},
	})
	if err != nil {
		return TransportLinkSpec{}, err
	}
	localAddr, peerAddr, err := group.DeriveTunnelAddressesForLink(local, peer, linkID, pathKey, spec.AddressEpoch, linkIndex)
	if err != nil {
		return TransportLinkSpec{}, err
	}
	if group.normalizedTunnelAddress().Mode == TunnelAddressSequentialPool && peer < local {
		localAddr, peerAddr = peerAddr, localAddr
	}
	spec.LocalTunnelAddr = localAddr
	spec.PeerTunnelAddr = peerAddr
	return spec, nil
}

func applyRuntimeGeneration(spec *TransportLinkSpec, group LinkGroupSpec, linkIndex int) error {
	runtimeGeneration := runtimeGenerationForPortGeneration(spec.Generation)
	spec.AddressEpoch = runtimeGeneration
	if spec.LinkID != "" {
		spec.TransportID = RuntimeConnectionID(spec.LinkID, runtimeGeneration, spec.Provider)
		spec.XFRMIfID = RuntimeXFRMIfID(spec.LinkID, runtimeGeneration, spec.Provider)
	} else {
		spec.XFRMIfID = StableXFRMIfID(spec.LocalZone, spec.PeerZone, spec.TransportID)
	}
	spec.InterfaceName = StableInterfaceName(spec.XFRMIfID)
	localAddr, peerAddr, err := group.DeriveTunnelAddressesForLink(spec.LocalZone, spec.PeerZone, spec.LinkID, spec.PathKey, spec.AddressEpoch, linkIndex)
	if err != nil {
		return err
	}
	if group.normalizedTunnelAddress().Mode == TunnelAddressSequentialPool && spec.PeerZone < spec.LocalZone {
		localAddr, peerAddr = peerAddr, localAddr
	}
	spec.LocalTunnelAddr = localAddr
	spec.PeerTunnelAddr = peerAddr
	return nil
}

// RuntimeSpecForPortGeneration returns the complete runtime spec for one port
// generation. Derived tunnel address modes are epoch-scoped; sequential pool
// addresses are stable across generations and keep base addresses.
func RuntimeSpecForPortGeneration(base TransportLinkSpec, group LinkGroupSpec, generation uint64) (TransportLinkSpec, error) {
	spec := base
	spec.Generation = generation
	runtimeGeneration := runtimeGenerationForPortGeneration(generation)
	spec.AddressEpoch = runtimeGeneration
	if spec.LinkID != "" {
		spec.TransportID = RuntimeConnectionID(spec.LinkID, runtimeGeneration, spec.Provider)
		spec.XFRMIfID = RuntimeXFRMIfID(spec.LinkID, runtimeGeneration, spec.Provider)
	} else {
		if runtimeGeneration != 0 {
			spec.TransportID = RotateConnectionName(base.TransportID, runtimeGeneration)
		}
		spec.XFRMIfID = StableXFRMIfID(spec.LocalZone, spec.PeerZone, spec.TransportID)
	}
	spec.InterfaceName = StableInterfaceName(spec.XFRMIfID)
	if group.ID != "" && group.normalizedTunnelAddress().Mode != TunnelAddressSequentialPool {
		localAddr, peerAddr, err := group.DeriveTunnelAddressesForLink(spec.LocalZone, spec.PeerZone, spec.LinkID, spec.PathKey, spec.AddressEpoch, 0)
		if err != nil {
			return TransportLinkSpec{}, err
		}
		spec.LocalTunnelAddr = localAddr
		spec.PeerTunnelAddr = peerAddr
	}
	var contacts []ContactPoint
	for _, point := range base.ContactPoints {
		if point.Generation == generation {
			contacts = append(contacts, point)
		}
	}
	if len(contacts) == 0 {
		contacts = append([]ContactPoint(nil), base.ContactPoints...)
	}
	spec.ContactPoints = contacts
	if !IsActiveInitiatorRole(spec.InitiatorRole) {
		spec.ContactPoints = nil
	}
	return spec, nil
}

func canLoadResponder(localRole string) bool {
	return localRole == RoleIn || localRole == RoleBoth
}

func localRoleFromState(ns *zone.NetworkState, local zone.ZonePath, now time.Time) string {
	if ns == nil || !local.Valid() {
		return RoleBoth
	}
	records, err := ExtractNodeRecords(ns, local, now)
	if err != nil {
		return RoleBoth
	}
	if records.Profile != nil && records.Profile.Role != "" {
		return records.Profile.Role
	}
	return RoleBoth
}

func localPortGeneration(ns *zone.NetworkState, local zone.ZonePath, now time.Time) uint64 {
	if ns == nil || ns.Zones[local] == nil {
		return 0
	}
	records, err := ExtractNodeRecords(ns, local, now)
	if err != nil {
		return 0
	}
	if records.Ports != nil && records.Ports.Current != nil {
		return records.Ports.Current.Generation
	}
	return 0
}

func localIKEPortFromState(ns *zone.NetworkState, local zone.ZonePath, now time.Time) uint16 {
	if ns == nil || ns.Zones[local] == nil {
		return 0
	}
	records, err := ExtractNodeRecords(ns, local, now)
	if err != nil {
		return 0
	}
	return localIKEPort(records)
}

func localIKEPort(records *NodeRecords) uint16 {
	if records == nil || records.Ports == nil || records.Ports.Current == nil {
		return 0
	}
	binding := records.Ports.Current.IKE
	// Local is the port charon actually binds to. If it is non-default,
	// tell StrongSwan explicitly. If it is the default IKE port, leave
	// LocalIKEPort zero so charon uses its normal listener.
	if binding.Local != 0 && binding.Local != DefaultIKEPort {
		return binding.Local
	}
	return 0
}

func groupContactPointsByFamily(contacts []ContactPoint) map[string][]ContactPoint {
	out := map[string][]ContactPoint{}
	for _, point := range contacts {
		family := point.Family
		if family == "" {
			family = inferIPFamily(point.Address)
		}
		if family == "" {
			continue
		}
		out[family] = append(out[family], point)
	}
	return out
}

func sortedFamilies(byFamily map[string][]ContactPoint) []string {
	families := make([]string, 0, len(byFamily))
	for family := range byFamily {
		families = append(families, family)
	}
	sort.Strings(families)
	return families
}

func responderPathFamilies(records *NodeRecords, remoteRole string, allowedSources, allowedFamilies []string) []string {
	if records == nil || records.Addresses == nil {
		return nil
	}
	if records.Profile != nil && remoteRole == RoleOut && len(records.Addresses.Addresses) == 0 {
		var out []string
		for _, family := range records.Profile.AddressFamilies {
			if len(allowedFamilies) > 0 && !oneOf(family, allowedFamilies...) {
				continue
			}
			out = append(out, family)
		}
		sort.Strings(out)
		return out
	}
	allowed := map[string]bool{}
	for _, source := range allowedSources {
		allowed[source] = true
	}
	seen := map[string]bool{}
	var out []string
	for _, address := range records.Addresses.Addresses {
		if len(allowed) > 0 && !allowed[address.Source] {
			continue
		}
		for _, family := range addressFamilies(address) {
			if seen[family] {
				continue
			}
			if len(records.Profile.AddressFamilies) > 0 && !oneOf(family, records.Profile.AddressFamilies...) {
				continue
			}
			if len(allowedFamilies) > 0 && !oneOf(family, allowedFamilies...) {
				continue
			}
			seen[family] = true
			out = append(out, family)
		}
	}
	sort.Strings(out)
	return out
}

func filterContactPointsByFamily(points []ContactPoint, allowedFamilies []string) []ContactPoint {
	if len(allowedFamilies) == 0 {
		return points
	}
	out := make([]ContactPoint, 0, len(points))
	for _, point := range points {
		family := point.Family
		if family == "" {
			family = inferIPFamily(point.Address)
		}
		if oneOf(family, allowedFamilies...) {
			out = append(out, point)
		}
	}
	return out
}

func applyMeshPolicyRules(group LinkGroupSpec, peer zone.ZonePath, records *NodeRecords, connectRules, denyRules []MeshPolicyRule) (LinkGroupSpec, bool, PlanSkip, error) {
	rule, reason, detail := selectMeshPolicyRule(peer, records, connectRules, denyRules)
	if reason != "" {
		return LinkGroupSpec{}, false, PlanSkip{GroupID: group.ID, Peer: peer, Reason: reason, Detail: detail}, nil
	}
	if rule == nil {
		return group, true, PlanSkip{}, nil
	}
	effective := applyMeshRuleToGroup(group, *rule)
	if err := effective.Validate(); err != nil {
		return LinkGroupSpec{}, false, PlanSkip{}, err
	}
	return effective.Normalized(), true, PlanSkip{}, nil
}

func selectMeshPolicyRule(peer zone.ZonePath, records *NodeRecords, connectRules, denyRules []MeshPolicyRule) (*MeshPolicyRule, string, string) {
	for _, rule := range denyRules {
		if meshRuleMatchesPeer(rule, peer, records) {
			return nil, SkipPolicyDenied, rule.Raw
		}
	}
	if len(connectRules) == 0 {
		return nil, "", ""
	}
	for _, rule := range connectRules {
		if !meshRuleMatchesPeer(rule, peer, records) {
			continue
		}
		return &rule, "", ""
	}
	return nil, SkipPolicyNoMatch, ""
}

func meshRuleMatchesPeer(rule MeshPolicyRule, peer zone.ZonePath, records *NodeRecords) bool {
	if rule.ZonePattern != "" && !rule.MatchesZone(peer) {
		return false
	}
	// Role/tag selectors are parsed and validated, but peer labels are not part of
	// the signed IPsec records yet. Until that source exists, they never match.
	if rule.Role != "" || rule.Tag != "" {
		return false
	}
	if rule.PeerRole != "" && (records == nil || records.Profile == nil || records.Profile.Role != rule.PeerRole) {
		return false
	}
	if rule.Family != "" && rule.Family != RuleFamilyDual {
		if records == nil || records.Profile == nil || !oneOf(rule.Family, records.Profile.AddressFamilies...) {
			return false
		}
		if records.Profile.Role != RoleOut && (records.Addresses == nil || !oneOf(rule.Family, recordFamilies(records.Addresses)...)) {
			return false
		}
	}
	return true
}

func applyMeshRuleToGroup(group LinkGroupSpec, rule MeshPolicyRule) LinkGroupSpec {
	out := group
	if rule.Family == FamilyIPv4 || rule.Family == FamilyIPv6 {
		out.AllowedAddressFamilies = []string{rule.Family}
	}
	if rule.PathMode != "" {
		out.DefaultPathMode = rule.PathMode
	}
	if len(rule.Sources) > 0 {
		out.AddressSourceOrder = append([]string(nil), rule.Sources...)
	}
	if rule.MaxPeers >= 0 {
		out.MaxPeers = rule.MaxPeers
	}
	return out
}

func sortedZones(ns *zone.NetworkState) []zone.ZonePath {
	out := make([]zone.ZonePath, 0, len(ns.Zones))
	for peer := range ns.Zones {
		if peer.IsRoot() {
			continue
		}
		out = append(out, peer)
	}
	slices.Sort(out)
	return out
}

func filterSpecsByOverlayIntent(specs []TransportLinkSpec, intent *OverlayIntentRecord) []TransportLinkSpec {
	if intent == nil {
		return nil
	}
	allowed := map[string]bool{}
	for _, pathKey := range intent.PathKeys {
		allowed[pathKey] = true
	}
	out := make([]TransportLinkSpec, 0, len(specs))
	for _, spec := range specs {
		if allowed[spec.PathKey] {
			out = append(out, spec)
		}
	}
	return out
}

func overlayIntentTunnelAddressCompatible(group LinkGroupSpec, intent *OverlayIntentRecord) bool {
	if intent == nil {
		return false
	}
	local := group.normalizedTunnelAddress()
	remote := intent.TunnelAddress
	if local.Mode != remote.Mode || local.Family != remote.Family {
		return false
	}
	switch local.Mode {
	case TunnelAddressDerivedPool, TunnelAddressSequentialPool:
		return local.Pool == remote.Pool
	default:
		return true
	}
}

func (p *LinkPlan) skip(groupID string, peer zone.ZonePath, reason, detail string) {
	p.Skipped = append(p.Skipped, PlanSkip{GroupID: groupID, Peer: peer, Reason: reason, Detail: detail})
}

func recordFamilies(record *AddressRecord) []string {
	if record == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, address := range record.Addresses {
		for _, family := range addressFamilies(address) {
			if seen[family] {
				continue
			}
			seen[family] = true
			out = append(out, family)
		}
	}
	return out
}

func familiesOverlap(left, right []string) bool {
	for _, l := range left {
		if slices.Contains(right, l) {
			return true
		}
	}
	return false
}

func resolvePeerContactPoints(ctx context.Context, records *NodeRecords, override PeerOverride, allowedFamilies []string, now time.Time, opts AddressCandidateOptions) ([]ContactPoint, string, error) {
	if len(override.Endpoints) == 0 {
		points, err := ResolveContactPoints(ctx, records.Addresses, records.Ports, now, opts)
		return points, "", err
	}
	addresses := *records.Addresses
	addresses.Addresses = nil
	for _, address := range records.Addresses.Addresses {
		families := make([]string, 0, 2)
		for _, family := range addressFamilies(address) {
			if _, pinned := override.Endpoints[family]; !pinned &&
				familyAllowed(family, records.Profile.AddressFamilies) &&
				(len(allowedFamilies) == 0 || familyAllowed(family, allowedFamilies)) {
				families = append(families, family)
			}
		}
		if len(families) > 0 {
			address.Families = families
			addresses.Addresses = append(addresses.Addresses, address)
		}
	}
	points, resolveErr := ResolveContactPoints(ctx, &addresses, records.Ports, now, opts)
	points = slices.DeleteFunc(points, func(point ContactPoint) bool {
		// A signed literal with an inconsistent family hint must not become
		// a fallback for its pinned address family.
		return point.Family != inferIPFamily(point.Address)
	})
	var problems []string
	ports := PortAdvertisements(records.Ports, now)
	for _, family := range []string{FamilyIPv4, FamilyIPv6} {
		endpoint, pinned := override.Endpoints[family]
		if !pinned {
			continue
		}
		if !familyAllowed(family, records.Profile.AddressFamilies) ||
			(len(allowedFamilies) != 0 && !familyAllowed(family, allowedFamilies)) {
			problems = append(problems, family+" is unavailable under the peer profile or local family policy")
			continue
		}
		pinPorts := ports
		if endpoint.NATTPort != nil {
			if records.Ports.Mode != PortModeFixed {
				problems = append(problems, family+" natt_port requires the peer to advertise fixed port mode")
				continue
			}
			// A single fixed UDP mapping terminates on the current responder generation.
			pinPorts = nil
			if len(ports) > 0 && ports[0].Current {
				port := ports[0]
				port.IKE = PortBinding{}
				port.NATT = PortBinding{Advertised: *endpoint.NATTPort}
				port.Observed = false
				pinPorts = []PortAdvertisement{port}
			}
		}
		if len(pinPorts) == 0 {
			problems = append(problems, family+" has no applicable signed port generation")
			continue
		}
		points = append(points, contactPointsForAdvertisements([]AddressCandidate{{
			ID: SourcePeerOverride + ":" + family, Source: SourcePeerOverride,
			Address: endpoint.Address.String(), Family: family,
		}}, pinPorts)...)
	}
	if len(points) != 0 || len(problems) != 0 {
		return points, strings.Join(problems, "; "), nil
	}
	return nil, "", resolveErr
}

func remoteNeedsInboundNATEvidence(profile *ProfileRecord) bool {
	if profile == nil {
		return false
	}
	return profile.NAT.Hint == NATHintBehindNAT || profile.NAT.InboundReachable == NATReachableFalse
}

func filterInboundNATEvidence(points []ContactPoint) []ContactPoint {
	out := make([]ContactPoint, 0, len(points))
	for _, point := range points {
		if contactHasInboundNATEvidence(point) {
			out = append(out, point)
		}
	}
	return out
}

func contactHasInboundNATEvidence(point ContactPoint) bool {
	if point.Source == SourcePeerOverride || point.Reachability == ReachabilityPublic {
		return true
	}
	if point.Reachability == ReachabilityNATObserved && point.ObservedPort {
		return true
	}
	ip := net.ParseIP(point.Address)
	return point.Family == FamilyIPv6 && ip != nil && !isPrivateOrLinkLocal(ip) && !ip.IsUnspecified()
}

func natEvidenceDetail(profile *ProfileRecord) string {
	if profile == nil {
		return ""
	}
	if profile.NAT.Hint != "" && profile.NAT.InboundReachable != "" {
		return fmt.Sprintf("nat.hint=%s inbound_reachable=%s requires public IPv6/address, port mapping, observed external port, hole punching, or relay", profile.NAT.Hint, profile.NAT.InboundReachable)
	}
	if profile.NAT.Hint != "" {
		return fmt.Sprintf("nat.hint=%s requires public IPv6/address, port mapping, observed external port, hole punching, or relay", profile.NAT.Hint)
	}
	return fmt.Sprintf("inbound_reachable=%s requires public IPv6/address, port mapping, observed external port, hole punching, or relay", profile.NAT.InboundReachable)
}
