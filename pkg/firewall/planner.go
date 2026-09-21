package firewall

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

const (
	ModeManaged  = "managed"
	ModeExternal = "external"
	ModeDisabled = "disabled"

	BackendAuto     = "auto"
	BackendNFT      = "nft"
	BackendIptables = "iptables"
	BackendNone     = "none"

	DefaultPolicyDrop   = "drop"
	DefaultPolicyAccept = "accept"

	ActionAccept = "accept"
	ActionDrop   = "drop"

	ChainInput   = "input"
	ChainForward = "forward"
	ChainOutput  = "output"

	ProtoTCP    = "tcp"
	ProtoUDP    = "udp"
	ProtoICMP   = "icmp"
	ProtoICMPv6 = "ipv6-icmp"

	CtStateEstablished = "established"
	CtStateRelated     = "related"
	CtStateInvalid     = "invalid"

	defaultIKEPort  = 500
	defaultNATTPort = 4500
)

// BuildDesiredState generates a backend-agnostic desired firewall state from
// the instance spec and verified policy input. It is pure logic: no I/O, no
// root required. Callers (daemon, dry-run smoke, unit tests) can assert on
// the returned rules without touching the system.
func BuildDesiredState(spec FirewallInstanceSpec, input FirewallPolicyInput) (*FirewallDesiredState, error) {
	if spec.ID == "" {
		return nil, fmt.Errorf("firewall instance spec ID is required")
	}
	if spec.Mode == ModeDisabled || spec.Mode == ModeExternal {
		return &FirewallDesiredState{Instance: spec}, nil
	}
	spec.Priorities = spec.Priorities.Normalized()
	if err := validateFirewallHooks(spec); err != nil {
		return nil, err
	}
	if err := ValidateChainPriorities(spec.Priorities); err != nil {
		return nil, fmt.Errorf("firewall instance %q: %w", spec.ID, err)
	}
	prefixes := buildPrefixSets(input)
	desired := &FirewallDesiredState{
		Instance:    spec,
		Prefixes:    prefixes,
		NativeHooks: spec.NativeHooks,
	}
	if spec.IsHost {
		buildHostRules(desired, spec, input)
	} else {
		buildOverlayRules(desired, spec, input)
	}
	return desired, nil
}

func validateFirewallHooks(spec FirewallInstanceSpec) error {
	if err := ValidateNativeHooks(spec.NativeHooks); err != nil {
		return fmt.Errorf("firewall instance %q: %w", spec.ID, err)
	}
	hasNFTInline := HasNFTInlineHooks(spec.NativeHooks)
	hasIPTablesInline := HasIPTablesInlineHooks(spec.NativeHooks)
	switch spec.Backend {
	case BackendNFT:
		if hasIPTablesInline && !hasNFTInline {
			return fmt.Errorf("firewall instance %q: backend nft has only iptables_hooks configured", spec.ID)
		}
	case BackendIptables:
		if hasNFTInline && !hasIPTablesInline {
			return fmt.Errorf("firewall instance %q: backend iptables has only nft_hooks configured", spec.ID)
		}
	case BackendNone:
		if hasNFTInline || hasIPTablesInline {
			return fmt.Errorf("firewall instance %q: inline hooks require nft or iptables backend", spec.ID)
		}
	}
	for _, rules := range []InlineHookRules{spec.NativeHooks.NFT, spec.NativeHooks.IPTables.IPv4, spec.NativeHooks.IPTables.IPv6} {
		if spec.IsHost && hasInlineRules(rules, overlayHookPoints) {
			return fmt.Errorf("firewall instance %q: overlay inline hooks require a non-host instance", spec.ID)
		}
		if !spec.IsHost && hasInlineRules(rules, hostHookPoints) {
			return fmt.Errorf("firewall instance %q: host inline hooks require a host instance", spec.ID)
		}
	}
	return nil
}

// buildPrefixSets partitions prefixes by family and purpose. Revoked prefixes
// (6.3.3 / 6.3.7 deny-first) are filtered out so they never appear in allow
// sets, and are also exposed in RevokedV4/V6 for audit / explicit drop rules.
func buildPrefixSets(input FirewallPolicyInput) PrefixSets {
	revokedSet := buildRevokedSet(input.Revoked)
	var out PrefixSets
	for _, p := range dedupSorted(input.LocalAssigned) {
		if revokedSet[p.String()] {
			continue
		}
		if p.Addr().Is4() {
			out.LocalAssignedV4 = append(out.LocalAssignedV4, p)
		} else {
			out.LocalAssignedV6 = append(out.LocalAssignedV6, p)
		}
	}
	for _, p := range dedupSorted(input.MeshAuthorized) {
		if revokedSet[p.String()] {
			continue
		}
		if p.Addr().Is4() {
			out.MeshAuthorizedV4 = append(out.MeshAuthorizedV4, p)
		} else {
			out.MeshAuthorizedV6 = append(out.MeshAuthorizedV6, p)
		}
	}
	// Audit-only revoked sets.
	for _, p := range dedupSorted(input.Revoked) {
		if p.Addr().Is4() {
			out.RevokedV4 = append(out.RevokedV4, p)
		} else {
			out.RevokedV6 = append(out.RevokedV6, p)
		}
	}
	return out
}

// buildRevokedSet returns a set of revoked prefix strings for fast lookup.
func buildRevokedSet(revoked []netip.Prefix) map[string]bool {
	out := make(map[string]bool, len(revoked))
	for _, p := range revoked {
		out[p.String()] = true
	}
	return out
}

// buildOverlayRules generates input/forward/output chains for an overlay netns.
func buildOverlayRules(desired *FirewallDesiredState, spec FirewallInstanceSpec, input FirewallPolicyInput) {
	prefixes := desired.Prefixes
	defaultPolicy := spec.DefaultPolicy
	if defaultPolicy == "" {
		defaultPolicy = DefaultPolicyDrop
	}
	chainSuffix := chainNameSuffix(spec)

	// --- input chain ---
	ruleIdx := 0
	addRule := func(chain string, r Rule) {
		r.Chain = chain
		if r.ID == "" {
			ruleIdx++
			r.ID = fmt.Sprintf("%s_%s_%d", chainSuffix, chain, ruleIdx)
		}
		switch chain {
		case ChainInput:
			desired.InputRules = append(desired.InputRules, r)
		case ChainForward:
			desired.ForwardRules = append(desired.ForwardRules, r)
		case ChainOutput:
			desired.OutputRules = append(desired.OutputRules, r)
		}
	}

	// 1. invalid drop (ct state)
	addRule(ChainInput, Rule{Action: ActionDrop, CtStates: []string{CtStateInvalid}, Comment: "invalid drop"})

	// 2. loopback accept
	addRule(ChainInput, Rule{Action: ActionAccept, IfaceIn: "lo", Comment: "loopback"})
	desired.HookPositions.PreInput = len(desired.InputRules)

	// 3. BIRD/Babel control traffic (UDP 6696 for babel)
	addRule(ChainInput, Rule{Action: ActionAccept, Proto: ProtoUDP, Port: 6696, Comment: "babel control"})
	// ICMP for health/neighbor discovery
	addRule(ChainInput, Rule{Action: ActionAccept, Proto: ProtoICMP, Comment: "icmp health"})
	addRule(ChainInput, Rule{Action: ActionAccept, Proto: ProtoICMPv6, Comment: "icmpv6 health"})

	// 4. established/related
	addRule(ChainInput, Rule{Action: ActionAccept, CtStates: []string{CtStateEstablished, CtStateRelated}, Comment: "established related", ID: chainSuffix + "_input_est"})

	// 5. local services
	for _, svc := range spec.LocalServices {
		srcs := svc.Sources
		if len(srcs) == 0 {
			srcs = append(append(srcs, prefixes.MeshAuthorizedV4...), prefixes.MeshAuthorizedV6...)
		}
		addRule(ChainInput, Rule{
			Action:  ActionAccept,
			Proto:   svc.Proto,
			Port:    svc.Port,
			Src:     srcs,
			Comment: fmt.Sprintf("local_service %s/%d", svc.Proto, svc.Port),
		})
	}

	// 6. mesh authorized sources to local assigned prefixes
	if len(prefixes.MeshAuthorizedV4) > 0 || len(prefixes.MeshAuthorizedV6) > 0 {
		allMesh := append(append([]netip.Prefix{}, prefixes.MeshAuthorizedV4...), prefixes.MeshAuthorizedV6...)
		allLocal := append(append([]netip.Prefix{}, prefixes.LocalAssignedV4...), prefixes.LocalAssignedV6...)
		if len(allLocal) > 0 {
			addRule(ChainInput, Rule{
				Action:  ActionAccept,
				Src:     allMesh,
				Dst:     allLocal,
				Comment: "mesh authorized to local assigned",
			})
		}
	}

	// 7. post_input inline hooks
	desired.HookPositions.PostInput = len(desired.InputRules)

	// 8. default policy
	addRule(ChainInput, Rule{Action: defaultPolicyVerb(defaultPolicy), Comment: "default policy"})

	// --- forward chain ---
	xfrmIfaces := interfaceSelectors(input.LiveInterfaces, spec.XFRMTunnelPattern, "phx*")
	upstreamIfaces := interfaceSelectors(input.UpstreamInterfaces)
	xfrmCompat := strings.TrimSpace(spec.XFRMTunnelPattern)
	if xfrmCompat == "" {
		xfrmCompat = "phx*"
	}
	upstreamCompat := singletonInterfaceSelector(upstreamIfaces)
	meshAll := append(append([]netip.Prefix{}, prefixes.MeshAuthorizedV4...), prefixes.MeshAuthorizedV6...)
	localAll := append(append([]netip.Prefix{}, prefixes.LocalAssignedV4...), prefixes.LocalAssignedV6...)
	var transit []netip.Prefix
	if input.Forwarding.Transit {
		transit = filterTransitPrefixes(prefixes.MeshAuthorizedV4, prefixes.MeshAuthorizedV6, input.Forwarding)
	}

	// A routed mesh may legitimately use different forward and reverse paths.
	// In that case an intermediate router can observe SYN followed by ACK/data
	// without observing the SYN-ACK, and conntrack classifies the latter packets
	// as INVALID. Admit only the same interface/prefix-scoped traffic that the
	// normal transit rules below authorize before applying the generic INVALID
	// drop. Normal NEW/ESTABLISHED traffic still follows the original hook order.
	if len(transit) > 0 {
		addRule(ChainForward, Rule{
			Action:    ActionAccept,
			IfaceIn:   xfrmCompat,
			IfaceOut:  xfrmCompat,
			IfacesIn:  xfrmIfaces,
			IfacesOut: xfrmIfaces,
			Src:       transit,
			Dst:       transit,
			CtStates:  []string{CtStateInvalid},
			Comment:   "xfrm transit asymmetric invalid accept",
		})
	}
	if len(upstreamIfaces) > 0 && len(localAll) > 0 {
		addRule(ChainForward, Rule{
			Action:    ActionAccept,
			IfaceIn:   xfrmCompat,
			IfaceOut:  upstreamCompat,
			IfacesIn:  xfrmIfaces,
			IfacesOut: upstreamIfaces,
			Dst:       localAll,
			CtStates:  []string{CtStateInvalid},
			Comment:   "xfrm to upstream asymmetric invalid accept",
		})
	}
	if len(upstreamIfaces) > 0 && len(meshAll) > 0 {
		addRule(ChainForward, Rule{
			Action:    ActionAccept,
			IfaceIn:   upstreamCompat,
			IfaceOut:  xfrmCompat,
			IfacesIn:  upstreamIfaces,
			IfacesOut: xfrmIfaces,
			Dst:       meshAll,
			CtStates:  []string{CtStateInvalid},
			Comment:   "upstream to xfrm asymmetric invalid accept",
		})
	}

	// Reject all other invalid traffic, including invalid non-transit traffic.
	addRule(ChainForward, Rule{Action: ActionDrop, CtStates: []string{CtStateInvalid}, Comment: "invalid drop"})

	// Preserve stateful fast-path behavior for traffic seen in both directions.
	addRule(ChainForward, Rule{Action: ActionAccept, CtStates: []string{CtStateEstablished, CtStateRelated}, Comment: "established related", ID: chainSuffix + "_fwd_est"})
	desired.HookPositions.PreForward = len(desired.ForwardRules)

	// XFRM -> XFRM authorized transit (only if forwarding policy allows)
	if input.Forwarding.Transit {
		if len(transit) > 0 {
			addRule(ChainForward, Rule{
				Action:    ActionAccept,
				IfaceIn:   xfrmCompat,
				IfaceOut:  xfrmCompat,
				IfacesIn:  xfrmIfaces,
				IfacesOut: xfrmIfaces,
				Src:       transit,
				Dst:       transit,
				Comment:   "xfrm transit (transit enabled)",
			})
		}
	} else {
		// Non-transit: explicitly drop XFRM-to-XFRM
		addRule(ChainForward, Rule{
			Action:    ActionDrop,
			IfaceIn:   xfrmCompat,
			IfaceOut:  xfrmCompat,
			IfacesIn:  xfrmIfaces,
			IfacesOut: xfrmIfaces,
			Comment:   "non-transit drop",
		})
	}

	// XFRM -> upstream: allow mesh traffic to local assigned prefixes (egress to main network)
	if len(upstreamIfaces) > 0 && len(localAll) > 0 {
		addRule(ChainForward, Rule{
			Action:    ActionAccept,
			IfaceIn:   xfrmCompat,
			IfaceOut:  upstreamCompat,
			IfacesIn:  xfrmIfaces,
			IfacesOut: upstreamIfaces,
			Dst:       localAll,
			Comment:   "xfrm to upstream local assigned",
		})
	}

	// upstream -> XFRM: allow local/main network to reach mesh authorized prefixes
	if len(upstreamIfaces) > 0 && len(meshAll) > 0 {
		addRule(ChainForward, Rule{
			Action:    ActionAccept,
			IfaceIn:   upstreamCompat,
			IfaceOut:  xfrmCompat,
			IfacesIn:  upstreamIfaces,
			IfacesOut: xfrmIfaces,
			Dst:       meshAll,
			Comment:   "upstream to xfrm mesh authorized",
		})
	}

	desired.HookPositions.PostForward = len(desired.ForwardRules)
	addRule(ChainForward, Rule{Action: defaultPolicyVerb(defaultPolicy), Comment: "default policy"})

	// --- output chain ---
	desired.HookPositions.PreOutput = len(desired.OutputRules)
	addRule(ChainOutput, Rule{Action: ActionAccept, IfaceOut: "lo", Comment: "loopback"})
	addRule(ChainOutput, Rule{Action: ActionAccept, Proto: ProtoUDP, Port: 6696, Comment: "babel control"})
	addRule(ChainOutput, Rule{Action: ActionAccept, Proto: ProtoICMP, Comment: "icmp health"})
	addRule(ChainOutput, Rule{Action: ActionAccept, Proto: ProtoICMPv6, Comment: "icmpv6 health"})

	if len(prefixes.LocalAssignedV4) > 0 || len(prefixes.LocalAssignedV6) > 0 {
		localAll := append(append([]netip.Prefix{}, prefixes.LocalAssignedV4...), prefixes.LocalAssignedV6...)
		addRule(ChainOutput, Rule{Action: ActionAccept, Src: localAll, Comment: "local assigned source"})
	}
	desired.HookPositions.PostOutput = len(desired.OutputRules)
	// Output default to accept for overlay services; can be tightened.
	addRule(ChainOutput, Rule{Action: ActionAccept, Comment: "default policy"})
}

func interfaceSelectors(primary []string, fallbacks ...string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, value := range primary {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	if len(out) == 0 {
		for _, value := range fallbacks {
			value = strings.TrimSpace(value)
			if value == "" || seen[value] {
				continue
			}
			seen[value] = true
			out = append(out, value)
			break
		}
	}
	sort.Strings(out)
	return out
}

func singletonInterfaceSelector(values []string) string {
	if len(values) == 1 {
		return values[0]
	}
	return ""
}

// buildHostRules generates host-side IKE/NAT-T ingress and optional redirect grace.
func buildHostRules(desired *FirewallDesiredState, spec FirewallInstanceSpec, input FirewallPolicyInput) {
	desired.HookPositions.HostPreInput = 0
	desired.HookPositions.HostPrePrerouting = 0
	for _, endpoint := range spec.EndpointServices {
		dst := netip.PrefixFrom(endpoint.Destination, endpoint.Destination.BitLen())
		// An empty resolved source set deliberately produces no accept rule. The
		// following exact endpoint drop keeps selector resolution fail-closed.
		if len(endpoint.Sources) > 0 {
			desired.ForwardRules = append(desired.ForwardRules, Rule{
				Action: ActionAccept, Proto: endpoint.Proto, Port: endpoint.Port,
				Src: endpoint.Sources, Dst: []netip.Prefix{dst},
				Comment: "endpoint_acl " + endpoint.Name,
			})
		}
		desired.ForwardRules = append(desired.ForwardRules, Rule{
			Action: ActionDrop, Proto: endpoint.Proto, Port: endpoint.Port,
			Dst: []netip.Prefix{dst}, Comment: "endpoint_acl default drop " + endpoint.Name,
		})
	}

	ikePort := spec.CharonIKEPort
	if ikePort == 0 {
		ikePort = defaultIKEPort
	}
	nattPort := spec.CharonNATTPort
	if nattPort == 0 {
		nattPort = defaultNATTPort
	}

	// IKE ingress
	if spec.HostPorts.IKE {
		desired.HostIngress = append(desired.HostIngress, buildHostIngress(ProtoUDP, ikePort, spec.ListenAddrs, "ike ingress")...)
	}
	// NAT-T ingress
	if spec.HostPorts.NATT {
		desired.HostIngress = append(desired.HostIngress, buildHostIngress(ProtoUDP, nattPort, spec.ListenAddrs, "natt ingress")...)
	}
	// WireGuard ingress (for Phase 7 WireGuard transport driver).
	wgPort := spec.WGPort
	if wgPort == 0 {
		wgPort = 51820
	}
	if spec.HostPorts.WG {
		desired.HostIngress = append(desired.HostIngress, buildHostIngress(ProtoUDP, wgPort, spec.ListenAddrs, "wg ingress")...)
	}

	// Redirect advertised ports to the current local listener ports. Current
	// advertised ports make port_range usable when charon keeps stable 500/4500
	// sockets; previous ports keep rotate grace alive during the configured
	// window. The daemon feeds concrete current/previous ports from the local
	// signed ipsec/ports record.
	if spec.RedirectGrace.Enabled {
		addNatRedirects(desired, input.AdvertisedCurrentIKEPorts, ikePort, "redirect current", "ike", spec.ListenAddrs)
		addNatRedirects(desired, input.AdvertisedPreviousIKEPorts, ikePort, "redirect grace", "ike", spec.ListenAddrs)
		addNatRedirects(desired, input.AdvertisedCurrentNATTPorts, nattPort, "redirect current", "natt", spec.ListenAddrs)
		addNatRedirects(desired, input.AdvertisedPreviousNATTPorts, nattPort, "redirect grace", "natt", spec.ListenAddrs)
		addNatSourceRewrites(desired, input.AdvertisedCurrentIKEPorts, ikePort, "source current", "ike")
		addNatSourceRewrites(desired, input.AdvertisedCurrentNATTPorts, nattPort, "source current", "natt")
		// WireGuard redirect: old advertised WG ports → current WG port.
		// Reserved for Phase 7 WireGuard port rotation.
		for _, prev := range input.AdvertisedPreviousWGPorts {
			if prev == wgPort || prev == 0 {
				continue
			}
			desired.NatRedirects = append(desired.NatRedirects, NatRedirectRule{
				Proto:       ProtoUDP,
				OriginalDst: prev,
				RedirectTo:  wgPort,
				DstAddr:     firstListenAddr(spec.ListenAddrs),
				Comment:     fmt.Sprintf("redirect grace %d -> %d (wg)", prev, wgPort),
			})
		}
	}
	desired.HookPositions.HostPostInput = len(desired.HostIngress)
	desired.HookPositions.HostPostPrerouting = len(desired.NatRedirects)
}

func addNatRedirects(desired *FirewallDesiredState, ports []uint16, target uint16, reason, label string, listenAddrs []netip.Addr) {
	redirectAddrs := listenAddrs
	if len(redirectAddrs) == 0 {
		redirectAddrs = []netip.Addr{{}}
	}
	seen := make(map[string]bool, len(desired.NatRedirects)+len(ports)*len(redirectAddrs))
	for _, existing := range desired.NatRedirects {
		if existing.RedirectTo == target {
			seen[natRedirectKey(existing.OriginalDst, target, existing.DstAddr)] = true
		}
	}
	for _, port := range ports {
		if port == 0 || port == target {
			continue
		}
		for _, addr := range redirectAddrs {
			key := natRedirectKey(port, target, addr)
			if seen[key] {
				continue
			}
			seen[key] = true
			desired.NatRedirects = append(desired.NatRedirects, NatRedirectRule{
				Proto:       ProtoUDP,
				OriginalDst: port,
				RedirectTo:  target,
				DstAddr:     addr,
				Comment:     fmt.Sprintf("%s %d -> %d (%s)", reason, port, target, label),
			})
		}
	}
}

func natRedirectKey(original, target uint16, addr netip.Addr) string {
	if !addr.IsValid() {
		return fmt.Sprintf("%d/%d/*", original, target)
	}
	return fmt.Sprintf("%d/%d/%s", original, target, addr.String())
}

func addNatSourceRewrites(desired *FirewallDesiredState, ports []uint16, original uint16, reason, label string) {
	seen := make(map[string]bool, len(desired.NatSources)+len(ports))
	for _, existing := range desired.NatSources {
		if existing.OriginalSrc == original {
			seen[natSourceKey(existing.OriginalSrc, existing.RewriteTo, existing.DstPort, existing.DstAddr)] = true
		}
	}
	for _, port := range ports {
		if port == 0 || port == original {
			continue
		}
		key := natSourceKey(original, port, 0, netip.Addr{})
		if seen[key] {
			continue
		}
		seen[key] = true
		desired.NatSources = append(desired.NatSources, NatSourceRule{
			Proto:       ProtoUDP,
			OriginalSrc: original,
			RewriteTo:   port,
			Comment:     fmt.Sprintf("%s %d -> %d (%s)", reason, original, port, label),
		})
	}
}

func natSourceKey(original, target, dstPort uint16, addr netip.Addr) string {
	addrPart := "*"
	if addr.IsValid() {
		addrPart = addr.String()
	}
	return fmt.Sprintf("%d/%d/%d/%s", original, target, dstPort, addrPart)
}

// buildHostIngress builds host ingress rule(s) for a service port. With no
// listen_addrs it returns a single rule with no destination binding (matches
// any local address); with one or more listen_addrs it returns one rule per
// address, each scoped to its destination — mirroring addNatRedirects.
func buildHostIngress(proto string, port uint16, listenAddrs []netip.Addr, comment string) []HostIngressRule {
	if len(listenAddrs) == 0 {
		return []HostIngressRule{{Proto: proto, Port: port, Comment: comment}}
	}
	rules := make([]HostIngressRule, 0, len(listenAddrs))
	for _, addr := range listenAddrs {
		rules = append(rules, HostIngressRule{Proto: proto, Port: port, DstAddr: addr, Comment: comment})
	}
	return rules
}

func firstListenAddr(addrs []netip.Addr) netip.Addr {
	if len(addrs) == 0 {
		return netip.Addr{}
	}
	return addrs[0]
}

func defaultPolicyVerb(policy string) string {
	if policy == DefaultPolicyAccept {
		return ActionAccept
	}
	return ActionDrop
}

func chainNameSuffix(spec FirewallInstanceSpec) string {
	prefix := spec.OwnerPrefix
	if prefix == "" {
		prefix = "photon"
	}
	if spec.IsHost {
		return prefix + "_host"
	}
	return prefix + "_" + spec.NetNS
}

func dedupSorted(prefixes []netip.Prefix) []netip.Prefix {
	seen := make(map[string]bool)
	var out []netip.Prefix
	for _, p := range prefixes {
		key := p.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].String() < out[j].String()
	})
	return out
}

// DesiredStateHash returns a stable hash of the desired state for generation
// tracking and change detection.
func DesiredStateHash(desired *FirewallDesiredState) string {
	if desired == nil {
		return ""
	}
	h := sha256.New()
	fmt.Fprintln(h, desired.Instance.ID)
	fmt.Fprintln(h, desired.Instance.Mode)
	fmt.Fprintln(h, desired.Instance.DefaultPolicy)
	priorities := desired.Instance.Priorities.Normalized()
	fmt.Fprintln(h, "priority", priorities.Filter.String(), priorities.Prerouting.String(), priorities.Postrouting.String())
	for _, p := range desired.Prefixes.LocalAssignedV4 {
		fmt.Fprintln(h, "lav4", p.String())
	}
	for _, p := range desired.Prefixes.LocalAssignedV6 {
		fmt.Fprintln(h, "lav6", p.String())
	}
	for _, p := range desired.Prefixes.MeshAuthorizedV4 {
		fmt.Fprintln(h, "mav4", p.String())
	}
	for _, p := range desired.Prefixes.MeshAuthorizedV6 {
		fmt.Fprintln(h, "mav6", p.String())
	}
	for _, p := range desired.Prefixes.RevokedV4 {
		fmt.Fprintln(h, "rev4", p.String())
	}
	for _, p := range desired.Prefixes.RevokedV6 {
		fmt.Fprintln(h, "rev6", p.String())
	}
	for _, r := range desired.InputRules {
		fmt.Fprintln(h, "in", r.Action, r.Proto, r.Port, r.IfaceIn, r.IfaceOut, r.IfacesIn, r.IfacesOut, r.CtStates, r.Src, r.Dst, r.Comment)
	}
	for _, r := range desired.ForwardRules {
		fmt.Fprintln(h, "fwd", r.Action, r.Proto, r.Port, r.IfaceIn, r.IfaceOut, r.IfacesIn, r.IfacesOut, r.CtStates, r.Src, r.Dst, r.Comment)
	}
	for _, r := range desired.OutputRules {
		fmt.Fprintln(h, "out", r.Action, r.Proto, r.Port, r.IfaceIn, r.IfaceOut, r.IfacesIn, r.IfacesOut, r.CtStates, r.Src, r.Dst, r.Comment)
	}
	for _, r := range desired.HostIngress {
		fmt.Fprintln(h, "hi", r.Proto, r.Port, r.DstAddr.String(), r.Comment)
	}
	for _, r := range desired.NatRedirects {
		fmt.Fprintln(h, "nat", r.Proto, r.OriginalDst, r.RedirectTo, r.DstAddr.String(), r.Comment)
	}
	for _, r := range desired.NatSources {
		fmt.Fprintln(h, "snat", r.Proto, r.OriginalSrc, r.RewriteTo, r.DstPort, r.DstAddr.String(), r.Comment)
	}
	writeNativeHooksHash(h, desired.NativeHooks)
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func writeNativeHooksHash(h interface{ Write([]byte) (int, error) }, hooks NativeHooks) {
	for _, point := range allHookPoints {
		for _, rule := range hooks.NFT.Rules(point) {
			fmt.Fprintln(h, "native", BackendNFT, point, rule)
		}
		for _, rule := range hooks.IPTables.IPv4.Rules(point) {
			fmt.Fprintln(h, "native", BackendIptables, "ipv4", point, rule)
		}
		for _, rule := range hooks.IPTables.IPv6.Rules(point) {
			fmt.Fprintln(h, "native", BackendIptables, "ipv6", point, rule)
		}
	}
}

// DesiredObjects returns the set of owned object references for a desired state.
// Used by Plan to compute the create/delete diff against observed state.
func DesiredObjects(desired *FirewallDesiredState) []FirewallObjectRef {
	if desired == nil || desired.Instance.Mode == ModeDisabled || desired.Instance.Mode == ModeExternal {
		return nil
	}
	prefix := desired.Instance.OwnerPrefix
	if prefix == "" {
		prefix = "photon"
	}
	target := desired.Instance.NetNS
	if desired.Instance.IsHost {
		target = "host"
	}
	tableName := prefix + "_" + target
	var refs []FirewallObjectRef
	refs = append(refs, FirewallObjectRef{Kind: "table", Family: "inet", Name: tableName})
	if desired.Instance.IsHost {
		// Host drivers always create the input chain. Forward and NAT chains
		// only exist when their corresponding rule sets are non-empty.
		refs = append(refs, FirewallObjectRef{Kind: "chain", Family: "inet", Name: tableName + "_input"})
		if len(desired.ForwardRules) > 0 {
			refs = append(refs, FirewallObjectRef{Kind: "chain", Family: "inet", Name: tableName + "_forward"})
		}
		if len(desired.NatRedirects) > 0 || hasNativeHookAt(desired.NativeHooks, HookHostPrePrerouting) || hasNativeHookAt(desired.NativeHooks, HookHostPostPrerouting) {
			refs = append(refs, FirewallObjectRef{Kind: "nat_redirect", Family: "inet", Name: tableName + "_prerouting"})
		}
		if len(desired.NatSources) > 0 {
			refs = append(refs, FirewallObjectRef{Kind: "nat_source", Family: "inet", Name: tableName + "_postrouting"})
		}
	} else {
		refs = append(refs, FirewallObjectRef{Kind: "chain", Family: "inet", Name: tableName + "_input"})
		refs = append(refs, FirewallObjectRef{Kind: "chain", Family: "inet", Name: tableName + "_forward"})
		refs = append(refs, FirewallObjectRef{Kind: "chain", Family: "inet", Name: tableName + "_output"})
	}
	// Hook jump-target chains are admin-owned and intentionally not tracked
	// here: they must never be reaped as stale (their content is not ours).
	if len(desired.Prefixes.MeshAuthorizedV4) > 0 {
		refs = append(refs, FirewallObjectRef{Kind: "set", Family: "inet", Name: tableName + "_mesh_v4"})
	}
	if len(desired.Prefixes.MeshAuthorizedV6) > 0 {
		refs = append(refs, FirewallObjectRef{Kind: "set", Family: "inet", Name: tableName + "_mesh_v6"})
	}
	return refs
}
