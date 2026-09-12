// Package firewall provides the Phase 6.3 Photon overlay data-plane firewall
// security boundary.
//
// The firewall planner consumes already-verified derived state (AuthorizedRouteSet,
// link instances, revocation state, local firewall configuration) and produces a
// backend-agnostic FirewallDesiredState. A FirewallDriver renders and applies that
// desired state to the system (nftables first, iptables fallback, dry-run for tests).
//
// Design document: docs/new/firewall.md
package firewall

import (
	"net/netip"
)

// Owner identifies Photon-owned firewall objects so reconcile can distinguish
// them from administrator-managed rules.
type Owner struct {
	Manager     string // always "photon"
	InstanceID  string // netns-level instance id, e.g. "photon" or "host"
	OwnerPrefix string // name prefix, default "photon"
	Generation  uint64 // desired-state generation
	Token       string // stable owner token derived from instance/prefix
}

// InterfaceRole classifies a managed interface for chain generation.
type InterfaceRole string

const (
	InterfaceRoleXFRMTunnel   InterfaceRole = "xfrm_tunnel"
	InterfaceRoleUpstreamVeth InterfaceRole = "upstream_veth"
	InterfaceRoleLoopback     InterfaceRole = "loopback"
	InterfaceRoleUnderlay     InterfaceRole = "underlay"
)

// LocalService is an explicitly-open overlay netns service entry.
type LocalService struct {
	Proto   string // "tcp" or "udp"
	Port    uint16
	Sources []netip.Prefix // empty = allow from authorized mesh prefixes
}

// EndpointService is a forwarded service endpoint, normally a container on a
// host Docker bridge. Empty Proto and zero Port make the rule IP-scoped.
// Sources are already resolved from trusted Zone state.
type EndpointService struct {
	Name        string
	Proto       string
	Port        uint16
	Destination netip.Addr
	Sources     []netip.Prefix
}

// HostPortConfig controls which entry ports are opened on the host for inbound
// transport connections (IKE, NAT-T, WireGuard, etc.).
type HostPortConfig struct {
	IKE  bool // UDP 500
	NATT bool // UDP 4500
	WG   bool // WireGuard listen port (configurable)
}

// WGPort is the WireGuard listen port for HostPortConfig.WG.
// Default 51820 if not set.

// RedirectGrace enables advertised port → current charon listen port
// DNAT/redirect rules on the host. Current advertised ports keep port_range
// usable when charon listens on stable 500/4500; previous ports keep rotate
// grace alive during the configured window.
type RedirectGrace struct {
	Enabled bool
}

// FirewallInstanceSpec is derived from firewall.instances[] config.
type FirewallInstanceSpec struct {
	ID            string
	NetNS         string // netns name, or "host"
	IsHost        bool
	Enabled       bool
	Mode          string // managed | external | disabled
	Backend       string // auto | nft | iptables | none
	DefaultPolicy string // drop | accept
	OwnerPrefix   string

	// Interface roles for overlay instances.
	XFRMTunnelPattern string // compatibility fallback when no live interface is available

	// Overlay data-plane inputs.
	LocalServices    []LocalService
	EndpointServices []EndpointService

	// Host-only inputs.
	HostPorts      HostPortConfig
	RedirectGrace  RedirectGrace
	ListenAddrs    []netip.Addr // host listen addresses to bind rules (empty = no daddr binding)
	CharonIKEPort  uint16       // current charon IKE listen port (default 500)
	CharonNATTPort uint16       // current charon NAT-T listen port (default 4500)
	WGPort         uint16       // current WireGuard listen port (default 51820)
	Priorities     ChainPriorities

	// NativeHooks are backend-native inline rule expressions compiled into
	// Photon-managed chains. They are intentionally not a portable rule DSL.
	NativeHooks NativeHooks
}

// HookPoint identifies a stable insertion point inside a Photon-managed chain.
type HookPoint string

const (
	HookPreInput           HookPoint = "pre_input"
	HookPostInput          HookPoint = "post_input"
	HookPreForward         HookPoint = "pre_forward"
	HookPostForward        HookPoint = "post_forward"
	HookPreOutput          HookPoint = "pre_output"
	HookPostOutput         HookPoint = "post_output"
	HookHostPrePrerouting  HookPoint = "host_pre_prerouting"
	HookHostPostPrerouting HookPoint = "host_post_prerouting"
	HookHostPreInput       HookPoint = "host_pre_input"
	HookHostPostInput      HookPoint = "host_post_input"
)

// InlineHookRules holds ordered backend-native expressions for every public
// hook point. Overlay and host points are validated against the instance kind.
type InlineHookRules struct {
	PreInput           []string
	PostInput          []string
	PreForward         []string
	PostForward        []string
	PreOutput          []string
	PostOutput         []string
	HostPrePrerouting  []string
	HostPostPrerouting []string
	HostPreInput       []string
	HostPostInput      []string
}

// IPTablesInlineHooks separates iptables and ip6tables rules explicitly. No
// rule is copied or inferred across address families.
type IPTablesInlineHooks struct {
	IPv4 InlineHookRules
	IPv6 InlineHookRules
}

// NativeHooks contains the two backend-specific inline configurations. Both
// may be present so one config can be used on heterogeneous hosts.
type NativeHooks struct {
	NFT      InlineHookRules
	IPTables IPTablesInlineHooks
}

// InlineHookPositions freezes planner-owned insertion indexes. Drivers use
// these indexes to interleave native expressions with backend-agnostic rules;
// they must not independently choose hook ordering.
type InlineHookPositions struct {
	PreInput           int
	PostInput          int
	PreForward         int
	PostForward        int
	PreOutput          int
	PostOutput         int
	HostPrePrerouting  int
	HostPostPrerouting int
	HostPreInput       int
	HostPostInput      int
}

// PrefixSets are the IPv4/IPv6 prefix collections generated by the planner.
type PrefixSets struct {
	LocalAssignedV4  []netip.Prefix
	LocalAssignedV6  []netip.Prefix
	MeshAuthorizedV4 []netip.Prefix
	MeshAuthorizedV6 []netip.Prefix
	// RevokedV4/V6 are audit-only: prefixes removed from allow sets due to
	// zone/subtree revocation (6.3.3 / 6.3.7 deny-first). They never appear in
	// LocalAssigned/MeshAuthorized.
	RevokedV4 []netip.Prefix
	RevokedV6 []netip.Prefix
}

// ForwardingPolicy is shared by BIRD and firewall to decide transit behavior.
// BIRD must not announce a transit path the firewall also blocks, and vice versa.
type ForwardingPolicy struct {
	Transit       bool
	AllowPrefixes []netip.Prefix
	DenyPrefixes  []netip.Prefix
	AllowPeers    []string // zone globs or exact
	DenyPeers     []string
	MetricHint    uint
}

// FirewallPolicyInput is the verified derived state consumed by the planner.
type FirewallPolicyInput struct {
	// Local assigned prefixes (AssignedTo == managed zone).
	LocalAssigned []netip.Prefix
	// All authorized mesh prefixes (from AuthorizedRouteSet.Announced).
	MeshAuthorized []netip.Prefix
	// All valid IPAM assignment prefixes (import whitelist).
	AssignmentPrefixes []netip.Prefix
	// Forwarding policy for transit decisions.
	Forwarding ForwardingPolicy
	// Revoked prefixes that must NOT appear in allow sets (audit only).
	Revoked []netip.Prefix
	// Live link interfaces (XFRM interface names) that should pass traffic.
	// When present, the planner renders these exact names instead of the
	// compatibility XFRMTunnelPattern.
	LiveInterfaces []string
	// Upstream interfaces. Routing configuration is the sole authority for
	// these names; the planner never invents an upstream fallback pattern.
	UpstreamInterfaces []string
	// AdvertisedCurrentIKEPorts are the currently advertised IKE entry ports
	// from the local signed ipsec/ports record.
	AdvertisedCurrentIKEPorts []uint16
	// AdvertisedCurrentNATTPorts are the currently advertised NAT-T entry ports
	// from the local signed ipsec/ports record.
	AdvertisedCurrentNATTPorts []uint16
	// AdvertisedPreviousIKEPorts are old advertised IKE ports still within the
	// redirect grace window (from ipsec/ports record).
	AdvertisedPreviousIKEPorts []uint16
	// AdvertisedPreviousNATTPorts are old advertised NAT-T ports still within
	// the redirect grace window (from ipsec/ports record).
	AdvertisedPreviousNATTPorts []uint16
	// AdvertisedPreviousWGPorts are old advertised WireGuard ports still within
	// the redirect grace window (from wireguard/ports record or
	// config). Reserved for Phase 7 WireGuard port rotation.
	AdvertisedPreviousWGPorts []uint16
}

// FirewallDesiredState is the backend-agnostic desired rule model.
type FirewallDesiredState struct {
	Instance      FirewallInstanceSpec
	Prefixes      PrefixSets
	NativeHooks   NativeHooks
	HookPositions InlineHookPositions
	InputRules    []Rule
	ForwardRules  []Rule
	OutputRules   []Rule
	HostIngress   []HostIngressRule
	NatRedirects  []NatRedirectRule
	NatSources    []NatSourceRule
}

// Rule is a single backend-agnostic firewall rule.
type Rule struct {
	ID     string
	Chain  string // input | forward | output
	Action string // accept | drop
	Proto  string // tcp | udp | icmp | ipv6-icmp | ""
	Src    []netip.Prefix
	Dst    []netip.Prefix
	// IfaceIn/IfaceOut are portable selectors. For XFRM rules they may be
	// relaxed role prefixes so iptables can avoid an interface cross-product.
	IfaceIn  string
	IfaceOut string
	// IfacesIn/IfacesOut are exact selector sets. nft prefers these sets;
	// iptables uses them only when no portable scalar selector is available.
	IfacesIn  []string
	IfacesOut []string
	Port      uint16   // destination port, 0 = any
	CtStates  []string // conntrack states to match: established | related | invalid
	Comment   string
}

// HostIngressRule is a host-side allow rule for IKE/NAT-T entry ports.
type HostIngressRule struct {
	Proto   string
	Port    uint16
	Src     []netip.Prefix
	DstAddr netip.Addr
	Comment string
}

// NatRedirectRule redirects an advertised entry port to the current local
// listener port.
type NatRedirectRule struct {
	Proto       string
	OriginalDst uint16
	RedirectTo  uint16
	Src         []netip.Prefix
	DstAddr     netip.Addr
	Comment     string
}

// NatSourceRule rewrites host-originated transport source ports to the current
// advertised entry port while charon keeps a stable local listener.
type NatSourceRule struct {
	Proto       string
	OriginalSrc uint16
	RewriteTo   uint16
	DstPort     uint16
	DstAddr     netip.Addr
	Comment     string
}

// FirewallObjectRef references an owned object for stale deletion.
type FirewallObjectRef struct {
	Kind   string // table | chain | set | rule | nat_redirect | nat_source
	Family string // inet | ip | ip6
	Name   string
}

// FirewallObservedState is the set of owned objects read from the system.
type FirewallObservedState struct {
	Objects []FirewallObjectRef
}

// FirewallPreflight reports backend availability and conflicts.
type FirewallPreflight struct {
	Backend         string
	NFTNetlink      string // ok | unavailable | ""
	CAPNetAdmin     string
	Iptables        string // iptables IPv4 command availability
	IptablesV6      string // ip6tables command availability
	IptablesVariant string
	IPSet           string // ipset userspace/kernel capability
	HostNATHook     string
	NetNSStatus     string
	Conflicts       []string
}

// FirewallPlanAction classifies a planned object change.
type FirewallPlanAction struct {
	Action string // create | update | delete | adopt | noop
	Object FirewallObjectRef
	Reason string
}

// FirewallPlan is the diff between desired and observed state.
type FirewallPlan struct {
	InstanceID string
	Actions    []FirewallPlanAction
}

// FirewallApplyResult records the outcome of applying a plan.
type FirewallApplyResult struct {
	Generation uint64
	Applied    int
	Failed     int
}

// FirewallInstanceObservation summarizes one instance's latest reconcile.
// It is safe to discard on daemon restart.
type FirewallInstanceObservation struct {
	Backend      string `json:"backend,omitempty"`
	Generation   uint64 `json:"generation,omitempty"`
	LastRunUnix  int64  `json:"last_run_unix,omitempty"`
	LastFailure  error  `json:"-"`
	PolicyHash   string `json:"policy_hash,omitempty"`
	OwnedObjects int    `json:"owned_objects,omitempty"`
}

// FirewallObservation is the process-local result of the latest reconcile.
type FirewallObservation struct {
	Backend     string                                  `json:"backend,omitempty"`
	Instances   map[string]*FirewallInstanceObservation `json:"instances,omitempty"`
	LastRunUnix int64                                   `json:"last_run_unix,omitempty"`
	LastFailure error                                   `json:"-"`
}
