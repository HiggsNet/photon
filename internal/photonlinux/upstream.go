package photonlinux

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Ownership is recovered from the kernel on every reconciliation. It is scoped
// to this namespace/interface and, for routes, the main table. No process-local
// inventory is used as authority to remove an object after a restart.
const upstreamProtocol = 242

type execUpstreamRouteManager struct {
	runner func(context.Context, string, ...string) *exec.Cmd
	mu     sync.Mutex
	// A kernel which silently drops IFA_PROTO must not appear healthy on the
	// next call just because its newly unmarked address now resembles a borrowed
	// address. This is a capability error, not an ownership ledger. A recreated
	// manager still never claims or removes an unmarked address.
	addressProtocolError error
}

func newExecUpstreamRouteManager() *execUpstreamRouteManager {
	return &execUpstreamRouteManager{runner: exec.CommandContext}
}

type upstreamRoute struct {
	prefix          netip.Prefix
	dev             string
	protocol        int
	table           int
	gateway, source netip.Addr
	metric          uint32
	typeName        string
	fingerprint     string
	complex         bool
}

func (r upstreamRoute) owned(iface string) bool {
	return r.protocol == upstreamProtocol && r.table == 254 && r.dev == iface
}
func (r upstreamRoute) equal(w upstreamRoute) bool {
	return r.prefix == w.prefix && r.dev == w.dev && r.protocol == w.protocol && r.table == w.table &&
		r.gateway == w.gateway && r.source == w.source && r.metric == w.metric && (r.typeName == "" || r.typeName == "unicast")
}

type upstreamAddress struct {
	prefix      netip.Prefix
	protocol    int
	secondary   bool
	fingerprint string
}

type upstreamSnapshot struct {
	routes    []upstreamRoute
	addresses []upstreamAddress
}

func (m *execUpstreamRouteManager) EnsureRoutes(ctx context.Context, spec UpstreamRouteSpec) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Validate the entire intention before running even the first mutation.
	var err error
	spec, err = validateUpstreamSpec(spec)
	if err != nil {
		return err
	}
	nextHops, _ := upstreamNextHopByFamily(spec.MeshIPv4LL, spec.MeshIPv6LL)
	sources := upstreamSourceByFamily(spec.SourcePrefixes)
	desired := make(map[netip.Prefix]upstreamRoute, len(spec.Prefixes))
	for _, p := range spec.Prefixes {
		metric := uint32(0)
		if p.Addr().Is6() {
			metric = 1024
		}
		desired[p] = upstreamRoute{prefix: p, dev: spec.Interface, protocol: upstreamProtocol, table: 254,
			gateway: nextHops[p.Addr().Is4()], source: sources[p.Addr().Is4()], metric: metric}
	}
	current, err := m.observeUpstream(ctx, spec)
	if err != nil {
		return err
	}
	// Withdrawal of an authorization which disappeared from desired state must
	// not be blocked by an unrelated new source or desired-route conflict.
	for _, old := range current.routes {
		if _, keep := desired[old.prefix]; old.owned(spec.Interface) && !keep {
			if err := m.deleteUpstreamRoute(ctx, spec, old); err != nil {
				return err
			}
		}
	}
	if m.addressProtocolError != nil && len(spec.SourcePrefixes) != 0 {
		return m.addressProtocolError
	}
	if err := upstreamRouteConflicts(current.routes, desired, spec.Interface); err != nil {
		return err
	}
	keepSources := make(map[netip.Prefix]bool, len(spec.SourcePrefixes))
	for _, p := range spec.SourcePrefixes {
		keepSources[p] = true
	}
	var staleSources []upstreamAddress
	for _, a := range current.addresses {
		if a.protocol == upstreamProtocol && !keepSources[a.prefix] {
			staleSources = append(staleSources, a)
		}
	}
	var adds [][]string
	for _, p := range spec.SourcePrefixes {
		found := false
		for _, a := range current.addresses {
			if a.prefix == p {
				found = true
			} else if a.prefix.Addr() == p.Addr() {
				return fmt.Errorf("upstream source %s conflicts with existing address %s", p, a.prefix)
			}
		}
		if !found {
			adds = append(adds, []string{upstreamFamily(p.Addr()), "addr", "add", p.String(), "dev", spec.Interface, "noprefixroute", "proto", "242"})
		}
	}
	if err := m.runUpstreamBatch(ctx, spec, adds); err != nil {
		return fmt.Errorf("add upstream source (requires ip/kernel IFA_PROTO support): %w", err)
	}
	if len(adds) != 0 {
		observed, err := m.observeUpstream(ctx, spec)
		if err != nil {
			return err
		}
		for _, command := range adds {
			p := netip.MustParsePrefix(command[3])
			marked := false
			for _, a := range observed.addresses {
				if a.prefix == p && a.protocol == upstreamProtocol {
					marked = true
				}
			}
			if !marked {
				m.addressProtocolError = fmt.Errorf("upstream source %s did not retain protocol 242; ip/kernel IFA_PROTO support is required; unmarked addresses will not be adopted or deleted", p)
				return m.addressProtocolError
			}
		}
	}
	// Stale routes include owned entries whose gateway/preferred source changed.
	// Delete exactly that owned route, then add; never replace a foreign entry.
	for _, old := range current.routes {
		if !old.owned(spec.Interface) {
			continue
		}
		want, ok := desired[old.prefix]
		if !ok || old.equal(want) {
			continue
		}
		if err := m.deleteUpstreamRoute(ctx, spec, old); err != nil {
			return err
		}
	}
	fresh, err := m.observeUpstream(ctx, spec)
	if err != nil {
		return err
	}
	if err := upstreamRouteConflicts(fresh.routes, desired, spec.Interface); err != nil {
		return err
	}
	adds = nil
	for _, p := range spec.Prefixes {
		want, present := desired[p], false
		for _, r := range fresh.routes {
			if r.owned(spec.Interface) && r.prefix == p {
				if !r.equal(want) {
					return fmt.Errorf("upstream route %s changed while reconciling; retry", p)
				}
				present = true
			}
		}
		if !present {
			adds = append(adds, want.command("add"))
		}
	}
	if err := m.runUpstreamBatch(ctx, spec, adds); err != nil {
		return err
	}
	// IPv4 primary deletion can remove secondary addresses. Always remove the
	// explicitly owned stale secondaries first, then recheck each primary.
	sort.SliceStable(staleSources, func(i, j int) bool {
		if staleSources[i].secondary != staleSources[j].secondary {
			return staleSources[i].secondary
		}
		return prefixLess(staleSources[i].prefix, staleSources[j].prefix)
	})
	for _, old := range staleSources {
		fresh, err := m.observeUpstream(ctx, spec)
		if err != nil {
			return err
		}
		found := false
		for _, a := range fresh.addresses {
			if a.prefix != old.prefix || a.protocol != upstreamProtocol {
				continue
			}
			if a.fingerprint != old.fingerprint {
				return fmt.Errorf("upstream source %s changed during withdrawal; retry", old.prefix)
			}
			found = true
		}
		if !found {
			continue
		}
		if err := upstreamAddressDeleteGuard(fresh, old, staleSources, spec.Interface); err != nil {
			return err
		}
		if _, err := m.runIPOutput(ctx, spec.NetNS, []string{upstreamFamily(old.prefix.Addr()), "addr", "del", old.prefix.String(), "dev", spec.Interface, "proto", "242"}, ""); err != nil {
			return err
		}
	}
	return nil
}

func (m *execUpstreamRouteManager) deleteUpstreamRoute(ctx context.Context, spec UpstreamRouteSpec, old upstreamRoute) error {
	fresh, err := m.observeUpstream(ctx, spec)
	if err != nil {
		return err
	}
	for _, route := range fresh.routes {
		if !route.owned(spec.Interface) {
			continue
		}
		if route.fingerprint == old.fingerprint {
			_, err := m.runIPOutput(ctx, spec.NetNS, old.command("del"), "")
			return err
		}
		if route.equal(old) {
			return fmt.Errorf("upstream route %s changed during withdrawal; retry", old.prefix)
		}
	}
	return nil // another actor already removed or relinquished this exact object
}

func upstreamAddressDeleteGuard(s upstreamSnapshot, old upstreamAddress, stale []upstreamAddress, iface string) error {
	for _, r := range s.routes {
		if r.source != old.prefix.Addr() || r.owned(iface) {
			continue
		}
		// This is the kernel's own local binding of the exact address, not a
		// separately configured route. Removing an address necessarily removes it.
		if r.table == 255 && r.protocol == 2 && r.typeName == "local" && r.dev == iface &&
			r.prefix.Addr() == old.prefix.Addr() && r.prefix.Bits() == old.prefix.Addr().BitLen() {
			continue
		}
		return fmt.Errorf("refusing to withdraw upstream source %s: foreign route %s table %d dev %s uses its preferred source", old.prefix, r.prefix, r.table, r.dev)
	}
	if old.prefix.Addr().Is4() && !old.secondary {
		for _, a := range s.addresses {
			if !a.secondary || !old.prefix.Masked().Contains(a.prefix.Addr()) {
				continue
			}
			removing := false
			for _, candidate := range stale {
				if a.prefix == candidate.prefix && a.protocol == upstreamProtocol {
					removing = true
					break
				}
			}
			if !removing {
				return fmt.Errorf("refusing to withdraw IPv4 primary %s: it could remove retained or foreign secondary %s", old.prefix, a.prefix)
			}
		}
	}
	return nil
}

func upstreamRouteConflicts(routes []upstreamRoute, desired map[netip.Prefix]upstreamRoute, iface string) error {
	for _, r := range routes {
		if _, wanted := desired[r.prefix]; wanted && r.table == 254 && !r.owned(iface) {
			return fmt.Errorf("upstream prefix %s conflicts with foreign main-table route (dev %s protocol %d); refusing to replace it", r.prefix, r.dev, r.protocol)
		}
	}
	return nil
}

func (r upstreamRoute) command(action string) []string {
	args := []string{upstreamFamily(r.prefix.Addr()), "route", action, r.prefix.String(), "table", "main", "dev", r.dev, "proto", "242"}
	if r.gateway.IsValid() {
		args = append(args, "via", r.gateway.String())
	}
	if r.source.IsValid() {
		args = append(args, "src", r.source.String())
	}
	return append(args, "metric", strconv.FormatUint(uint64(r.metric), 10))
}

func validateUpstreamSpec(spec UpstreamRouteSpec) (UpstreamRouteSpec, error) {
	if spec.Interface == "" || strings.ContainsRune(spec.Interface, '\x00') || strings.ContainsRune(spec.NetNS, '\x00') {
		return spec, fmt.Errorf("upstream interface/namespace is missing or contains NUL")
	}
	spec.Prefixes = append([]netip.Prefix(nil), spec.Prefixes...)
	spec.SourcePrefixes = append([]netip.Prefix(nil), spec.SourcePrefixes...)
	for _, p := range spec.Prefixes {
		if !p.IsValid() || p.Addr().Is4In6() || p != p.Masked() {
			return spec, fmt.Errorf("invalid upstream route prefix %s: require a canonical network prefix", p)
		}
	}
	for _, p := range spec.SourcePrefixes {
		if !p.IsValid() || p.Addr().Is4In6() || p.Addr().IsUnspecified() || p.Addr().IsMulticast() {
			return spec, fmt.Errorf("invalid upstream source prefix %s", p)
		}
	}
	if _, err := upstreamNextHopByFamily(spec.MeshIPv4LL, spec.MeshIPv6LL); err != nil {
		return spec, err
	}
	sort.Slice(spec.Prefixes, func(i, j int) bool { return prefixLess(spec.Prefixes[i], spec.Prefixes[j]) })
	sort.Slice(spec.SourcePrefixes, func(i, j int) bool { return prefixLess(spec.SourcePrefixes[i], spec.SourcePrefixes[j]) })
	spec.Prefixes = uniqueUpstreamPrefixes(spec.Prefixes)
	spec.SourcePrefixes = uniqueUpstreamPrefixes(spec.SourcePrefixes)
	for i := 1; i < len(spec.SourcePrefixes); i++ {
		if spec.SourcePrefixes[i-1].Addr() == spec.SourcePrefixes[i].Addr() {
			return spec, fmt.Errorf("conflicting source prefix lengths for %s", spec.SourcePrefixes[i].Addr())
		}
	}
	return spec, nil
}

func uniqueUpstreamPrefixes(in []netip.Prefix) []netip.Prefix {
	out := in[:0]
	for _, p := range in {
		if len(out) == 0 || out[len(out)-1] != p {
			out = append(out, p)
		}
	}
	return out
}

func upstreamSourceByFamily(prefixes []netip.Prefix) map[bool]netip.Addr {
	out := make(map[bool]netip.Addr, 2)
	for _, p := range prefixes {
		if _, ok := out[p.Addr().Is4()]; !ok {
			out[p.Addr().Is4()] = p.Addr()
		}
	}
	return out
}

func upstreamNextHopByFamily(ipv4LL, ipv6LL string) (map[bool]netip.Addr, error) {
	out := make(map[bool]netip.Addr, 2)
	for _, input := range []struct {
		value string
		is4   bool
	}{{ipv4LL, true}, {ipv6LL, false}} {
		if input.value == "" {
			continue
		}
		p, err := netip.ParsePrefix(input.value)
		if err != nil || p.Addr().Is4() != input.is4 || p.Addr().Is4In6() || p.Addr().IsUnspecified() || p.Addr().IsMulticast() {
			return nil, fmt.Errorf("invalid upstream next hop/family %q", input.value)
		}
		out[input.is4] = p.Addr()
	}
	return out, nil
}

func prefixLess(a, b netip.Prefix) bool {
	if a.Addr() != b.Addr() {
		return a.Addr().Less(b.Addr())
	}
	return a.Bits() < b.Bits()
}
func upstreamFamily(a netip.Addr) string {
	if a.Is4() {
		return "-4"
	}
	return "-6"
}

func (m *execUpstreamRouteManager) runUpstreamBatch(ctx context.Context, spec UpstreamRouteSpec, commands [][]string) error {
	batchable := !strings.ContainsAny(spec.Interface, " \t\r\n\x00#'\"\\")
	for len(commands) > 0 {
		args, input, count := commands[0], "", 1
		if batchable {
			for count < len(commands) && commands[count][0] == args[0] {
				count++
			}
			var script strings.Builder
			for _, command := range commands[:count] {
				script.WriteString(strings.Join(command[1:], " "))
				script.WriteByte('\n')
			}
			input = script.String()
			args = []string{args[0], "-batch", "-"}
		}
		if _, err := m.runIPOutput(ctx, spec.NetNS, args, input); err != nil {
			return err
		}
		commands = commands[count:]
	}
	return nil
}

func (m *execUpstreamRouteManager) runIPOutput(ctx context.Context, netns string, args []string, input string) ([]byte, error) {
	if netns != "" && netns != "host" {
		args = append([]string{"netns", "exec", netns, "ip"}, args...)
	}
	runner := m.runner
	if runner == nil {
		runner = exec.CommandContext
	}
	cmd := runner(ctx, "ip", args...)
	if input != "" {
		cmd.Stdin = strings.NewReader(input)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("ip %s: %w (%s)", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

func (m *execUpstreamRouteManager) observeUpstream(ctx context.Context, spec UpstreamRouteSpec) (upstreamSnapshot, error) {
	var snapshot upstreamSnapshot
	for _, family := range []string{"-4", "-6"} {
		data, err := m.runIPOutput(ctx, spec.NetNS, []string{family, "-j", "-N", "route", "show", "table", "all"}, "")
		if err != nil {
			return snapshot, err
		}
		routes, err := parseUpstreamRoutes(data, family == "-4")
		if err != nil {
			return snapshot, fmt.Errorf("observe upstream %s routes: %w", family, err)
		}
		for _, route := range routes {
			if route.owned(spec.Interface) && route.complex {
				return snapshot, fmt.Errorf("unsupported owned upstream route shape for %s; refusing mutation", route.prefix)
			}
		}
		snapshot.routes = append(snapshot.routes, routes...)
	}
	data, err := m.runIPOutput(ctx, spec.NetNS, []string{"-j", "-N", "addr", "show", "dev", spec.Interface}, "")
	if err != nil {
		return snapshot, err
	}
	snapshot.addresses, err = parseUpstreamAddresses(data, spec.Interface)
	if err != nil {
		return snapshot, fmt.Errorf("observe upstream addresses: %w", err)
	}
	return snapshot, nil
}

func upstreamJSONArray(data []byte) ([]json.RawMessage, error) {
	if !bytes.HasPrefix(bytes.TrimSpace(data), []byte("[")) {
		return nil, fmt.Errorf("expected a JSON array")
	}
	var list []json.RawMessage
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, err
	}
	return list, nil
}

func upstreamNumber(raw json.RawMessage, defaultValue int) (int, error) {
	if len(raw) == 0 {
		return defaultValue, nil
	}
	var value string
	if raw[0] == '"' {
		if err := json.Unmarshal(raw, &value); err != nil {
			return 0, err
		}
	} else {
		value = string(raw)
	}
	switch value {
	case "main":
		return 254, nil
	case "local":
		return 255, nil
	case "default":
		return 253, nil
	case "kernel":
		return 2, nil
	case "static":
		return 4, nil
	case "boot":
		return 3, nil
	}
	base := 10
	if strings.HasPrefix(value, "0x") {
		base = 0
	}
	n, err := strconv.ParseUint(value, base, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid numeric ip attribute %q", value)
	}
	return int(n), nil
}

func upstreamFingerprint(raw json.RawMessage) (string, error) {
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil || value == nil {
		return "", fmt.Errorf("invalid JSON object")
	}
	data, err := json.Marshal(value)
	return string(data), err
}

func parseUpstreamRoutes(data []byte, is4 bool) ([]upstreamRoute, error) {
	list, err := upstreamJSONArray(data)
	if err != nil {
		return nil, err
	}
	out := make([]upstreamRoute, 0, len(list))
	for _, raw := range list {
		var v struct {
			Dst, Dev, Gateway, PrefSrc            string
			Protocol, Table, Type                 json.RawMessage
			Metric                                uint32
			Nexthops, Encap, Via, Nhid, From, Tos json.RawMessage
		}
		if err := json.Unmarshal(raw, &v); err != nil {
			return nil, err
		}
		fingerprint, err := upstreamFingerprint(raw)
		if err != nil {
			return nil, err
		}
		p, err := upstreamObservedPrefix(v.Dst, is4)
		if err != nil {
			return nil, err
		}
		proto, err := upstreamNumber(v.Protocol, 0)
		if err != nil {
			return nil, err
		}
		table, err := upstreamNumber(v.Table, 254)
		if err != nil {
			return nil, err
		}
		typeName, err := upstreamRouteType(v.Type)
		if err != nil {
			return nil, err
		}
		r := upstreamRoute{prefix: p, dev: v.Dev, protocol: proto, table: table, metric: v.Metric, typeName: typeName, fingerprint: fingerprint}
		for _, item := range []struct {
			text   string
			target *netip.Addr
		}{{v.Gateway, &r.gateway}, {v.PrefSrc, &r.source}} {
			if item.text != "" {
				a, err := netip.ParseAddr(item.text)
				if err != nil || a.Is4() != is4 || a.Is4In6() {
					return nil, fmt.Errorf("invalid route address/family %q", item.text)
				}
				*item.target = a
			}
		}
		r.complex = len(v.Nexthops) > 0 || len(v.Encap) > 0 || len(v.Via) > 0 || len(v.Nhid) > 0 || len(v.From) > 0 || len(v.Tos) > 0 || typeName != "unicast"
		out = append(out, r)
	}
	return out, nil
}

// ip -N applies numeric formatting to route types as well as protocols/tables.
// Accept both JSON strings and numbers without broadening the local-route guard.
func upstreamRouteType(raw json.RawMessage) (string, error) {
	if len(raw) == 0 {
		return "unicast", nil
	}
	var value string
	if raw[0] == '"' {
		if err := json.Unmarshal(raw, &value); err != nil {
			return "", err
		}
	} else {
		value = string(raw)
	}
	switch value {
	case "1", "unicast":
		return "unicast", nil
	case "2", "local":
		return "local", nil
	case "3", "broadcast":
		return "broadcast", nil
	case "4", "anycast":
		return "anycast", nil
	case "5", "multicast":
		return "multicast", nil
	case "6", "blackhole":
		return "blackhole", nil
	case "7", "unreachable":
		return "unreachable", nil
	case "8", "prohibit":
		return "prohibit", nil
	case "9", "throw":
		return "throw", nil
	case "10", "nat":
		return "nat", nil
	case "11", "xresolve":
		return "xresolve", nil
	default:
		return "", fmt.Errorf("invalid or unsupported route type %q", value)
	}
}

func upstreamObservedPrefix(value string, is4 bool) (netip.Prefix, error) {
	if value == "default" {
		if is4 {
			return netip.MustParsePrefix("0.0.0.0/0"), nil
		}
		return netip.MustParsePrefix("::/0"), nil
	}
	p, err := netip.ParsePrefix(value)
	if err != nil {
		if a, e := netip.ParseAddr(value); e == nil {
			p = netip.PrefixFrom(a, a.BitLen())
			err = nil
		}
	}
	if err != nil || p.Addr().Is4() != is4 || p.Addr().Is4In6() || p != p.Masked() {
		return netip.Prefix{}, fmt.Errorf("invalid observed route destination %q", value)
	}
	return p, nil
}

func parseUpstreamAddresses(data []byte, iface string) ([]upstreamAddress, error) {
	list, err := upstreamJSONArray(data)
	if err != nil {
		return nil, err
	}
	if len(list) != 1 {
		return nil, fmt.Errorf("expected exactly one interface %q", iface)
	}
	var link struct {
		Ifname   string
		AddrInfo []json.RawMessage `json:"addr_info"`
	}
	if err := json.Unmarshal(list[0], &link); err != nil {
		return nil, err
	}
	if link.Ifname != iface || link.AddrInfo == nil {
		return nil, fmt.Errorf("invalid address observation for interface %q", iface)
	}
	out := make([]upstreamAddress, 0, len(link.AddrInfo))
	for _, raw := range link.AddrInfo {
		var v struct {
			Family, Local, Address string
			Prefixlen              *int
			Protocol               json.RawMessage
			Secondary              bool
			Flags                  []string
		}
		if err := json.Unmarshal(raw, &v); err != nil {
			return nil, err
		}
		a, err := netip.ParseAddr(v.Local)
		if err != nil || a.Is4In6() || v.Prefixlen == nil || v.Family != "inet" && v.Family != "inet6" || (v.Family == "inet") != a.Is4() {
			return nil, fmt.Errorf("invalid address/family observation %q", v.Local)
		}
		p := netip.PrefixFrom(a, *v.Prefixlen)
		if !p.IsValid() {
			return nil, fmt.Errorf("invalid address prefix length for %s", a)
		}
		proto, err := upstreamNumber(v.Protocol, 0)
		if err != nil {
			return nil, err
		}
		if proto == upstreamProtocol && v.Address != "" && v.Address != v.Local {
			return nil, fmt.Errorf("unsupported owned point-to-point source %s", p)
		}
		fingerprint, err := upstreamFingerprint(raw)
		if err != nil {
			return nil, err
		}
		secondary := v.Secondary
		for _, flag := range v.Flags {
			if flag == "secondary" {
				secondary = true
			}
		}
		out = append(out, upstreamAddress{prefix: p, protocol: proto, secondary: secondary, fingerprint: fingerprint})
	}
	return out, nil
}
