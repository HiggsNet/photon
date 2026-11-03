package ipsec

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
)

type xfrmBatchGroup struct {
	netns   NetNSSpec
	indices []int
	specs   []TransportLinkSpec
}

type ipJSONLink struct {
	IfName          string   `json:"ifname"`
	Flags           []string `json:"flags"`
	IPv6AddrGenMode string   `json:"inet6_addr_gen_mode"`
	LinkInfo        struct {
		InfoKind string `json:"info_kind"`
		InfoData struct {
			IfID ipJSONIfID `json:"if_id"`
		} `json:"info_data"`
	} `json:"linkinfo"`
}

// iproute2 emits XFRM if_id as a hexadecimal JSON string on some builds.
// Keep numeric JSON support; reject malformed or overflowing IDs rather than
// silently treating an unknown interface as ID zero.
type ipJSONIfID uint32

func (id *ipJSONIfID) UnmarshalJSON(data []byte) error {
	var value uint32
	if len(data) > 0 && data[0] == '"' {
		var text string
		if err := json.Unmarshal(data, &text); err != nil {
			return err
		}
		base := 10
		if strings.HasPrefix(text, "0x") || strings.HasPrefix(text, "0X") {
			base, text = 16, text[2:]
		}
		if text == "" || text[0] == '+' || text[0] == '-' {
			return fmt.Errorf("invalid XFRM if_id %q", text)
		}
		n, err := strconv.ParseUint(text, base, 32)
		if err != nil {
			return fmt.Errorf("invalid XFRM if_id: %w", err)
		}
		value = uint32(n)
	} else {
		if string(data) == "null" {
			return fmt.Errorf("null XFRM if_id")
		}
		if err := json.Unmarshal(data, &value); err != nil {
			return err
		}
	}
	*id = ipJSONIfID(value)
	return nil
}

type ipJSONAddressLink struct {
	IfName   string              `json:"ifname"`
	AddrInfo []ipJSONAddressInfo `json:"addr_info"`
}

type ipJSONAddressInfo struct {
	Local     string `json:"local"`
	PrefixLen int    `json:"prefixlen"`
}

type ipJSONNetNS struct {
	Name string `json:"name"`
}

// InspectLinks performs one link/address read per namespace and, when desired
// interfaces are present, one forwarding read. Named namespace existence is
// discovered once for the whole batch.
func (d SystemXFRMDriver) InspectLinks(ctx context.Context, specs []TransportLinkSpec, namespaces []NetNSSpec) ([]XFRMLinkState, []XFRMLinkState, error) {
	states := make([]XFRMLinkState, len(specs))
	groups := make(map[string]*xfrmBatchGroup)
	needNamedNamespaces := false
	for i, spec := range specs {
		if spec.InterfaceName == "" {
			return nil, nil, fmt.Errorf("interface name is required at batch index %d", i)
		}
		netns, err := d.specNetNS(spec)
		if err != nil {
			return nil, nil, err
		}
		if netns.Kind == NetNSPath {
			return nil, nil, fmt.Errorf("path netns %q is not supported by batch exec inspection", netns.Path)
		}
		if netns.Kind == NetNSName {
			needNamedNamespaces = true
		}
		key := xfrmBatchNetNSKey(netns)
		group := groups[key]
		if group == nil {
			group = &xfrmBatchGroup{netns: netns}
			groups[key] = group
		}
		group.indices = append(group.indices, i)
		group.specs = append(group.specs, spec)
		states[i].NetNS = netns
	}
	for _, netns := range namespaces {
		netns = netns.Normalized()
		if err := netns.Validate(); err != nil {
			return nil, nil, err
		}
		if netns.Kind == NetNSPath {
			return nil, nil, fmt.Errorf("path netns %q is not supported by batch exec inspection", netns.Path)
		}
		if netns.Kind == NetNSName {
			needNamedNamespaces = true
		}
		key := xfrmBatchNetNSKey(netns)
		if groups[key] == nil {
			groups[key] = &xfrmBatchGroup{netns: netns}
		}
	}

	namedNamespaces := map[string]bool{}
	if needNamedNamespaces && d.listNetNS != nil {
		var err error
		namedNamespaces, err = d.listNetNS()
		needNamedNamespaces = err != nil
	}
	if needNamedNamespaces {
		namedNamespaces = make(map[string]bool)
		out, err := d.output(ctx, d.ipCommand(), "-j", "netns", "list")
		if err != nil {
			return nil, nil, fmt.Errorf("list network namespaces: %w", err)
		}
		if len(strings.TrimSpace(string(out))) != 0 {
			var rows []ipJSONNetNS
			if err := json.Unmarshal(out, &rows); err != nil {
				return nil, nil, fmt.Errorf("parse network namespace JSON: %w", err)
			}
			for _, row := range rows {
				namedNamespaces[row.Name] = true
			}
		}
	}

	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var inventory []XFRMLinkState
	for _, key := range keys {
		group := groups[key]
		exists := group.netns.Kind == NetNSHost || namedNamespaces[group.netns.Name]
		for _, index := range group.indices {
			states[index].NamespaceExists = exists
		}
		if !exists {
			continue
		}
		groupStates, groupInventory, err := d.inspectLinksInNamespace(ctx, group.netns, group.specs)
		if err != nil {
			return nil, nil, err
		}
		inventory = append(inventory, groupInventory...)
		for i, index := range group.indices {
			states[index] = groupStates[i]
		}
	}
	return states, inventory, nil
}

func (d SystemXFRMDriver) inspectLinksInNamespace(ctx context.Context, netns NetNSSpec, specs []TransportLinkSpec) ([]XFRMLinkState, []XFRMLinkState, error) {
	var links []observedInterface
	var err error
	if d.inspectNetlink != nil {
		links, err = d.inspectNetlink(ctx, netns)
	}
	if d.inspectNetlink == nil || err != nil {
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		links, err = d.inspectLinksViaIP(ctx, netns)
		if err != nil {
			return nil, nil, err
		}
	}

	linksByName := make(map[string]XFRMLinkState, len(links))
	var inventory []XFRMLinkState
	for _, link := range links {
		linksByName[link.state.InterfaceName] = link.state
		if link.xfrm {
			inventory = append(inventory, link.state)
		}
	}
	if len(specs) == 0 {
		return nil, inventory, nil
	}

	interfaceNames := make([]string, 0, len(specs))
	seenInterfaces := make(map[string]bool, len(specs))
	for _, spec := range specs {
		if _, exists := linksByName[spec.InterfaceName]; exists && !seenInterfaces[spec.InterfaceName] {
			seenInterfaces[spec.InterfaceName] = true
			interfaceNames = append(interfaceNames, spec.InterfaceName)
		}
	}
	sort.Strings(interfaceNames)
	namespaceForwarding, interfaceForwarding, err := d.inspectForwardingInNamespace(ctx, netns, interfaceNames)
	if err != nil {
		return nil, nil, err
	}

	states := make([]XFRMLinkState, len(specs))
	for i, spec := range specs {
		state := XFRMLinkState{
			NetNS:                    netns,
			InterfaceName:            spec.InterfaceName,
			NamespaceExists:          true,
			NamespaceForwardingKnown: true,
			NamespaceForwarding:      namespaceForwarding,
		}
		observed, exists := linksByName[spec.InterfaceName]
		state.InterfaceExists = exists
		if exists {
			state.XFRMIfID = observed.XFRMIfID
			state.FlagsKnown = observed.FlagsKnown
			state.InterfaceUp = observed.InterfaceUp
			state.Multicast = observed.Multicast
			state.IPv6AddrGenModeKnown = observed.IPv6AddrGenModeKnown
			state.IPv6AddrGenDisabled = observed.IPv6AddrGenDisabled
			state.InterfaceForwardingKnown = true
			state.InterfaceForwarding = interfaceForwarding[spec.InterfaceName]
			state.Addresses = append([]netip.Prefix(nil), observed.Addresses...)
		}
		states[i] = state
	}
	return states, inventory, nil
}

type observedInterface struct {
	state          XFRMLinkState
	xfrm           bool
	hasPeerAddress bool
}

func (d SystemXFRMDriver) inspectLinksViaIP(ctx context.Context, netns NetNSSpec) ([]observedInterface, error) {
	linkOut, err := d.outputInNetNS(ctx, netns, "-j", "-d", "link", "show")
	if err != nil {
		return nil, fmt.Errorf("batch inspect links in %s: %w", netnsLabel(netns), err)
	}
	var links []ipJSONLink
	if err := json.Unmarshal(linkOut, &links); err != nil {
		return nil, fmt.Errorf("parse link JSON in %s: %w", netnsLabel(netns), err)
	}
	addrOut, err := d.outputInNetNS(ctx, netns, "-j", "addr", "show")
	if err != nil {
		return nil, fmt.Errorf("batch inspect addresses in %s: %w", netnsLabel(netns), err)
	}
	var addressLinks []ipJSONAddressLink
	if err := json.Unmarshal(addrOut, &addressLinks); err != nil {
		return nil, fmt.Errorf("parse address JSON in %s: %w", netnsLabel(netns), err)
	}
	addressesByName := make(map[string][]netip.Prefix, len(addressLinks))
	for _, link := range addressLinks {
		for _, info := range link.AddrInfo {
			addr, err := netip.ParseAddr(info.Local)
			if err != nil || info.PrefixLen < 0 || info.PrefixLen > addr.BitLen() {
				continue
			}
			addressesByName[link.IfName] = append(addressesByName[link.IfName], netip.PrefixFrom(addr, info.PrefixLen))
		}
	}
	observed := make([]observedInterface, 0, len(links))
	for _, link := range links {
		observed = append(observed, observedInterface{
			state: observedXFRMLink(netns, link, addressesByName[link.IfName]),
			xfrm:  link.LinkInfo.InfoKind == "xfrm",
		})
	}
	return observed, nil
}

func observedXFRMLink(netns NetNSSpec, link ipJSONLink, addresses []netip.Prefix) XFRMLinkState {
	state := XFRMLinkState{
		NetNS:                netns,
		InterfaceName:        link.IfName,
		XFRMIfID:             uint32(link.LinkInfo.InfoData.IfID),
		NamespaceExists:      true,
		InterfaceExists:      true,
		FlagsKnown:           link.Flags != nil,
		IPv6AddrGenModeKnown: link.IPv6AddrGenMode != "",
		IPv6AddrGenDisabled:  link.IPv6AddrGenMode == "none",
		Addresses:            append([]netip.Prefix(nil), addresses...),
	}
	for _, flag := range link.Flags {
		switch strings.ToUpper(flag) {
		case "UP":
			state.InterfaceUp = true
		case "MULTICAST":
			state.Multicast = true
		}
	}
	return state
}

func (d SystemXFRMDriver) inspectForwardingInNamespace(ctx context.Context, netns NetNSSpec, interfaces []string) (bool, map[string]bool, error) {
	keys := append([]string(nil), namespaceForwardingKeys[:]...)
	for _, iface := range interfaces {
		keys = append(keys,
			fmt.Sprintf("net.ipv4.conf.%s.forwarding", iface),
			fmt.Sprintf("net.ipv6.conf.%s.forwarding", iface),
		)
	}
	values, err := d.readForwardingValues(ctx, netns, keys)
	if err != nil {
		return false, nil, err
	}
	namespaceKeyCount := len(namespaceForwardingKeys)
	namespaceForwarding := true
	for _, value := range values[:namespaceKeyCount] {
		namespaceForwarding = namespaceForwarding && value == "1"
	}
	interfaceForwarding := make(map[string]bool, len(interfaces))
	for i, iface := range interfaces {
		base := namespaceKeyCount + i*2
		interfaceForwarding[iface] = values[base] == "1" && values[base+1] == "1"
	}
	return namespaceForwarding, interfaceForwarding, nil
}

func (d SystemXFRMDriver) readForwardingValues(ctx context.Context, netns NetNSSpec, keys []string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if d.inNetNS != nil {
		values := make([]string, 0, len(keys))
		err := d.inNetNS(netns.Normalized(), func() error {
			// These files resolve against the calling thread's network namespace.
			for _, key := range keys {
				path, err := forwardingProcPath(key)
				if err != nil {
					return err
				}
				out, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				value := strings.TrimSpace(string(out))
				if value != "0" && value != "1" {
					return fmt.Errorf("unexpected forwarding value for %s", key)
				}
				values = append(values, value)
			}
			return nil
		})
		if err == nil {
			return values, nil
		}
	}
	out, err := d.outputSysctl(ctx, netns, append([]string{"-n"}, keys...)...)
	if err != nil {
		return nil, fmt.Errorf("inspect forwarding in %s: %w", netnsLabel(netns), err)
	}
	values := strings.Fields(string(out))
	if len(values) != len(keys) {
		return nil, fmt.Errorf("inspect forwarding in %s: got %d values for %d keys", netnsLabel(netns), len(values), len(keys))
	}
	return values, nil
}

func (d SystemXFRMDriver) outputSysctl(ctx context.Context, netns NetNSSpec, args ...string) ([]byte, error) {
	netns = netns.Normalized()
	switch netns.Kind {
	case NetNSHost:
		return d.output(ctx, d.sysctlCommand(), args...)
	case NetNSName:
		full := append([]string{"netns", "exec", netns.Name, d.sysctlCommand()}, args...)
		return d.output(ctx, d.ipCommand(), full...)
	default:
		return nil, fmt.Errorf("unsupported netns kind %q", netns.Kind)
	}
}

// EnsureObservedInterfaces repairs only properties proven missing by a batch
// observation. Namespace forwarding is repaired at most once per namespace.
func (d SystemXFRMDriver) EnsureObservedInterfaces(ctx context.Context, observed []XFRMObservedInterface) error {
	groups := make(map[string][]XFRMObservedInterface)
	for _, item := range observed {
		netns, err := d.specNetNS(item.Spec)
		if err != nil {
			return err
		}
		groups[xfrmBatchNetNSKey(netns)] = append(groups[xfrmBatchNetNSKey(netns)], item)
	}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		items := groups[key]
		if len(items) == 0 {
			continue
		}
		netns, err := d.specNetNS(items[0].Spec)
		if err != nil {
			return err
		}
		if !items[0].State.NamespaceForwardingKnown || !items[0].State.NamespaceForwarding {
			if err := d.enableNamespaceForwarding(ctx, netns); err != nil {
				return err
			}
		}
		for _, item := range items {
			state := item.State
			if !state.NamespaceExists || !state.InterfaceExists {
				if err := d.EnsureInterface(ctx, item.Spec); err != nil {
					return err
				}
				continue
			}
			if !state.IPv6AddrGenModeKnown || !state.IPv6AddrGenDisabled {
				if err := d.disableIPv6AddrGen(ctx, netns, item.Spec.InterfaceName); err != nil {
					return err
				}
			}
			if !state.FlagsKnown || !state.Multicast {
				if err := d.enableMulticast(ctx, netns, item.Spec.InterfaceName); err != nil {
					return err
				}
			}
			if !state.FlagsKnown || !state.InterfaceUp {
				if err := d.setLinkUp(ctx, netns, item.Spec.InterfaceName); err != nil {
					return err
				}
			}
			if !state.InterfaceForwardingKnown || !state.InterfaceForwarding {
				if err := d.enableInterfaceForwarding(ctx, netns, item.Spec.InterfaceName); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func xfrmBatchNetNSKey(netns NetNSSpec) string {
	netns = netns.Normalized()
	return string(netns.Kind) + "\x00" + netns.Name + "\x00" + netns.Path
}

func netnsLabel(netns NetNSSpec) string {
	netns = netns.Normalized()
	switch netns.Kind {
	case NetNSHost:
		return "host"
	case NetNSName:
		return netns.Name
	case NetNSPath:
		return netns.Path
	default:
		return string(netns.Kind)
	}
}
