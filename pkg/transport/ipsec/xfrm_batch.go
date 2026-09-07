package ipsec

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
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
			IfID uint32 `json:"if_id"`
		} `json:"info_data"`
	} `json:"linkinfo"`
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
	if needNamedNamespaces {
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
	linkOut, err := d.outputInNetNS(ctx, netns, "-j", "-d", "link", "show")
	if err != nil {
		return nil, nil, fmt.Errorf("batch inspect links in %s: %w", netnsLabel(netns), err)
	}
	var links []ipJSONLink
	if err := json.Unmarshal(linkOut, &links); err != nil {
		return nil, nil, fmt.Errorf("parse link JSON in %s: %w", netnsLabel(netns), err)
	}
	linksByName := make(map[string]ipJSONLink, len(links))
	for _, link := range links {
		linksByName[link.IfName] = link
	}

	addrOut, err := d.outputInNetNS(ctx, netns, "-j", "addr", "show")
	if err != nil {
		return nil, nil, fmt.Errorf("batch inspect addresses in %s: %w", netnsLabel(netns), err)
	}
	var addressLinks []ipJSONAddressLink
	if err := json.Unmarshal(addrOut, &addressLinks); err != nil {
		return nil, nil, fmt.Errorf("parse address JSON in %s: %w", netnsLabel(netns), err)
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
	var inventory []XFRMLinkState
	for _, link := range links {
		if link.LinkInfo.InfoKind != "xfrm" {
			continue
		}
		inventory = append(inventory, observedXFRMLink(netns, link, addressesByName[link.IfName]))
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
		link, exists := linksByName[spec.InterfaceName]
		state.InterfaceExists = exists
		if exists {
			observed := observedXFRMLink(netns, link, addressesByName[spec.InterfaceName])
			state.XFRMIfID = observed.XFRMIfID
			state.FlagsKnown = observed.FlagsKnown
			state.InterfaceUp = observed.InterfaceUp
			state.Multicast = observed.Multicast
			state.IPv6AddrGenModeKnown = observed.IPv6AddrGenModeKnown
			state.IPv6AddrGenDisabled = observed.IPv6AddrGenDisabled
			state.InterfaceForwardingKnown = true
			state.InterfaceForwarding = interfaceForwarding[spec.InterfaceName]
			state.Addresses = observed.Addresses
		}
		states[i] = state
	}
	return states, inventory, nil
}

func observedXFRMLink(netns NetNSSpec, link ipJSONLink, addresses []netip.Prefix) XFRMLinkState {
	state := XFRMLinkState{
		NetNS:                netns,
		InterfaceName:        link.IfName,
		XFRMIfID:             link.LinkInfo.InfoData.IfID,
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
	keys := []string{
		"net.ipv4.conf.all.forwarding",
		"net.ipv4.conf.default.forwarding",
		"net.ipv6.conf.all.forwarding",
		"net.ipv6.conf.default.forwarding",
	}
	for _, iface := range interfaces {
		keys = append(keys,
			fmt.Sprintf("net.ipv4.conf.%s.forwarding", iface),
			fmt.Sprintf("net.ipv6.conf.%s.forwarding", iface),
		)
	}
	args := append([]string{"-n"}, keys...)
	out, err := d.outputSysctl(ctx, netns, args...)
	if err != nil {
		return false, nil, fmt.Errorf("inspect forwarding in %s: %w", netnsLabel(netns), err)
	}
	values := strings.Fields(string(out))
	if len(values) != len(keys) {
		return false, nil, fmt.Errorf("inspect forwarding in %s: got %d values for %d keys", netnsLabel(netns), len(values), len(keys))
	}
	namespaceForwarding := true
	for _, value := range values[:4] {
		namespaceForwarding = namespaceForwarding && value == "1"
	}
	interfaceForwarding := make(map[string]bool, len(interfaces))
	for i, iface := range interfaces {
		base := 4 + i*2
		interfaceForwarding[iface] = values[base] == "1" && values[base+1] == "1"
	}
	return namespaceForwarding, interfaceForwarding, nil
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
