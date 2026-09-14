package ipsec

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
)

type CommandRunner func(context.Context, string, ...string) ([]byte, error)

type SystemXFRMDriver struct {
	Command      CommandRunner
	Stat         func(string) error
	DefaultNetNS NetNSSpec
	StateNetNS   NetNSSpec
	IPPath       string
	SysctlPath   string
	TruePath     string
	// Backend selects how per-link devices are materialized and how CHILD
	// SAs bind to them. Zero selects XFRMBackendInterface.
	Backend XFRMBackend
}

func NewSystemXFRMDriver(defaultNetNS NetNSSpec) SystemXFRMDriver {
	return SystemXFRMDriver{
		Command:      execCommand,
		Stat:         statPath,
		DefaultNetNS: defaultNetNS.Normalized(),
		StateNetNS:   NetNSSpec{Kind: NetNSHost},
		IPPath:       resolveExecutable("ip"),
		SysctlPath:   resolveExecutable("sysctl"),
		TruePath:     resolveExecutable("true"),
	}
}

func (d SystemXFRMDriver) EnsureNamespace(ctx context.Context, spec NetNSSpec) error {
	spec = spec.Normalized()
	if err := spec.Validate(); err != nil {
		return err
	}
	switch spec.Kind {
	case NetNSHost:
		return d.enableNamespaceForwarding(ctx, spec)
	case NetNSPath:
		stat := d.Stat
		if stat == nil {
			stat = statPath
		}
		if err := stat(spec.Path); err != nil {
			return fmt.Errorf("netns path %s: %w", spec.Path, err)
		}
		return nil
	case NetNSName:
		if d.netnsExists(ctx, spec.Name) {
			return d.enableNamespaceForwarding(ctx, spec)
		}
		if !spec.Create {
			return fmt.Errorf("netns %q does not exist and create=false", spec.Name)
		}
		if err := d.run(ctx, d.ipCommand(), "netns", "add", spec.Name); err != nil {
			return err
		}
		return d.enableNamespaceForwarding(ctx, spec)
	default:
		return fmt.Errorf("unsupported netns kind %q", spec.Kind)
	}
}

func (d SystemXFRMDriver) EnsureInterface(ctx context.Context, spec TransportLinkSpec) error {
	if spec.InterfaceName == "" {
		return errors.New("interface name is required")
	}
	if spec.XFRMIfID == 0 {
		return errors.New("xfrm if_id is required")
	}
	netns, err := d.specNetNS(spec)
	if err != nil {
		return err
	}
	if err := d.EnsureNamespace(ctx, netns); err != nil {
		return err
	}
	if d.policyBackend() {
		// Policy-based xfrm: no virtual device. The tunnel address is
		// assigned to lo via AssignAddress. Peer routing is an Ensure
		// invariant so Adopt/Repair/Staged pick it up without a side interface.
		return d.ensurePolicyRoute(ctx, netns, spec)
	}
	if d.linkExists(ctx, netns, spec.InterfaceName) {
		if err := d.disableIPv6AddrGen(ctx, netns, spec.InterfaceName); err != nil {
			return err
		}
		if err := d.enableMulticast(ctx, netns, spec.InterfaceName); err != nil {
			return err
		}
		if err := d.setLinkUp(ctx, netns, spec.InterfaceName); err != nil {
			return err
		}
	} else {
		stateNetNS := d.stateNetNS()
		if d.linkExists(ctx, stateNetNS, spec.InterfaceName) {
			if err := d.moveLinkFrom(ctx, stateNetNS, spec.InterfaceName, netns); err != nil {
				return err
			}
		} else {
			if err := d.addXFRMInterface(ctx, stateNetNS, spec.InterfaceName, spec.XFRMIfID); err != nil {
				return err
			}
			if err := d.moveLinkFrom(ctx, stateNetNS, spec.InterfaceName, netns); err != nil {
				return err
			}
		}
		if err := d.disableIPv6AddrGen(ctx, netns, spec.InterfaceName); err != nil {
			return err
		}
		if err := d.enableMulticast(ctx, netns, spec.InterfaceName); err != nil {
			return err
		}
		if err := d.setLinkUp(ctx, netns, spec.InterfaceName); err != nil {
			return err
		}
	}
	if err := d.enableInterfaceForwarding(ctx, netns, spec.InterfaceName); err != nil {
		return err
	}
	return d.ensureInterfacePeerRoute(ctx, netns, spec)
}

func (d SystemXFRMDriver) ensureInterfacePeerRoute(ctx context.Context, netns NetNSSpec, spec TransportLinkSpec) error {
	if !spec.PeerTunnelAddr.IsValid() || spec.InterfaceName == "" {
		return nil
	}
	bits := 32
	if spec.PeerTunnelAddr.Is6() {
		bits = 128
	}
	prefix := netip.PrefixFrom(spec.PeerTunnelAddr, bits)
	return d.runInNetNS(ctx, netns, "route", "replace", prefix.String(), "dev", spec.InterfaceName)
}

func (d SystemXFRMDriver) InspectLink(ctx context.Context, spec TransportLinkSpec) (XFRMLinkState, error) {
	if spec.InterfaceName == "" {
		return XFRMLinkState{}, errors.New("interface name is required")
	}
	netns, err := d.specNetNS(spec)
	if err != nil {
		return XFRMLinkState{}, err
	}
	state := XFRMLinkState{NetNS: netns}
	switch netns.Kind {
	case NetNSHost:
		state.NamespaceExists = true
	case NetNSName:
		state.NamespaceExists = d.netnsExists(ctx, netns.Name)
	case NetNSPath:
		stat := d.Stat
		if stat == nil {
			stat = statPath
		}
		state.NamespaceExists = stat(netns.Path) == nil
	default:
		return XFRMLinkState{}, fmt.Errorf("unsupported netns kind %q", netns.Kind)
	}
	if !state.NamespaceExists {
		return state, nil
	}
	observedName := d.observedInterfaceName(spec.InterfaceName)
	link, err := d.inspectInterfaceLink(ctx, netns, observedName)
	if err != nil {
		return XFRMLinkState{}, err
	}
	state.InterfaceExists = link.exists
	state.FlagsKnown = link.flagsKnown
	state.InterfaceUp = link.up
	state.Multicast = link.multicast
	state.SharedAttachment = d.policyBackend()
	if state.InterfaceExists {
		state.Addresses, err = d.inspectInterfaceAddresses(ctx, netns, observedName)
		if err != nil {
			return XFRMLinkState{}, err
		}
	}
	return state, nil
}

func (d SystemXFRMDriver) observedInterfaceName(name string) string {
	if d.policyBackend() {
		return "lo"
	}
	return name
}

func (d SystemXFRMDriver) FilterSAsWithMissingLinks(ctx context.Context, desired []TransportLinkSpec, sas []SAState) ([]SAState, map[string]TransportLinkSpec, error) {
	if len(desired) == 0 {
		return sas, nil, nil
	}
	missing := make(map[string]TransportLinkSpec)
	for _, spec := range desired {
		state, err := d.InspectLink(ctx, spec)
		if err != nil {
			return nil, nil, err
		}
		if d.linkStateMatchesSpec(state, spec) {
			continue
		}
		missing[LinkInstanceID(spec)] = spec
	}
	if len(missing) == 0 || len(sas) == 0 {
		return sas, missing, nil
	}
	filtered := sas[:0]
	for _, sa := range sas {
		if saMatchesAnyMissingLink(sa, missing) {
			continue
		}
		filtered = append(filtered, sa)
	}
	return filtered, missing, nil
}

func (d SystemXFRMDriver) inspectInterfaceAddresses(ctx context.Context, netns NetNSSpec, name string) ([]netip.Prefix, error) {
	var prefixes []netip.Prefix
	for _, family := range []string{"-4", "-6"} {
		addrs, err := d.interfaceAddresses(ctx, netns, name, family)
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			prefix, err := netip.ParsePrefix(addr)
			if err != nil {
				continue
			}
			prefixes = append(prefixes, prefix)
		}
	}
	return prefixes, nil
}

// linkStateMatchesSpec reports whether an observed link satisfies its spec.
// XFRM interfaces must be up and multicast-enabled. The policy backend uses
// the loopback device (lo), which never carries the MULTICAST flag, so only
// UP is required there.
func (d SystemXFRMDriver) linkStateMatchesSpec(state XFRMLinkState, spec TransportLinkSpec) bool {
	if !state.NamespaceExists || !state.InterfaceExists {
		return false
	}
	if state.FlagsKnown && !state.InterfaceUp {
		return false
	}
	if !state.SharedAttachment && state.FlagsKnown && !state.Multicast {
		return false
	}
	if !spec.LocalTunnelAddr.IsValid() {
		return true
	}
	for _, prefix := range state.Addresses {
		if prefix.Addr() == spec.LocalTunnelAddr {
			return true
		}
	}
	return false
}

func saMatchesAnyMissingLink(sa SAState, missing map[string]TransportLinkSpec) bool {
	for _, spec := range missing {
		if sa.Name == spec.TransportID || sa.ChildSA == ChildSAName(spec) || (spec.XFRMIfID != 0 && sa.XFRMIfID == spec.XFRMIfID) {
			return true
		}
	}
	return false
}

func (d SystemXFRMDriver) DeleteInterface(ctx context.Context, name string) error {
	if d.policyBackend() {
		// Policy mode has no per-link device to delete; the tunnel address
		// on lo is reclaimed by address pruning in AssignAddress.
		return nil
	}
	if name == "" {
		return errors.New("interface name is required")
	}
	netns := d.DefaultNetNS.Normalized()
	if d.linkExists(ctx, netns, name) {
		return d.runInNetNS(ctx, netns, "link", "delete", name)
	}
	if d.linkExists(ctx, NetNSSpec{Kind: NetNSHost}, name) {
		return d.run(ctx, d.ipCommand(), "link", "delete", name)
	}
	return nil
}

func (d SystemXFRMDriver) AssignAddress(ctx context.Context, spec TransportLinkSpec, address string) error {
	if spec.InterfaceName == "" {
		return errors.New("interface name is required")
	}
	if address == "" {
		return errors.New("address is required")
	}
	netns, err := d.specNetNS(spec)
	if err != nil {
		return err
	}
	// In policy mode the address goes on lo, which accumulates one address
	// per link; pruning would strip sibling links' tunnel addresses.
	if !d.policyBackend() {
		if err := d.pruneInterfaceAddresses(ctx, netns, spec.InterfaceName, address); err != nil {
			return err
		}
		return d.runInNetNS(ctx, netns, "addr", "replace", address, "dev", spec.InterfaceName)
	}
	return d.runInNetNS(ctx, netns, "addr", "replace", address, "dev", "lo")
}

func (d SystemXFRMDriver) AssignExtraAddress(ctx context.Context, spec TransportLinkSpec, address string) error {
	if spec.InterfaceName == "" {
		return errors.New("interface name is required")
	}
	if address == "" {
		return errors.New("address is required")
	}
	netns, err := d.specNetNS(spec)
	if err != nil {
		return err
	}
	return d.runInNetNS(ctx, netns, "addr", "replace", address, "dev", spec.InterfaceName)
}

func (d SystemXFRMDriver) pruneInterfaceAddresses(ctx context.Context, netns NetNSSpec, name, target string) error {
	targetPrefix, err := netip.ParsePrefix(target)
	if err != nil {
		return fmt.Errorf("parse assigned address %q: %w", target, err)
	}
	family := "-4"
	if targetPrefix.Addr().Is6() {
		family = "-6"
	}
	addrs, err := d.interfaceAddresses(ctx, netns, name, family)
	if err != nil {
		return err
	}
	targetAddr := targetPrefix.Addr()
	for _, addr := range addrs {
		prefix, err := netip.ParsePrefix(addr)
		if err != nil {
			continue
		}
		if prefix.Addr() == targetAddr {
			continue
		}
		if err := d.runInNetNS(ctx, netns, "addr", "del", addr, "dev", name); err != nil {
			return err
		}
	}
	return nil
}

func (d SystemXFRMDriver) interfaceAddresses(ctx context.Context, netns NetNSSpec, name, family string) ([]string, error) {
	out, err := d.outputInNetNS(ctx, netns, family, "-o", "addr", "show", "dev", name)
	if err != nil {
		return nil, err
	}
	var addrs []string
	for line := range strings.SplitSeq(string(out), "\n") {
		fields := strings.Fields(line)
		for i, field := range fields {
			if (field == "inet" || field == "inet6") && i+1 < len(fields) {
				addrs = append(addrs, fields[i+1])
				break
			}
		}
	}
	return addrs, nil
}

type xfrmInterfaceLinkState struct {
	exists     bool
	flagsKnown bool
	up         bool
	multicast  bool
}

func (d SystemXFRMDriver) inspectInterfaceLink(ctx context.Context, netns NetNSSpec, name string) (xfrmInterfaceLinkState, error) {
	out, err := d.outputInNetNS(ctx, netns, "link", "show", "dev", name)
	if err != nil {
		return xfrmInterfaceLinkState{}, nil
	}
	flags, ok := parseIPLinkFlags(string(out))
	return xfrmInterfaceLinkState{
		exists:     true,
		flagsKnown: ok,
		up:         flags["UP"],
		multicast:  flags["MULTICAST"],
	}, nil
}

func parseIPLinkFlags(out string) (map[string]bool, bool) {
	start := strings.Index(out, "<")
	if start < 0 {
		return nil, false
	}
	end := strings.Index(out[start+1:], ">")
	if end < 0 {
		return nil, false
	}
	raw := out[start+1 : start+1+end]
	flags := make(map[string]bool)
	for flag := range strings.SplitSeq(raw, ",") {
		flag = strings.ToUpper(strings.TrimSpace(flag))
		if flag == "" {
			continue
		}
		flags[flag] = true
	}
	return flags, len(flags) > 0
}

func (d SystemXFRMDriver) specNetNS(spec TransportLinkSpec) (NetNSSpec, error) {
	defaultNS := d.DefaultNetNS.Normalized()
	if spec.NetNS == "" {
		return defaultNS, defaultNS.Validate()
	}
	if defaultNS.Kind == NetNSName && spec.NetNS == defaultNS.Name {
		return defaultNS, defaultNS.Validate()
	}
	ns := NetNSSpec{Kind: NetNSName, Name: spec.NetNS}
	if strings.HasPrefix(spec.NetNS, "/") {
		ns = NetNSSpec{Kind: NetNSPath, Path: spec.NetNS}
	}
	return ns.Normalized(), ns.Validate()
}

func (d SystemXFRMDriver) stateNetNS() NetNSSpec {
	if d.StateNetNS.Kind == "" && d.StateNetNS.Name == "" && d.StateNetNS.Path == "" {
		return NetNSSpec{Kind: NetNSHost}
	}
	return d.StateNetNS.Normalized()
}

func (d SystemXFRMDriver) netnsExists(ctx context.Context, name string) bool {
	return d.commandSucceeds(ctx, d.ipCommand(), "netns", "exec", name, d.trueCommand())
}

func (d SystemXFRMDriver) linkExists(ctx context.Context, netns NetNSSpec, name string) bool {
	if netns.Normalized().Kind == NetNSHost {
		return d.commandSucceeds(ctx, d.ipCommand(), "link", "show", "dev", name)
	}
	return d.commandSucceedsInNetNS(ctx, netns, "link", "show", "dev", name)
}

func (d SystemXFRMDriver) moveLinkFrom(ctx context.Context, source NetNSSpec, name string, target NetNSSpec) error {
	source = source.Normalized()
	target = target.Normalized()
	if sameNetNS(source, target) {
		return nil
	}
	switch source.Kind {
	case NetNSHost:
		return d.moveLink(ctx, name, target)
	case NetNSName:
		switch target.Kind {
		case NetNSHost:
			return d.runInNetNS(ctx, source, "link", "set", name, "netns", "1")
		case NetNSName:
			return d.runInNetNS(ctx, source, "link", "set", name, "netns", target.Name)
		case NetNSPath:
			return fmt.Errorf("moving links to path netns %q is not supported by the exec driver; bind it under /var/run/netns and use kind=name", target.Path)
		default:
			return fmt.Errorf("unsupported netns kind %q", target.Kind)
		}
	case NetNSPath:
		return fmt.Errorf("moving links from path netns %q is not supported by the exec driver; bind it under /var/run/netns and use kind=name", source.Path)
	default:
		return fmt.Errorf("unsupported netns kind %q", source.Kind)
	}
}

func (d SystemXFRMDriver) moveLink(ctx context.Context, name string, netns NetNSSpec) error {
	netns = netns.Normalized()
	switch netns.Kind {
	case NetNSHost:
		return nil
	case NetNSName:
		return d.run(ctx, d.ipCommand(), "link", "set", name, "netns", netns.Name)
	case NetNSPath:
		return fmt.Errorf("moving links to path netns %q is not supported by the exec driver; bind it under /var/run/netns and use kind=name", netns.Path)
	default:
		return fmt.Errorf("unsupported netns kind %q", netns.Kind)
	}
}

func sameNetNS(a, b NetNSSpec) bool {
	a = a.Normalized()
	b = b.Normalized()
	if a.Kind != b.Kind {
		return false
	}
	switch a.Kind {
	case NetNSHost:
		return true
	case NetNSName:
		return a.Name == b.Name
	case NetNSPath:
		return a.Path == b.Path
	default:
		return false
	}
}

func (d SystemXFRMDriver) addXFRMInterface(ctx context.Context, netns NetNSSpec, name string, ifID uint32) error {
	args := []string{"link", "add", name, "type", "xfrm", "if_id", fmt.Sprintf("%d", ifID)}
	return d.runInNetNS(ctx, netns, args...)
}

func (d SystemXFRMDriver) setLinkUp(ctx context.Context, netns NetNSSpec, name string) error {
	return d.runInNetNS(ctx, netns, "link", "set", name, "up")
}

func (d SystemXFRMDriver) enableMulticast(ctx context.Context, netns NetNSSpec, name string) error {
	return d.runInNetNS(ctx, netns, "link", "set", name, "multicast", "on")
}

func (d SystemXFRMDriver) disableIPv6AddrGen(ctx context.Context, netns NetNSSpec, name string) error {
	return d.runInNetNS(ctx, netns, "link", "set", name, "addrgenmode", "none")
}

func (d SystemXFRMDriver) runInNetNS(ctx context.Context, netns NetNSSpec, args ...string) error {
	_, err := d.outputInNetNS(ctx, netns, args...)
	return err
}

func (d SystemXFRMDriver) outputInNetNS(ctx context.Context, netns NetNSSpec, args ...string) ([]byte, error) {
	netns = netns.Normalized()
	if netns.Kind == NetNSHost {
		return d.output(ctx, d.ipCommand(), args...)
	}
	if netns.Kind == NetNSPath {
		return nil, fmt.Errorf("path netns %q is not supported by the exec driver; bind it under /var/run/netns and use kind=name", netns.Path)
	}
	full := append([]string{"netns", "exec", netns.Name, d.ipCommand()}, args...)
	return d.output(ctx, d.ipCommand(), full...)
}

func (d SystemXFRMDriver) commandSucceedsInNetNS(ctx context.Context, netns NetNSSpec, args ...string) bool {
	netns = netns.Normalized()
	if netns.Kind == NetNSHost {
		return d.commandSucceeds(ctx, d.ipCommand(), args...)
	}
	if netns.Kind == NetNSPath {
		return false
	}
	full := append([]string{"netns", "exec", netns.Name, d.ipCommand()}, args...)
	return d.commandSucceeds(ctx, d.ipCommand(), full...)
}

func (d SystemXFRMDriver) commandSucceeds(ctx context.Context, name string, args ...string) bool {
	return d.run(ctx, name, args...) == nil
}

func (d SystemXFRMDriver) run(ctx context.Context, name string, args ...string) error {
	_, err := d.output(ctx, name, args...)
	return err
}

func (d SystemXFRMDriver) output(ctx context.Context, name string, args ...string) ([]byte, error) {
	runner := d.Command
	if runner == nil {
		runner = execCommand
	}
	out, err := runner(ctx, name, args...)
	if err != nil {
		detail := strings.TrimSpace(string(out))
		if detail == "" {
			return nil, fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
		}
		return nil, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, detail)
	}
	return out, nil
}

func execCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

func statPath(path string) error {
	_, err := os.Stat(path)
	return err
}

func resolveExecutable(name string) string {
	path, err := exec.LookPath(name)
	if err != nil {
		return name
	}
	return path
}

func (d SystemXFRMDriver) ipCommand() string {
	if d.IPPath != "" {
		return d.IPPath
	}
	return "ip"
}

func (d SystemXFRMDriver) sysctlCommand() string {
	if d.SysctlPath != "" {
		return d.SysctlPath
	}
	return "sysctl"
}

func (d SystemXFRMDriver) trueCommand() string {
	if d.TruePath != "" {
		return d.TruePath
	}
	return "true"
}

func (d SystemXFRMDriver) enableNamespaceForwarding(ctx context.Context, netns NetNSSpec) error {
	params := []string{
		"net.ipv4.conf.all.forwarding=1",
		"net.ipv4.conf.default.forwarding=1",
		"net.ipv6.conf.all.forwarding=1",
		"net.ipv6.conf.default.forwarding=1",
	}
	for _, p := range params {
		if err := d.sysctl(ctx, netns, "-w", p); err != nil {
			return err
		}
	}
	return nil
}

func (d SystemXFRMDriver) enableInterfaceForwarding(ctx context.Context, netns NetNSSpec, iface string) error {
	params := []string{
		fmt.Sprintf("net.ipv4.conf.%s.forwarding=1", iface),
		fmt.Sprintf("net.ipv6.conf.%s.forwarding=1", iface),
	}
	for _, p := range params {
		if err := d.sysctl(ctx, netns, "-w", p); err != nil {
			return err
		}
	}
	return nil
}

func (d SystemXFRMDriver) sysctl(ctx context.Context, netns NetNSSpec, args ...string) error {
	netns = netns.Normalized()
	switch netns.Kind {
	case NetNSHost:
		return d.run(ctx, d.sysctlCommand(), args...)
	case NetNSName:
		full := append([]string{"netns", "exec", netns.Name, d.sysctlCommand()}, args...)
		return d.run(ctx, d.ipCommand(), full...)
	case NetNSPath:
		return fmt.Errorf("path netns %q is not supported by the exec driver; bind it under /var/run/netns and use kind=name", netns.Path)
	default:
		return fmt.Errorf("unsupported netns kind %q", netns.Kind)
	}
}
