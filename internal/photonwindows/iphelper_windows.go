package photonwindows

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"unsafe"

	"golang.org/x/sys/windows"
)

var ipHelperDLL = windows.NewLazySystemDLL("iphlpapi.dll")

// ipHelperDriver can only configure the adapter created by its Wintun owner.
// The device lock pins that adapter throughout observation and reconciliation.
// There is no interface-index fallback and no persistent desired-state cache.
type ipHelperDriver struct {
	device      *wintunDevice
	splitRoutes []netip.Prefix
}

func newIPHelperDriver(device *wintunDevice, splitRoutes []netip.Prefix) (*ipHelperDriver, error) {
	if device == nil {
		return nil, errors.New("IP Helper requires an owned Wintun adapter")
	}
	// Validate the configured scope once and copy it so a caller cannot broaden
	// the scope by mutating its original slice. Empty scope permits cleanup only.
	if err := validateIPHelperPrefixes(nil, splitRoutes); err != nil {
		return nil, err
	}
	return &ipHelperDriver{device: device, splitRoutes: slices.Clone(splitRoutes)}, nil
}

type ipHelperIntent struct {
	Addresses []netip.Prefix // local /32 or /128 addresses
	Routes    []netip.Prefix // authorized on-link aggregate routes; no default
	MTU       uint32
	Metric    uint32
}

type ipHelperObservation struct {
	luid       uint64
	interfaces [2]windows.MibIpInterfaceRow
	addresses  []windows.MibUnicastIpAddressRow
	routes     []windows.MibIpForwardRow2
}

type ipHelperPlan struct {
	interfaces  []windows.MibIpInterfaceRow
	removeAddr  []windows.MibUnicastIpAddressRow
	addAddr     []netip.Prefix
	removeRoute []windows.MibIpForwardRow2
	addRoute    []netip.Prefix
}

func (p ipHelperPlan) empty() bool {
	return len(p.interfaces)+len(p.removeAddr)+len(p.addAddr)+len(p.removeRoute)+len(p.addRoute) == 0
}

func ipHelperCall(name string, row unsafe.Pointer) error {
	proc := ipHelperDLL.NewProc(name)
	if err := proc.Find(); err != nil {
		return err
	}
	r, _, _ := proc.Call(uintptr(row))
	if r != 0 {
		return fmt.Errorf("%s: %w", name, windows.Errno(r))
	}
	return nil
}

func ipHelperInitialize(name string, row unsafe.Pointer) error {
	proc := ipHelperDLL.NewProc(name)
	if err := proc.Find(); err != nil {
		return err
	}
	proc.Call(uintptr(row)) // Initialize* returns void, not a Win32 status.
	return nil
}

func ipHelperSockaddr(addr netip.Addr) windows.RawSockaddrInet {
	var raw windows.RawSockaddrInet
	if addr.Is4() {
		a := (*windows.RawSockaddrInet4)(unsafe.Pointer(&raw))
		a.Family, a.Addr = windows.AF_INET, addr.As4()
	} else {
		a := (*windows.RawSockaddrInet6)(unsafe.Pointer(&raw))
		a.Family, a.Addr = windows.AF_INET6, addr.As16()
	}
	return raw
}

func ipHelperAddr(raw *windows.RawSockaddrInet) netip.Addr {
	switch raw.Family {
	case windows.AF_INET:
		return netip.AddrFrom4((*windows.RawSockaddrInet4)(unsafe.Pointer(raw)).Addr)
	case windows.AF_INET6:
		return netip.AddrFrom16((*windows.RawSockaddrInet6)(unsafe.Pointer(raw)).Addr)
	}
	return netip.Addr{}
}

func ipHelperAddressPrefix(row windows.MibUnicastIpAddressRow) netip.Prefix {
	return netip.PrefixFrom(ipHelperAddr((*windows.RawSockaddrInet)(unsafe.Pointer(&row.Address))), int(row.OnLinkPrefixLength))
}

func ipHelperRoutePrefix(row windows.MibIpForwardRow2) netip.Prefix {
	return netip.PrefixFrom(ipHelperAddr(&row.DestinationPrefix.Prefix), int(row.DestinationPrefix.PrefixLength))
}

func (d ipHelperDriver) lock(ctx context.Context) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if d.device == nil {
		return nil, errors.New("IP Helper requires an owned Wintun adapter")
	}
	d.device.mu.Lock()
	if d.device.closed || d.device.luid == 0 {
		d.device.mu.Unlock()
		return nil, io.ErrClosedPipe
	}
	return d.device.mu.Unlock, nil
}

func (d ipHelperDriver) Observe(ctx context.Context) (ipHelperObservation, error) {
	unlock, err := d.lock(ctx)
	if err != nil {
		return ipHelperObservation{}, err
	}
	defer unlock()
	return d.observe(ctx)
}

func (d ipHelperDriver) observe(ctx context.Context) (ipHelperObservation, error) {
	o := ipHelperObservation{luid: d.device.luid}
	for n, family := range []uint16{windows.AF_INET, windows.AF_INET6} {
		if err := ctx.Err(); err != nil {
			return o, err
		}
		o.interfaces[n] = windows.MibIpInterfaceRow{Family: family, InterfaceLuid: o.luid}
		if err := windows.GetIpInterfaceEntry(&o.interfaces[n]); err != nil {
			return o, err
		}
	}
	var addresses *windows.MibUnicastIpAddressTable
	if err := windows.GetUnicastIpAddressTable(windows.AF_UNSPEC, &addresses); err != nil {
		return o, err
	}
	defer windows.FreeMibTable(unsafe.Pointer(addresses))
	for _, row := range unsafe.Slice(&addresses.Table[0], addresses.NumEntries) {
		// Leave generated IPv6 link-local and other OS-managed addresses alone.
		if row.InterfaceLuid == o.luid && row.PrefixOrigin == 1 && row.SuffixOrigin == 1 {
			o.addresses = append(o.addresses, row)
		}
	}
	var routes *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(windows.AF_UNSPEC, &routes); err != nil {
		return o, err
	}
	defer windows.FreeMibTable(unsafe.Pointer(routes))
	for _, row := range routes.Rows() {
		// Connected/local routes are owned by Windows and follow address lifetime.
		if row.InterfaceLuid == o.luid && row.Protocol == windows.MIB_IPPROTO_NETMGMT {
			o.routes = append(o.routes, row)
		}
	}
	return o, ctx.Err()
}

func validateIPHelperPrefixes(addresses, routes []netip.Prefix) error {
	for kind, prefixes := range [][]netip.Prefix{addresses, routes} {
		seen := make(map[netip.Prefix]bool)
		for _, prefix := range prefixes {
			a := prefix.Addr()
			if !prefix.IsValid() || !a.IsGlobalUnicast() || a.Is4In6() || a.Zone() != "" || prefix.Bits() == 0 ||
				(kind == 0 && prefix.Bits() != a.BitLen()) || (kind == 1 && prefix != prefix.Masked()) || seen[prefix] {
				return fmt.Errorf("invalid or duplicate IP Helper prefix %s", prefix)
			}
			seen[prefix] = true
		}
	}
	return nil
}

func planIPHelper(want ipHelperIntent, have ipHelperObservation) (ipHelperPlan, error) {
	var p ipHelperPlan
	if have.luid == 0 || want.MTU < 1280 || want.MTU > 65535 || want.Metric == 0 || want.Metric > 9999 {
		return p, errors.New("invalid IP Helper LUID, dual-stack MTU or metric")
	}
	if err := validateIPHelperPrefixes(want.Addresses, want.Routes); err != nil {
		return p, err
	}
	for _, row := range have.interfaces {
		if row.InterfaceLuid != have.luid || (row.Family != windows.AF_INET && row.Family != windows.AF_INET6) {
			return p, errors.New("IP Helper observation includes foreign interface")
		}
		if row.NlMtu != want.MTU || row.Metric != want.Metric || row.UseAutomaticMetric != 0 {
			row.NlMtu, row.Metric, row.UseAutomaticMetric = want.MTU, want.Metric, 0
			if row.Family == windows.AF_INET {
				row.SitePrefixLength = 0
			}
			p.interfaces = append(p.interfaces, row)
		}
	}
	remainingAddr := slices.Clone(want.Addresses)
	for _, row := range have.addresses {
		if row.InterfaceLuid != have.luid {
			return p, errors.New("IP Helper observation includes foreign address")
		}
		prefix := ipHelperAddressPrefix(row)
		if n := slices.Index(remainingAddr, prefix); n >= 0 && row.SkipAsSource == 0 {
			remainingAddr = slices.Delete(remainingAddr, n, n+1)
		} else {
			p.removeAddr = append(p.removeAddr, row)
		}
	}
	p.addAddr = remainingAddr
	remainingRoutes := slices.Clone(want.Routes)
	for _, row := range have.routes {
		if row.InterfaceLuid != have.luid {
			return p, errors.New("IP Helper observation includes foreign route")
		}
		prefix := ipHelperRoutePrefix(row)
		if n := slices.Index(remainingRoutes, prefix); n >= 0 && row.Metric == 0 && ipHelperAddr(&row.NextHop).IsUnspecified() {
			remainingRoutes = slices.Delete(remainingRoutes, n, n+1)
		} else {
			p.removeRoute = append(p.removeRoute, row)
		}
	}
	p.addRoute = remainingRoutes
	return p, nil
}

// Reconcile derives operations from a fresh OS observation. Revoked routes and
// addresses are removed before additions; failures are returned with a fresh
// observation so the caller can withdraw forwarding and retry from reality.
func (d ipHelperDriver) Reconcile(ctx context.Context, want ipHelperIntent) (ipHelperObservation, error) {
	for _, route := range want.Routes {
		if !slices.Contains(d.splitRoutes, route) {
			return ipHelperObservation{}, fmt.Errorf("IP Helper route %s is outside configured split routes", route)
		}
	}
	unlock, err := d.lock(ctx)
	if err != nil {
		return ipHelperObservation{}, err
	}
	defer unlock()
	have, err := d.observe(ctx)
	if err != nil {
		return have, err
	}
	p, err := planIPHelper(want, have)
	if err != nil {
		return have, err
	}
	applyErr := d.apply(ctx, p)
	// Cancellation can interrupt a partially applied plan. Still read back the
	// actual state while the adapter is pinned, rather than returning an empty
	// observation that could be mistaken for successful withdrawal.
	after, observeErr := d.observe(context.WithoutCancel(ctx))
	if applyErr != nil || observeErr != nil {
		return after, errors.Join(applyErr, observeErr)
	}
	remaining, err := planIPHelper(want, after)
	if err != nil {
		return after, err
	}
	if !remaining.empty() {
		return after, errors.New("IP Helper state did not converge")
	}
	return after, nil
}

func (d ipHelperDriver) apply(ctx context.Context, p ipHelperPlan) error {
	call := func(name string, row unsafe.Pointer) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return ipHelperCall(name, row)
	}
	for _, row := range p.removeRoute {
		if err := call("DeleteIpForwardEntry2", unsafe.Pointer(&row)); err != nil && !errors.Is(err, windows.ERROR_NOT_FOUND) {
			return err
		}
	}
	for _, row := range p.removeAddr {
		if err := call("DeleteUnicastIpAddressEntry", unsafe.Pointer(&row)); err != nil && !errors.Is(err, windows.ERROR_NOT_FOUND) {
			return err
		}
	}
	for _, row := range p.interfaces {
		if err := call("SetIpInterfaceEntry", unsafe.Pointer(&row)); err != nil {
			return err
		}
	}
	for _, prefix := range p.addAddr {
		var row windows.MibUnicastIpAddressRow
		if err := ipHelperInitialize("InitializeUnicastIpAddressEntry", unsafe.Pointer(&row)); err != nil {
			return err
		}
		raw := ipHelperSockaddr(prefix.Addr())
		row.Address = *(*windows.RawSockaddrInet6)(unsafe.Pointer(&raw))
		row.InterfaceLuid, row.OnLinkPrefixLength = d.device.luid, uint8(prefix.Bits())
		row.PrefixOrigin, row.SuffixOrigin = 1, 1 // IpPrefixOriginManual / IpSuffixOriginManual
		if err := call("CreateUnicastIpAddressEntry", unsafe.Pointer(&row)); err != nil {
			return err
		}
	}
	for _, prefix := range p.addRoute {
		var row windows.MibIpForwardRow2
		if err := ipHelperInitialize("InitializeIpForwardEntry", unsafe.Pointer(&row)); err != nil {
			return err
		}
		row.InterfaceLuid = d.device.luid
		row.DestinationPrefix = windows.IpAddressPrefix{Prefix: ipHelperSockaddr(prefix.Addr()), PrefixLength: uint8(prefix.Bits())}
		unspecified := netip.IPv6Unspecified()
		if prefix.Addr().Is4() {
			unspecified = netip.IPv4Unspecified()
		}
		row.NextHop, row.Protocol, row.Metric = ipHelperSockaddr(unspecified), windows.MIB_IPPROTO_NETMGMT, 0
		if err := call("CreateIpForwardEntry2", unsafe.Pointer(&row)); err != nil {
			return err
		}
	}
	return nil
}
