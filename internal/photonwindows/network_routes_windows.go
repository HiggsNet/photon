package photonwindows

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var getBestRoute2 = ipHelperDLL.NewProc("GetBestRoute2")

type outboundRouteResolver struct {
	source      netip.Addr
	splitRoutes []netip.Prefix
	cache       atomic.Pointer[outboundRouteCache]
}

type outboundRouteCache struct {
	mu    sync.Mutex
	paths map[netip.Addr]cachedOutboundRoute
}

type cachedOutboundRoute struct {
	path    outboundRoute
	retryAt time.Time
}

func (s *packetSockets) configureOutboundRoutes(source netip.Addr, splitRoutes []netip.Prefix) {
	s.outboundRoutes = &outboundRouteResolver{source: source.Unmap().WithZone(""), splitRoutes: slices.Clone(splitRoutes)}
	s.outboundRoutes.invalidate()
}

func (r *outboundRouteResolver) invalidate() {
	if r != nil {
		r.cache.Store(&outboundRouteCache{paths: make(map[netip.Addr]cachedOutboundRoute)})
	}
}

func (r *outboundRouteResolver) packetPath(target netip.Addr, generation uint64) (outboundRoute, error) {
	target = target.Unmap()
	if r == nil || !target.IsGlobalUnicast() {
		return outboundRoute{}, nil
	}
	if generation == 0 {
		for _, prefix := range r.splitRoutes {
			if prefix.Contains(target) {
				// Overlay Gossip still belongs on the Photon network.
				return outboundRoute{}, nil
			}
		}
	}
	cache := r.cache.Load()
	cache.mu.Lock()
	entry, ok := cache.paths[target]
	cache.mu.Unlock()
	if !ok || (!entry.retryAt.IsZero() && !time.Now().Before(entry.retryAt)) {
		interfaces, err := outboundInterfaces()
		if err != nil {
			return outboundRoute{}, err
		}
		entry = cachedOutboundRoute{path: bestOutboundRoute(target, r.source, interfaces)}
		if entry.path.index == 0 {
			// A temporary IP Helper failure can look like unreachability.
			entry.retryAt = time.Now().Add(time.Second)
		}
		cache.mu.Lock()
		// Gossip can receive datagrams from arbitrary sources. Bound the
		// cache and keep cached entries until the next network notification.
		if ok || len(cache.paths) < 512 {
			cache.paths[target] = entry
		}
		cache.mu.Unlock()
	}
	if entry.path.index == 0 {
		return outboundRoute{}, fmt.Errorf("no eligible Windows outbound route to %s: %w", target, windows.WSAENETUNREACH)
	}
	return entry.path, nil
}

// Caller holds the ownership registry read lock.
func excludedOutboundAdapter(row windows.MibIfRow2) bool {
	if ownedAdapterGUIDs.refs[row.InterfaceGuid] != 0 {
		return true
	}
	switch strings.ToLower(windows.UTF16ToString(row.Alias[:])) {
	case "flclash", "mihomo", "meta", "photon mihomo":
		return true
	}
	// Mihomo sets the driver tunnel type to Meta even when the adapter
	// alias is customized. Do not discard other VPNs just for using Wintun.
	description := strings.ToLower(windows.UTF16ToString(row.Description[:]))
	return description == "meta tunnel" || strings.HasPrefix(description, "meta tunnel #")
}

type outboundInterface struct {
	luid   uint64
	index  uint32
	family uint16
	metric uint32
	mtu    uint32
}

func outboundInterfaces() ([]outboundInterface, error) {
	if err := getBestRoute2.Find(); err != nil {
		return nil, err
	}
	var links *windows.MibIfTable2
	if err := windows.GetIfTable2Ex(windows.MibIfTableNormalWithoutStatistics, &links); err != nil {
		return nil, err
	}
	defer windows.FreeMibTable(unsafe.Pointer(links))
	rows, err := getIPHelperInterfaceTable()
	if err != nil {
		return nil, err
	}
	defer windows.FreeMibTable(unsafe.Pointer(rows))
	eligible := make(map[uint64]bool)
	ownedAdapterGUIDs.RLock()
	for _, link := range unsafe.Slice(&links.Table[0], links.NumEntries) {
		if link.OperStatus == windows.IfOperStatusUp && link.Type != windows.IF_TYPE_SOFTWARE_LOOPBACK && !excludedOutboundAdapter(link) {
			eligible[link.InterfaceLuid] = true
		}
	}
	ownedAdapterGUIDs.RUnlock()
	var result []outboundInterface
	for _, row := range unsafe.Slice(&rows.Table[0], rows.NumEntries) {
		if eligible[row.InterfaceLuid] && row.Connected != 0 && row.InterfaceIndex != 0 {
			result = append(result, outboundInterface{row.InterfaceLuid, row.InterfaceIndex, row.Family, row.Metric, row.NlMtu})
		}
	}
	return result, nil
}

func bestOutboundRoute(target, boundSource netip.Addr, interfaces []outboundInterface) outboundRoute {
	destination := ipHelperSockaddr(target)
	var sourceConstraint *windows.RawSockaddrInet
	if boundSource.IsValid() && !boundSource.IsUnspecified() {
		if boundSource.BitLen() != target.BitLen() {
			return outboundRoute{}
		}
		source := ipHelperSockaddr(boundSource)
		sourceConstraint = &source
	}
	var best outboundRoute
	for _, candidate := range interfaces {
		if candidate.family != destination.Family {
			continue
		}
		var route windows.MibIpForwardRow2
		var rawSource windows.RawSockaddrInet
		result, _, _ := getBestRoute2.Call(0, uintptr(candidate.index), uintptr(unsafe.Pointer(sourceConstraint)),
			uintptr(unsafe.Pointer(&destination)), 0, uintptr(unsafe.Pointer(&route)), uintptr(unsafe.Pointer(&rawSource)))
		if result != 0 || route.InterfaceLuid != candidate.luid || route.InterfaceIndex != candidate.index {
			continue
		}
		prefix := ipHelperRoutePrefix(route)
		source := ipHelperAddr(&rawSource)
		if !prefix.Contains(target) || !source.IsGlobalUnicast() || source.BitLen() != target.BitLen() ||
			(sourceConstraint != nil && source != boundSource) {
			continue
		}
		path := outboundRoute{
			source: source, nextHop: ipHelperAddr(&route.NextHop), index: candidate.index, luid: candidate.luid,
			mtu: candidate.mtu, prefixBits: prefix.Bits(), metric: uint64(route.Metric) + uint64(candidate.metric),
		}
		if path.precedes(best) {
			best = path
		}
	}
	return best
}

func outboundRouteSnapshot(targets []netip.Addr, source netip.Addr) (map[netip.Addr]string, error) {
	interfaces, err := outboundInterfaces()
	if err != nil {
		return nil, err
	}
	entries := make(map[netip.Addr]string, len(targets))
	for _, target := range targets {
		path := bestOutboundRoute(target, source, interfaces)
		entries[target] = fmt.Sprintf("source:%s:hop:%s:if:%d:%d:%d", path.source, path.nextHop, path.luid, path.index, path.mtu)
	}
	return entries, nil
}
