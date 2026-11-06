package photonwindows

import (
	"fmt"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

var getBestRoute2 = ipHelperDLL.NewProc("GetBestRoute2")

// Compare the paths actually used by Photon's public peers, including source
// selection, next hop and interface identity/MTU/status. Unrelated VPN adapter
// and route notifications cannot reset the inner network. A VPN or specific
// route that changes a real outer path still triggers recovery. All IP Helper
// calls run in the network observer, never the packet-owner loop.
func outboundRouteSnapshot(targets []netip.Addr) (map[netip.Addr]string, error) {
	if err := getBestRoute2.Find(); err != nil {
		return nil, err
	}
	entries := make(map[netip.Addr]string, len(targets))
	for _, target := range targets {
		destination := ipHelperSockaddr(target)
		var route windows.MibIpForwardRow2
		var source windows.RawSockaddrInet
		result, _, _ := getBestRoute2.Call(0, 0, 0, uintptr(unsafe.Pointer(&destination)), 0, uintptr(unsafe.Pointer(&route)), uintptr(unsafe.Pointer(&source)))
		if result != 0 {
			// Stable unreachability is data; losing or regaining a route must change
			// the signature rather than coalescing every failure into one error.
			entries[target] = "unreachable"
			continue
		}
		row := windows.MibIfRow2{InterfaceLuid: route.InterfaceLuid}
		if err := ipHelperCall("GetIfEntry2", unsafe.Pointer(&row)); err != nil {
			return nil, err
		}
		ipif := ipHelperInterfaceRow{Family: destination.Family, InterfaceLuid: route.InterfaceLuid}
		if err := getIPHelperInterface(&ipif); err != nil {
			return nil, err
		}
		entries[target] = fmt.Sprintf("source:%s:hop:%s:if:%s:%d:%d:%d:%d:%d:%d:%d", ipHelperAddr(&source), ipHelperAddr(&route.NextHop), row.InterfaceGuid.String(), row.InterfaceLuid, row.OperStatus, row.AdminStatus, row.MediaConnectState, row.Mtu, ipif.NlMtu, ipif.Connected)
	}
	return entries, nil
}
