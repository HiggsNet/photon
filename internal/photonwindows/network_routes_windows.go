package photonwindows

import (
	"crypto/sha256"
	"fmt"
	"net/netip"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var getBestRoute2 = ipHelperDLL.NewProc("GetBestRoute2")

// Compare the paths actually used by Photon's public peers, including source
// selection, next hop and interface identity/MTU/status. Unrelated VPN adapter
// and route notifications cannot reset the inner network. A VPN or specific
// route that changes a real outer path still triggers recovery. All IP Helper
// calls run in the network observer, never the packet-owner loop.
func outboundRouteSnapshot(targets []netip.Addr) ([32]byte, error) {
	if err := getBestRoute2.Find(); err != nil {
		return [32]byte{}, err
	}
	var entries []string
	for _, target := range targets {
		destination := ipHelperSockaddr(target)
		var route windows.MibIpForwardRow2
		var source windows.RawSockaddrInet
		result, _, _ := getBestRoute2.Call(0, 0, 0, uintptr(unsafe.Pointer(&destination)), 0, uintptr(unsafe.Pointer(&route)), uintptr(unsafe.Pointer(&source)))
		if result != 0 {
			// Stable unreachability is data; losing or regaining a route must change
			// the signature rather than coalescing every failure into one error.
			entries = append(entries, fmt.Sprintf("target:%s:unreachable:%d", target, result))
			continue
		}
		row := windows.MibIfRow2{InterfaceLuid: route.InterfaceLuid}
		if err := ipHelperCall("GetIfEntry2", unsafe.Pointer(&row)); err != nil {
			return [32]byte{}, err
		}
		ipif := ipHelperInterfaceRow{Family: destination.Family, InterfaceLuid: route.InterfaceLuid}
		if err := getIPHelperInterface(&ipif); err != nil {
			return [32]byte{}, err
		}
		entries = append(entries, fmt.Sprintf("target:%s:source:%s:route:%s:%s:%d:if:%s:%d:%d:%d:%d:%d:%d:%d:%d", target, ipHelperAddr(&source), ipHelperRoutePrefix(route), ipHelperAddr(&route.NextHop), route.Metric, row.InterfaceGuid.String(), row.InterfaceLuid, row.OperStatus, row.AdminStatus, row.MediaConnectState, row.Mtu, ipif.NlMtu, ipif.Metric, ipif.Connected))
	}
	return sha256.Sum256([]byte(strings.Join(entries, "\n"))), nil
}
