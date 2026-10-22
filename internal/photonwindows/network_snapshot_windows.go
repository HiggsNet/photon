package photonwindows

import (
	"crypto/sha256"
	"fmt"
	"slices"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Register the requested adapter GUID before Wintun starts creating it. LUIDs
// do not exist yet at that point. The registry describes owned OS resources,
// never business intent, and entries disappear only after adapter destruction.
var ownedAdapterGUIDs = struct {
	sync.RWMutex
	refs map[windows.GUID]int
}{refs: make(map[windows.GUID]int)}

func registerOwnedAdapter(guid windows.GUID) func() {
	ownedAdapterGUIDs.Lock()
	ownedAdapterGUIDs.refs[guid]++
	ownedAdapterGUIDs.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			ownedAdapterGUIDs.Lock()
			defer ownedAdapterGUIDs.Unlock()
			ownedAdapterGUIDs.refs[guid]--
			if ownedAdapterGUIDs.refs[guid] == 0 {
				delete(ownedAdapterGUIDs.refs, guid)
			}
		})
	}
}

// Read only stable underlay properties. Age/counters/countdown lifetimes must
// not make an unrelated notification look like a network configuration change.
// All routes matter: an endpoint may use a specific route, not the default.
func underlaySnapshot() ([32]byte, error) {
	ownedAdapterGUIDs.RLock()
	defer ownedAdapterGUIDs.RUnlock()
	var interfaces *windows.MibIfTable2
	if err := windows.GetIfTable2Ex(windows.MibIfTableNormalWithoutStatistics, &interfaces); err != nil {
		return [32]byte{}, err
	}
	defer windows.FreeMibTable(unsafe.Pointer(interfaces))
	underlay := make(map[uint64]bool)
	var entries []string
	ipInterfaces, err := getIPHelperInterfaceTable()
	if err != nil {
		return [32]byte{}, err
	}
	defer windows.FreeMibTable(unsafe.Pointer(ipInterfaces))
	ipLUIDs := make(map[uint64]bool)
	for _, row := range unsafe.Slice(&ipInterfaces.Table[0], ipInterfaces.NumEntries) {
		ipLUIDs[row.InterfaceLuid] = true
	}
	for _, row := range unsafe.Slice(&interfaces.Table[0], interfaces.NumEntries) {
		// MIB_IF_TABLE2 can briefly retain an adapter after its IP interfaces
		// have been deleted. Such tombstones cannot be an IP underlay and must
		// not resurrect our GUID after Close unregisters its ownership.
		if ownedAdapterGUIDs.refs[row.InterfaceGuid] != 0 || !ipLUIDs[row.InterfaceLuid] {
			continue
		}
		underlay[row.InterfaceLuid] = true
		entries = append(entries, fmt.Sprintf("if:%d:%d:%d:%d:%d:%d", row.InterfaceLuid, row.InterfaceIndex, row.Mtu, row.OperStatus, row.AdminStatus, row.MediaConnectState))
	}
	for _, row := range unsafe.Slice(&ipInterfaces.Table[0], ipInterfaces.NumEntries) {
		if underlay[row.InterfaceLuid] {
			entries = append(entries, fmt.Sprintf("ipif:%d:%d:%d:%d:%d:%d", row.InterfaceLuid, row.Family, row.Metric, row.NlMtu, row.UseAutomaticMetric, row.Connected))
		}
	}
	var addresses *windows.MibUnicastIpAddressTable
	if err := windows.GetUnicastIpAddressTable(windows.AF_UNSPEC, &addresses); err != nil {
		return [32]byte{}, err
	}
	defer windows.FreeMibTable(unsafe.Pointer(addresses))
	for _, row := range unsafe.Slice(&addresses.Table[0], addresses.NumEntries) {
		if underlay[row.InterfaceLuid] {
			entries = append(entries, fmt.Sprintf("addr:%d:%s:%d:%d", row.InterfaceLuid, ipHelperAddressPrefix(row), row.DadState, row.SkipAsSource))
		}
	}
	var routes *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(windows.AF_UNSPEC, &routes); err != nil {
		return [32]byte{}, err
	}
	defer windows.FreeMibTable(unsafe.Pointer(routes))
	for _, row := range routes.Rows() {
		if underlay[row.InterfaceLuid] {
			entries = append(entries, fmt.Sprintf("route:%d:%s:%s:%d:%d", row.InterfaceLuid, ipHelperRoutePrefix(row), ipHelperAddr(&row.NextHop), row.Metric, row.Protocol))
		}
	}
	slices.Sort(entries)
	return sha256.Sum256([]byte(strings.Join(entries, "\n"))), nil
}
