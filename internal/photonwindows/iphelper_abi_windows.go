package photonwindows

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// MIB_IPINTERFACE_ROW from netioapi.h. x/sys v0.47.0 incorrectly models the
// two NL_INTERFACE_OFFLOAD_ROD members as uint32. Each is eight BOOLEAN bits
// packed into ONE byte, making the amd64 row 168 bytes, not 176. The incorrect
// stride silently corrupts every table entry after the first.
// https://learn.microsoft.com/en-us/windows/win32/api/nldef/ns-nldef-nl_interface_offload_rod
type ipHelperInterfaceRow struct {
	Family                               uint16
	InterfaceLuid                        uint64
	InterfaceIndex                       uint32
	MaxReassemblySize                    uint32
	InterfaceIdentifier                  uint64
	MinRouterAdvertisementInterval       uint32
	MaxRouterAdvertisementInterval       uint32
	AdvertisingEnabled                   uint8
	ForwardingEnabled                    uint8
	WeakHostSend                         uint8
	WeakHostReceive                      uint8
	UseAutomaticMetric                   uint8
	UseNeighborUnreachabilityDetection   uint8
	ManagedAddressConfigurationSupported uint8
	OtherStatefulConfigurationSupported  uint8
	AdvertiseDefaultRoute                uint8
	RouterDiscoveryBehavior              uint32
	DadTransmits                         uint32
	BaseReachableTime                    uint32
	RetransmitTime                       uint32
	PathMtuDiscoveryTimeout              uint32
	LinkLocalAddressBehavior             uint32
	LinkLocalAddressTimeout              uint32
	ZoneIndices                          [16]uint32
	SitePrefixLength                     uint32
	Metric                               uint32
	NlMtu                                uint32
	Connected                            uint8
	SupportsWakeUpPatterns               uint8
	SupportsNeighborDiscovery            uint8
	SupportsRouterDiscovery              uint8
	ReachableTime                        uint32
	TransmitOffload                      uint8
	ReceiveOffload                       uint8
	DisableDefaultRoutes                 uint8
}

type ipHelperInterfaceTable struct {
	NumEntries uint32
	Table      [1]ipHelperInterfaceRow
}

func getIPHelperInterface(row *ipHelperInterfaceRow) error {
	return ipHelperCall("GetIpInterfaceEntry", unsafe.Pointer(row))
}

func getIPHelperInterfaceTable() (*ipHelperInterfaceTable, error) {
	var table *ipHelperInterfaceTable
	// Only the returned allocation pointer crosses this cast; never access the
	// x/sys row or table layout. FreeMibTable remains the allocation's owner.
	err := windows.GetIpInterfaceTable(windows.AF_UNSPEC, (**windows.MibIpInterfaceTable)(unsafe.Pointer(&table)))
	return table, err
}
