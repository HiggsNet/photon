//go:build linux

package photonlinux

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/sys/unix"
)

// ReadIPsecInterfaces observes the host namespace. RTM_GETADDR includes address
// flags/lifetimes that net.Interface.Addrs omits (DAD, privacy and deprecation).
func ReadIPsecInterfaces() ([]IPsecInterface, error) {
	devices, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	data, err := syscall.NetlinkRIB(unix.RTM_GETADDR, unix.AF_UNSPEC)
	if err != nil {
		return nil, err
	}
	messages, err := syscall.ParseNetlinkMessage(data)
	if err != nil {
		return nil, err
	}
	byIndex := map[int]int{}
	inventory := make([]IPsecInterface, 0, len(devices))
	for _, device := range devices {
		byIndex[device.Index] = len(inventory)
		inventory = append(inventory, IPsecInterface{Name: device.Name, Up: device.Flags&net.FlagUp != 0})
	}
	for _, message := range messages {
		if message.Header.Type != unix.RTM_NEWADDR {
			continue
		}
		if len(message.Data) < unix.SizeofIfAddrmsg {
			return nil, fmt.Errorf("short interface address netlink message")
		}
		deviceIndex := binary.NativeEndian.Uint32(message.Data[4:8])
		index, ok := byIndex[int(deviceIndex)]
		if !ok {
			continue
		}
		attrs, err := syscall.ParseNetlinkRouteAttr(&message)
		if err != nil {
			return nil, err
		}
		flags := uint32(message.Data[2])
		var local, peer netip.Addr
		deprecated := false
		for _, attr := range attrs {
			switch attr.Attr.Type {
			case unix.IFA_LOCAL:
				local, _ = netip.AddrFromSlice(attr.Value)
			case unix.IFA_ADDRESS:
				peer, _ = netip.AddrFromSlice(attr.Value)
			case unix.IFA_FLAGS:
				if len(attr.Value) >= 4 {
					flags = binary.NativeEndian.Uint32(attr.Value)
				}
			case unix.IFA_CACHEINFO:
				if len(attr.Value) >= 8 {
					deprecated = binary.NativeEndian.Uint32(attr.Value) == 0 || binary.NativeEndian.Uint32(attr.Value[4:]) == 0
				}
			}
		}
		if !local.IsValid() {
			local = peer
		}
		local = local.Unmap()
		if !local.IsValid() {
			continue
		}
		inventory[index].Addresses = append(inventory[index].Addresses, IPsecInterfaceAddress{Address: local, Temporary: local.Is6() && flags&unix.IFA_F_TEMPORARY != 0, Deprecated: deprecated || flags&unix.IFA_F_DEPRECATED != 0, Tentative: flags&(unix.IFA_F_TENTATIVE|unix.IFA_F_DADFAILED) != 0})
	}
	return inventory, nil
}
