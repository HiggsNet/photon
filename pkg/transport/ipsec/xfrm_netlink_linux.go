package ipsec

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

func inspectPlatformLinks(ctx context.Context, netns NetNSSpec) ([]observedInterface, error) {
	var links []observedInterface
	err := inXFRMNetNS(netns, func() error {
		var err error
		links, err = dumpXFRMInterfaces(ctx, netns)
		return err
	})
	return links, err
}

const namedNetNSDir = "/var/run/netns"
const addrGenModeNone = 1

func listPlatformNetNS() (map[string]bool, error) {
	entries, err := os.ReadDir(namedNetNSDir)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	names := make(map[string]bool, len(entries))
	for _, entry := range entries {
		names[entry.Name()] = true
	}
	return names, nil
}

func probePlatformNetNS(name string) (bool, error) {
	fd, err := openNamedNetNS(name)
	if err == unix.ENOENT {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer unix.Close(fd)
	kind, err := unix.IoctlRetInt(fd, unix.NS_GET_NSTYPE)
	return kind == unix.CLONE_NEWNET, err
}

func openNamedNetNS(name string) (int, error) {
	if name == "" || filepath.Base(name) != name || name == "." || name == ".." {
		return -1, unix.EINVAL
	}
	return unix.Open(filepath.Join(namedNetNSDir, name), unix.O_RDONLY|unix.O_CLOEXEC, 0)
}

func inXFRMNetNS(netns NetNSSpec, operation func() error) error {
	switch netns.Kind {
	case NetNSHost:
		return operation()
	case NetNSName:
		target, err := openNamedNetNS(netns.Name)
		if err != nil {
			return err
		}
		defer unix.Close(target)

		// Retire the OS thread if we cannot restore its original namespace.
		done := make(chan error, 1)
		go func() {
			runtime.LockOSThread()
			canUnlock := true
			defer func() {
				if canUnlock {
					runtime.UnlockOSThread()
				}
			}()
			original, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
			if err != nil {
				done <- err
				return
			}
			defer unix.Close(original)
			if err := unix.Setns(target, unix.CLONE_NEWNET); err != nil {
				done <- err
				return
			}
			canUnlock = false
			err = operation()
			if restoreErr := unix.Setns(original, unix.CLONE_NEWNET); restoreErr != nil {
				done <- fmt.Errorf("restore network namespace: %w", restoreErr)
				return
			}
			canUnlock = true
			done <- err
		}()
		return <-done
	default:
		return unix.EOPNOTSUPP
	}
}

func dumpXFRMInterfaces(ctx context.Context, netns NetNSSpec) ([]observedInterface, error) {
	linkMessages, err := routeDump(ctx, unix.RTM_GETLINK)
	if err != nil {
		return nil, err
	}
	links := make([]observedInterface, 0, len(linkMessages))
	indices := make(map[uint32]int, len(linkMessages))
	for _, msg := range linkMessages {
		if msg.Header.Type != unix.RTM_NEWLINK {
			continue
		}
		link, index, err := decodeRouteLink(netns, msg.Data)
		if err != nil {
			return nil, err
		}
		indices[index] = len(links)
		links = append(links, link)
	}

	addressMessages, err := routeDump(ctx, unix.RTM_GETADDR)
	if err != nil {
		return nil, err
	}
	for _, msg := range addressMessages {
		if msg.Header.Type != unix.RTM_NEWADDR {
			continue
		}
		prefix, index, peer, err := decodeRouteAddress(msg.Data)
		if err != nil {
			return nil, err
		}
		if i, found := indices[index]; found && prefix.IsValid() {
			links[i].state.Addresses = append(links[i].state.Addresses, prefix)
			links[i].hasPeerAddress = links[i].hasPeerAddress || peer
		}
	}
	return links, nil
}

func routeDump(ctx context.Context, request int) ([]syscall.NetlinkMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	data, err := syscall.NetlinkRIB(request, unix.AF_UNSPEC)
	if err != nil {
		return nil, err
	}
	messages, err := syscall.ParseNetlinkMessage(data)
	if err != nil {
		return nil, err
	}
	for _, msg := range messages {
		if msg.Header.Flags&unix.NLM_F_DUMP_INTR != 0 {
			return nil, unix.EINTR
		}
		if msg.Header.Type == unix.NLMSG_OVERRUN ||
			(msg.Header.Type == unix.NLMSG_DONE && len(msg.Data) >= 4 && binary.NativeEndian.Uint32(msg.Data) != 0) {
			return nil, fmt.Errorf("incomplete rtnetlink dump for request %d", request)
		}
	}
	return messages, ctx.Err()
}

func decodeRouteLink(netns NetNSSpec, data []byte) (observedInterface, uint32, error) {
	if len(data) < unix.SizeofIfInfomsg {
		return observedInterface{}, 0, unix.EINVAL
	}
	index := binary.NativeEndian.Uint32(data[4:8])
	flags := binary.NativeEndian.Uint32(data[8:12])
	link := observedInterface{state: XFRMLinkState{
		NetNS: netns, NamespaceExists: true, InterfaceExists: true, FlagsKnown: true,
		InterfaceUp: flags&unix.IFF_UP != 0,
		Multicast:   flags&unix.IFF_MULTICAST != 0,
	}}
	err := visitRouteAttrs(data[unix.SizeofIfInfomsg:], func(kind uint16, value []byte) error {
		switch kind {
		case unix.IFLA_IFNAME:
			link.state.InterfaceName = string(bytes.TrimRight(value, "\x00"))
		case unix.IFLA_LINKINFO:
			var info []byte
			if err := visitRouteAttrs(value, func(kind uint16, value []byte) error {
				switch kind {
				case unix.IFLA_INFO_KIND:
					link.xfrm = bytes.Equal(bytes.TrimRight(value, "\x00"), []byte("xfrm"))
				case unix.IFLA_INFO_DATA:
					info = value
				}
				return nil
			}); err != nil {
				return err
			}
			if link.xfrm {
				return visitRouteAttrs(info, func(kind uint16, value []byte) error {
					if kind == unix.IFLA_XFRM_IF_ID {
						if len(value) != 4 {
							return unix.EINVAL
						}
						link.state.XFRMIfID = binary.NativeEndian.Uint32(value)
					}
					return nil
				})
			}
		case unix.IFLA_AF_SPEC:
			return visitRouteAttrs(value, func(family uint16, value []byte) error {
				if family != unix.AF_INET6 {
					return nil
				}
				return visitRouteAttrs(value, func(kind uint16, value []byte) error {
					if kind == unix.IFLA_INET6_ADDR_GEN_MODE {
						if len(value) != 1 {
							return unix.EINVAL
						}
						link.state.IPv6AddrGenModeKnown = true
						link.state.IPv6AddrGenDisabled = value[0] == addrGenModeNone
					}
					return nil
				})
			})
		}
		return nil
	})
	if err == nil && link.state.InterfaceName == "" {
		err = unix.EINVAL
	}
	return link, index, err
}

func decodeRouteAddress(data []byte) (netip.Prefix, uint32, bool, error) {
	if len(data) < unix.SizeofIfAddrmsg {
		return netip.Prefix{}, 0, false, unix.EINVAL
	}
	family, bits := data[0], int(data[1])
	index := binary.NativeEndian.Uint32(data[4:8])
	if family != unix.AF_INET && family != unix.AF_INET6 {
		return netip.Prefix{}, index, false, nil
	}

	var local, address []byte
	err := visitRouteAttrs(data[unix.SizeofIfAddrmsg:], func(kind uint16, value []byte) error {
		switch kind {
		case unix.IFA_LOCAL:
			local = value
		case unix.IFA_ADDRESS:
			address = value
		}
		return nil
	})
	if local == nil {
		local = address
	}
	addr, ok := netip.AddrFromSlice(local)
	if !ok || (family == unix.AF_INET) != addr.Is4() || bits > addr.BitLen() {
		return netip.Prefix{}, index, false, unix.EINVAL
	}
	return netip.PrefixFrom(addr, bits), index, address != nil && !bytes.Equal(local, address), err
}

func visitRouteAttrs(data []byte, visit func(uint16, []byte) error) error {
	for len(data) != 0 {
		if len(data) < unix.SizeofRtAttr {
			return unix.EINVAL
		}
		length := int(binary.NativeEndian.Uint16(data[:2]))
		aligned := (length + 3) &^ 3
		if length < unix.SizeofRtAttr || aligned > len(data) {
			return unix.EINVAL
		}
		// The top two type bits are NLA_F_NESTED and NLA_F_NET_BYTEORDER.
		kind := binary.NativeEndian.Uint16(data[2:4]) & 0x3fff
		if err := visit(kind, data[unix.SizeofRtAttr:length]); err != nil {
			return err
		}
		data = data[aligned:]
	}
	return nil
}
