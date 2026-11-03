package ipsec

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"golang.org/x/sys/unix"
)

func mutatePlatformLink(ctx context.Context, ns NetNSSpec, name string, op xfrmMutation) (attempted bool, err error) {
	targetFD := -1
	if op.kind == xfrmMove {
		if op.target.Kind == NetNSHost {
			// Match the existing ip command's destination, PID 1.
			targetFD, err = unix.Open("/proc/1/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
		} else {
			targetFD, err = openNamedNetNS(op.target.Name)
		}
		if err != nil {
			return false, err
		}
		defer unix.Close(targetFD)
	}

	err = inXFRMNetNS(ns, func() error {
		index := 0
		if op.kind != xfrmAdd {
			iface, err := net.InterfaceByName(name)
			if err != nil {
				return err
			}
			index = iface.Index
		}
		typ, flags, payload := encodeXFRMMutation(index, name, op, targetFD)
		return sendXFRMMutation(ctx, typ, flags, payload, &attempted)
	})
	return attempted, err
}

func encodeXFRMMutation(index int, name string, op xfrmMutation, targetFD int) (uint16, uint16, []byte) {
	if op.kind == xfrmReplaceAddr || op.kind == xfrmDeleteAddr {
		prefix := op.prefix
		addr := prefix.Addr()
		payload := make([]byte, unix.SizeofIfAddrmsg)
		payload[0] = unix.AF_INET6
		if addr.Is4() {
			payload[0] = unix.AF_INET
		}
		payload[1] = byte(prefix.Bits())
		if addr.Is4() && addr.IsLoopback() && op.kind == xfrmReplaceAddr {
			payload[3] = unix.RT_SCOPE_HOST
		}
		binary.NativeEndian.PutUint32(payload[4:8], uint32(index))
		payload = appendRouteAttr(payload, unix.IFA_LOCAL, addr.AsSlice())
		payload = appendRouteAttr(payload, unix.IFA_ADDRESS, addr.AsSlice())
		if op.kind == xfrmDeleteAddr {
			return unix.RTM_DELADDR, 0, payload
		}
		return unix.RTM_NEWADDR, unix.NLM_F_CREATE | unix.NLM_F_REPLACE, payload
	}

	payload := make([]byte, unix.SizeofIfInfomsg)
	binary.NativeEndian.PutUint32(payload[4:8], uint32(index))
	switch op.kind {
	case xfrmAdd:
		payload = appendRouteAttr(payload, unix.IFLA_IFNAME, append([]byte(name), 0))
		info := appendRouteAttr(nil, unix.IFLA_INFO_KIND, []byte("xfrm\x00"))
		data := appendRouteAttr(nil, unix.IFLA_XFRM_IF_ID, routeUint32(op.ifID))
		info = appendRouteAttr(info, unix.IFLA_INFO_DATA|unix.NLA_F_NESTED, data)
		payload = appendRouteAttr(payload, unix.IFLA_LINKINFO|unix.NLA_F_NESTED, info)
		return unix.RTM_NEWLINK, unix.NLM_F_CREATE | unix.NLM_F_EXCL, payload
	case xfrmDelete:
		return unix.RTM_DELLINK, 0, payload
	case xfrmMove:
		payload = appendRouteAttr(payload, unix.IFLA_NET_NS_FD, routeUint32(uint32(targetFD)))
	case xfrmUp, xfrmMulticast:
		flag := uint32(unix.IFF_UP)
		if op.kind == xfrmMulticast {
			flag = unix.IFF_MULTICAST
		}
		binary.NativeEndian.PutUint32(payload[8:12], flag)
		binary.NativeEndian.PutUint32(payload[12:16], flag)
	case xfrmDisableAddrGen:
		inet6 := appendRouteAttr(nil, unix.IFLA_INET6_ADDR_GEN_MODE, []byte{addrGenModeNone})
		af := appendRouteAttr(nil, unix.AF_INET6|unix.NLA_F_NESTED, inet6)
		payload = appendRouteAttr(payload, unix.IFLA_AF_SPEC|unix.NLA_F_NESTED, af)
	}
	return unix.RTM_NEWLINK, 0, payload
}

func routeUint32(value uint32) []byte {
	return binary.NativeEndian.AppendUint32(nil, value)
}

func appendRouteAttr(dst []byte, kind uint16, value []byte) []byte {
	length := unix.SizeofRtAttr + len(value)
	dst = binary.NativeEndian.AppendUint16(dst, uint16(length))
	dst = binary.NativeEndian.AppendUint16(dst, kind)
	dst = append(dst, value...)
	return append(dst, make([]byte, (-length)&3)...)
}

func sendXFRMMutation(ctx context.Context, typ, flags uint16, payload []byte, attempted *bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	timeout := 2 * time.Second
	if deadline, ok := ctx.Deadline(); ok {
		timeout = min(timeout, time.Until(deadline))
		if timeout <= 0 {
			return context.DeadlineExceeded
		}
	}
	timeval := unix.NsecToTimeval(timeout.Nanoseconds())
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeval); err != nil {
		return err
	}
	request := make([]byte, unix.NLMSG_HDRLEN, unix.NLMSG_HDRLEN+len(payload))
	binary.NativeEndian.PutUint32(request, uint32(unix.NLMSG_HDRLEN+len(payload)))
	binary.NativeEndian.PutUint16(request[4:6], typ)
	binary.NativeEndian.PutUint16(request[6:8], flags|unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	const seq = 1
	binary.NativeEndian.PutUint32(request[8:12], seq)
	request = append(request, payload...)
	if err := unix.Sendto(fd, request, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	*attempted = true
	var buf [4096]byte
	n, sender, err := unix.Recvfrom(fd, buf[:], 0)
	for err == unix.EINTR && ctx.Err() == nil {
		n, sender, err = unix.Recvfrom(fd, buf[:], 0)
	}
	if err != nil {
		return fmt.Errorf("receive rtnetlink acknowledgement: %w", err)
	}
	kernel, ok := sender.(*unix.SockaddrNetlink)
	if !ok || kernel.Pid != 0 || n < unix.NLMSG_HDRLEN+4 ||
		binary.NativeEndian.Uint32(buf[:4]) != uint32(n) ||
		binary.NativeEndian.Uint16(buf[4:6]) != unix.NLMSG_ERROR ||
		binary.NativeEndian.Uint32(buf[8:12]) != seq {
		return fmt.Errorf("unexpected rtnetlink acknowledgement")
	}
	code := int32(binary.NativeEndian.Uint32(buf[unix.NLMSG_HDRLEN:]))
	if code < 0 {
		return unix.Errno(-code)
	}
	if code > 0 {
		return fmt.Errorf("invalid rtnetlink acknowledgement code %d", code)
	}
	return nil
}
