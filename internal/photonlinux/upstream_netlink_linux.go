//go:build linux

package photonlinux

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type upstreamNetlink struct {
	fd           int
	index        uint32
	seq          uint32
	name         string
	readySources map[netip.Addr]bool // only for this single synchronous reconcile
}

// Linux IFA_PROTO (11), added in 5.18; x/sys does not expose it yet.
const upstreamAddressProtocolAttr = 11

func withUpstreamRouteIO(ctx context.Context, spec UpstreamRouteSpec, operation func(upstreamRouteIO) error) error {
	return inUpstreamNamespace(spec.NetNS, func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		iface, err := net.InterfaceByName(spec.Interface)
		if err != nil {
			return err
		}
		fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
		if err != nil {
			return err
		}
		defer unix.Close(fd)
		// Short reads allow cancellation without closing a potentially reused fd.
		timeout := unix.NsecToTimeval((100 * time.Millisecond).Nanoseconds())
		if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout); err != nil {
			return err
		}
		return operation(&upstreamNetlink{fd: fd, index: uint32(iface.Index), name: iface.Name})
	})
}

func inUpstreamNamespace(name string, operation func() error) error {
	if name == "" || name == "host" {
		return operation()
	}
	if filepath.Base(name) != name || name == "." || name == ".." {
		return fmt.Errorf("invalid upstream namespace %q", name)
	}
	target, err := unix.Open(filepath.Join("/var/run/netns", name), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(target)
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		restored := true
		defer func() {
			if restored {
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
		restored = false
		err = operation()
		if restoreErr := unix.Setns(original, unix.CLONE_NEWNET); restoreErr != nil {
			// Exiting while locked retires this thread instead of returning a
			// thread in the wrong namespace to the Go scheduler.
			done <- errors.Join(err, fmt.Errorf("restore upstream namespace: %w", restoreErr))
			return
		}
		restored = true
		done <- err
	}()
	return <-done
}

func (io *upstreamNetlink) exchange(ctx context.Context, kind, flags uint16, payload []byte) ([]syscall.NetlinkMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	io.seq++
	request := make([]byte, unix.NLMSG_HDRLEN)
	binary.NativeEndian.PutUint32(request, uint32(len(request)+len(payload)))
	binary.NativeEndian.PutUint16(request[4:6], kind)
	binary.NativeEndian.PutUint16(request[6:8], unix.NLM_F_REQUEST|flags)
	binary.NativeEndian.PutUint32(request[8:12], io.seq)
	request = append(request, payload...)
	if err := unix.Sendto(io.fd, request, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(2 * time.Second)
	var result []syscall.NetlinkMessage
	buffer := make([]byte, 64<<10)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("upstream rtnetlink response: %w", os.ErrDeadlineExceeded)
		}
		n, _, flags, sender, err := unix.Recvmsg(io.fd, buffer, nil, 0)
		if err == unix.EINTR || err == unix.EAGAIN {
			continue
		}
		if err != nil {
			return nil, err
		}
		kernel, ok := sender.(*unix.SockaddrNetlink)
		if !ok || kernel.Pid != 0 || flags&unix.MSG_TRUNC != 0 {
			return nil, fmt.Errorf("invalid or truncated upstream rtnetlink response")
		}
		messages, err := syscall.ParseNetlinkMessage(buffer[:n])
		if err != nil {
			return nil, err
		}
		for _, message := range messages {
			if message.Header.Seq != io.seq {
				continue // A canceled or failed request can leave a late ACK.
			}
			if message.Header.Flags&unix.NLM_F_DUMP_INTR != 0 || message.Header.Type == unix.NLMSG_OVERRUN {
				return nil, fmt.Errorf("incomplete upstream rtnetlink dump")
			}
			switch message.Header.Type {
			case unix.NLMSG_ERROR, unix.NLMSG_DONE:
				if len(message.Data) >= 4 {
					code := int32(binary.NativeEndian.Uint32(message.Data))
					if code < 0 {
						return nil, unix.Errno(-code)
					}
					if code > 0 {
						return nil, fmt.Errorf("invalid upstream rtnetlink error %d", code)
					}
				} else if message.Header.Type == unix.NLMSG_ERROR {
					return nil, fmt.Errorf("short upstream rtnetlink acknowledgement")
				}
				return result, nil
			default:
				message.Data = append([]byte(nil), message.Data...)
				result = append(result, message)
			}
		}
	}
}

func (io *upstreamNetlink) Read(ctx context.Context) (upstreamSnapshot, error) {
	var snapshot upstreamSnapshot
	addresses, err := io.exchange(ctx, unix.RTM_GETADDR, unix.NLM_F_DUMP, make([]byte, unix.SizeofIfAddrmsg))
	if err != nil {
		return snapshot, err
	}
	for _, message := range addresses {
		if message.Header.Type != unix.RTM_NEWADDR || len(message.Data) < unix.SizeofIfAddrmsg {
			return snapshot, fmt.Errorf("invalid upstream address dump")
		}
		if binary.NativeEndian.Uint32(message.Data[4:8]) != io.index {
			continue
		}
		attributes, err := syscall.ParseNetlinkRouteAttr(&message)
		if err != nil {
			return snapshot, err
		}
		var local, peer netip.Addr
		var protocol uint8
		addressFlags := uint32(message.Data[2])
		for _, attribute := range attributes {
			switch attribute.Attr.Type {
			case unix.IFA_LOCAL:
				local, _ = netip.AddrFromSlice(attribute.Value)
			case unix.IFA_ADDRESS:
				peer, _ = netip.AddrFromSlice(attribute.Value)
			case upstreamAddressProtocolAttr:
				if len(attribute.Value) != 1 {
					return snapshot, fmt.Errorf("invalid upstream address protocol")
				}
				protocol = attribute.Value[0]
			case unix.IFA_FLAGS:
				if len(attribute.Value) != 4 {
					return snapshot, fmt.Errorf("invalid upstream address flags")
				}
				addressFlags = binary.NativeEndian.Uint32(attribute.Value)
			}
		}
		if !local.IsValid() {
			local = peer
		}
		prefix := netip.PrefixFrom(local, int(message.Data[1]))
		if !prefix.IsValid() {
			return snapshot, fmt.Errorf("invalid upstream address prefix")
		}
		snapshot.Addresses = append(snapshot.Addresses, upstreamAddress{Prefix: prefix, Protocol: protocol})
		if addressFlags&(unix.IFA_F_TENTATIVE|unix.IFA_F_DADFAILED) != 0 {
			if snapshot.UnreadyAddresses == nil {
				snapshot.UnreadyAddresses = make(map[netip.Addr]uint32)
			}
			snapshot.UnreadyAddresses[local] = addressFlags
		}
	}
	for _, family := range []byte{unix.AF_INET, unix.AF_INET6} {
		payload := make([]byte, unix.SizeofRtMsg)
		payload[0] = family
		routes, err := io.exchange(ctx, unix.RTM_GETROUTE, unix.NLM_F_DUMP, payload)
		if err != nil {
			return snapshot, err
		}
		for _, message := range routes {
			route, found, err := decodeUpstreamRoute(message, io.index)
			if err != nil {
				return snapshot, err
			}
			if found {
				snapshot.Routes = append(snapshot.Routes, route)
			}
		}
	}
	return snapshot, nil
}

func decodeUpstreamRoute(message syscall.NetlinkMessage, index uint32) (upstreamRoute, bool, error) {
	var route upstreamRoute
	if message.Header.Type != unix.RTM_NEWROUTE || len(message.Data) < unix.SizeofRtMsg {
		return route, false, fmt.Errorf("invalid upstream route dump")
	}
	data := message.Data
	if data[7] != unix.RTN_UNICAST {
		return route, false, nil
	}
	var table, output uint32 = uint32(data[4]), 0
	address := netip.IPv6Unspecified()
	if data[0] == unix.AF_INET {
		address = netip.IPv4Unspecified()
	}
	attributes, err := syscall.ParseNetlinkRouteAttr(&message)
	if err != nil {
		return route, false, err
	}
	for _, attribute := range attributes {
		switch attribute.Attr.Type {
		case unix.RTA_OIF, unix.RTA_TABLE, unix.RTA_PRIORITY:
			if len(attribute.Value) != 4 {
				return route, false, fmt.Errorf("invalid upstream route attribute")
			}
			value := binary.NativeEndian.Uint32(attribute.Value)
			switch attribute.Attr.Type {
			case unix.RTA_OIF:
				output = value
			case unix.RTA_TABLE:
				table = value
			case unix.RTA_PRIORITY:
				route.Metric = value
			}
		case unix.RTA_DST:
			address, _ = netip.AddrFromSlice(attribute.Value)
		case unix.RTA_GATEWAY:
			route.Gateway, _ = netip.AddrFromSlice(attribute.Value)
		case unix.RTA_PREFSRC:
			route.Source, _ = netip.AddrFromSlice(attribute.Value)
		}
	}
	if table != unix.RT_TABLE_MAIN || output != index {
		return route, false, nil
	}
	route.Prefix = netip.PrefixFrom(address, int(data[1]))
	route.Protocol = data[5]
	if !route.Prefix.IsValid() {
		return route, false, fmt.Errorf("invalid upstream route prefix")
	}
	return route, true, nil
}

func (io *upstreamNetlink) Apply(ctx context.Context, operation upstreamOperation) error {
	if operation.Delete && operation.Address != nil {
		// IFA_PROTO is not an atomic delete predicate on every kernel. Recheck
		// it so a source deliberately taken over by an administrator survives.
		observed, err := io.Read(ctx)
		if err != nil {
			return err
		}
		if !slices.Contains(observed.Addresses, *operation.Address) {
			return nil
		}
	}
	if operation.Delete && operation.Address != nil && operation.Address.Prefix.Addr().Is4() {
		// Linux otherwise removes secondary IPv4 addresses when their primary
		// is deleted, including administrator addresses and replacement sources.
		return io.withSecondaryPromotion(func() error { return io.apply(ctx, operation) })
	}
	return io.apply(ctx, operation)
}

func (io *upstreamNetlink) withSecondaryPromotion(operation func() error) (err error) {
	path := filepath.Join("/proc/sys/net/ipv4/conf", io.name, "promote_secondaries")
	previous, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read upstream secondary-address policy: %w", err)
	}
	if strings.TrimSpace(string(previous)) == "1" {
		return operation()
	}
	if err := os.WriteFile(path, []byte("1"), 0o644); err != nil {
		return fmt.Errorf("preserve upstream secondary addresses: %w", err)
	}
	defer func() { err = errors.Join(err, os.WriteFile(path, previous, 0o644)) }()
	return operation()
}

func (io *upstreamNetlink) apply(ctx context.Context, operation upstreamOperation) error {
	if operation.Route != nil && !operation.Delete && operation.Route.Source.IsValid() {
		if err := io.waitSourceReady(ctx, operation.Route.Source); err != nil {
			return err
		}
	}
	kind, flags, payload := encodeUpstreamOperation(io.index, operation)
	_, err := io.exchange(ctx, kind, flags|unix.NLM_F_ACK, payload)
	if operation.Delete && (errors.Is(err, unix.ESRCH) || errors.Is(err, unix.EADDRNOTAVAIL)) {
		return nil // Another kernel action already removed this exact object.
	}
	if err != nil {
		if operation.Route != nil {
			return fmt.Errorf("apply upstream route %s via %s source %s: %w", operation.Route.Prefix, operation.Route.Gateway, operation.Route.Source, err)
		}
		return fmt.Errorf("apply upstream source address %s: %w", operation.Address.Prefix, err)
	}
	if operation.Address != nil && !operation.Delete {
		// Old kernels may silently ignore IFA_PROTO. Never report success for
		// an unmarked installation that a future reconcile cannot safely own.
		observed, readErr := io.Read(ctx)
		if readErr == nil {
			for _, address := range observed.Addresses {
				if address == *operation.Address {
					return nil
				}
			}
		}
		rollback := operation
		rollback.Delete = true
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		// This is the address just created by our acknowledged exclusive add,
		// so rollback is allowed even when the kernel discarded its marker.
		var cleanupErr error
		if rollback.Address.Prefix.Addr().Is4() {
			cleanupErr = io.withSecondaryPromotion(func() error { return io.apply(cleanupCtx, rollback) })
		} else {
			cleanupErr = io.apply(cleanupCtx, rollback)
		}
		return errors.Join(fmt.Errorf("upstream source address ownership could not be confirmed; Linux 5.18+ with IFA_PROTO is required"), readErr, cleanupErr)
	}
	return nil
}

func (io *upstreamNetlink) waitSourceReady(ctx context.Context, source netip.Addr) error {
	if source.Is4() || io.readySources[source] {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	for {
		observed, err := io.Read(ctx)
		if err != nil {
			return err
		}
		flags := observed.UnreadyAddresses[source]
		if flags&unix.IFA_F_DADFAILED != 0 {
			return fmt.Errorf("upstream source address %s failed duplicate-address detection", source)
		}
		if flags&unix.IFA_F_TENTATIVE == 0 {
			if io.readySources == nil {
				io.readySources = make(map[netip.Addr]bool)
			}
			io.readySources[source] = true
			return nil
		}
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func encodeUpstreamOperation(index uint32, operation upstreamOperation) (uint16, uint16, []byte) {
	flags := uint16(unix.NLM_F_CREATE | unix.NLM_F_EXCL)
	if operation.Delete {
		flags = 0
	}
	if address := operation.Address; address != nil {
		payload := make([]byte, unix.SizeofIfAddrmsg)
		payload[0], payload[1] = upstreamFamily(address.Prefix.Addr()), byte(address.Prefix.Bits())
		binary.NativeEndian.PutUint32(payload[4:8], index)
		payload = upstreamAttr(payload, unix.IFA_LOCAL, address.Prefix.Addr().AsSlice())
		payload = upstreamAttr(payload, unix.IFA_ADDRESS, address.Prefix.Addr().AsSlice())
		payload = upstreamAttr(payload, upstreamAddressProtocolAttr, []byte{address.Protocol})
		kind := uint16(unix.RTM_NEWADDR)
		if operation.Delete {
			kind = unix.RTM_DELADDR
		}
		return kind, flags, payload
	}
	route := operation.Route
	payload := make([]byte, unix.SizeofRtMsg)
	payload[0], payload[1] = upstreamFamily(route.Prefix.Addr()), byte(route.Prefix.Bits())
	payload[4], payload[5], payload[6], payload[7] = unix.RT_TABLE_MAIN, route.Protocol, unix.RT_SCOPE_LINK, unix.RTN_UNICAST
	if route.Gateway.IsValid() {
		payload[6] = unix.RT_SCOPE_UNIVERSE
		payload = upstreamAttr(payload, unix.RTA_GATEWAY, route.Gateway.AsSlice())
	}
	if route.Source.IsValid() {
		payload = upstreamAttr(payload, unix.RTA_PREFSRC, route.Source.AsSlice())
	}
	payload = upstreamAttr(payload, unix.RTA_DST, route.Prefix.Addr().AsSlice())
	payload = upstreamAttr(payload, unix.RTA_OIF, binary.NativeEndian.AppendUint32(nil, index))
	payload = upstreamAttr(payload, unix.RTA_PRIORITY, binary.NativeEndian.AppendUint32(nil, route.Metric))
	kind := uint16(unix.RTM_NEWROUTE)
	if operation.Delete {
		kind = unix.RTM_DELROUTE
	}
	return kind, flags, payload
}

func upstreamFamily(address netip.Addr) byte {
	if address.Is4() {
		return unix.AF_INET
	}
	return unix.AF_INET6
}

func upstreamAttr(payload []byte, kind uint16, value []byte) []byte {
	length := unix.SizeofRtAttr + len(value)
	payload = binary.NativeEndian.AppendUint16(payload, uint16(length))
	payload = binary.NativeEndian.AppendUint16(payload, kind)
	payload = append(payload, value...)
	return append(payload, make([]byte, (-length)&3)...)
}
