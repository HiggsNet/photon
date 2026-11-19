package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/HiggsNet/photon/internal/trusttunnel"
)

const (
	socksVersion    = 5
	socksConnect    = 1
	socksAssociate  = 3
	socksIPv4       = 1
	socksDomain     = 3
	socksIPv6       = 4
	socksSucceeded  = 0
	socksFailure    = 1
	socksDenied     = 2
	socksBadCommand = 7
	socksBadAddress = 8
)

type tunnelOpener interface {
	open(context.Context, string) (*tunnelStream, error)
}

func serveSOCKS(ctx context.Context, listener net.Listener, client tunnelOpener) error {
	return serveSOCKSListener(ctx, listener, func() tunnelOpener { return client })
}

func serveSOCKSListener(ctx context.Context, listener net.Listener, selectClient func() tunnelOpener) error {
	defer listener.Close()
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()
	slots := make(chan struct{}, sessionLimit)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var workers sync.WaitGroup
	defer workers.Wait()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			cancel()
			return err
		}
		select {
		case slots <- struct{}{}:
			client := selectClient()
			workers.Go(func() {
				defer func() { <-slots }()
				handleSOCKS(ctx, conn.(*net.TCPConn), client)
			})
		default:
			_ = conn.Close()
		}
	}
}

func handleSOCKS(ctx context.Context, conn *net.TCPConn, client tunnelOpener) {
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	_ = conn.SetDeadline(time.Now().Add(setupTimeout))
	var hello [2]byte
	if _, err := io.ReadFull(conn, hello[:]); err != nil || hello[0] != socksVersion {
		return
	}
	methods := make([]byte, hello[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	if !bytes.Contains(methods, []byte{0}) {
		_, _ = conn.Write([]byte{socksVersion, 0xff})
		return
	}
	if _, err := conn.Write([]byte{socksVersion, 0}); err != nil {
		return
	}
	var cmd [3]byte
	if _, err := io.ReadFull(conn, cmd[:]); err != nil || cmd[0] != socksVersion || cmd[2] != 0 {
		return
	}
	host, port, err := readSOCKSAddress(conn)
	if err != nil {
		_ = socksReply(conn, socksBadAddress, netip.AddrPort{})
		return
	}
	_ = conn.SetDeadline(time.Time{})
	switch cmd[1] {
	case socksConnect:
		target := net.JoinHostPort(host, strconv.Itoa(int(port)))
		if _, err := splitTarget(target); err != nil {
			_ = socksReply(conn, socksBadAddress, netip.AddrPort{})
			return
		}
		socksTCP(ctx, conn, client, target)
	case socksAssociate:
		socksUDP(ctx, conn, client, port)
	default:
		_ = socksReply(conn, socksBadCommand, netip.AddrPort{})
	}
}

func socksTCP(ctx context.Context, conn *net.TCPConn, client tunnelOpener, target string) {
	stream, err := client.open(ctx, target)
	if err != nil {
		code := byte(socksFailure)
		if errors.Is(err, errDenied) {
			code = socksDenied
		} else {
			log.Printf("TCP tunnel setup: %v", err)
		}
		_ = socksReply(conn, code, netip.AddrPort{})
		return
	}
	defer stream.Close()
	if err := socksReply(conn, socksSucceeded, netip.AddrPort{}); err != nil {
		return
	}
	uploadDone := make(chan struct{})
	go func() {
		defer close(uploadDone)
		if _, err := io.Copy(stream, conn); err != nil {
			_ = stream.Close()
			return
		}
		_ = stream.CloseWrite()
	}()
	_, _ = io.Copy(conn, stream)
	_ = conn.Close()
	_ = stream.Close()
	<-uploadDone
}

func socksUDP(ctx context.Context, conn *net.TCPConn, client tunnelOpener, requestedPort uint16) {
	localIP := conn.LocalAddr().(*net.TCPAddr).AddrPort().Addr().Unmap()
	peerIP := conn.RemoteAddr().(*net.TCPAddr).AddrPort().Addr().Unmap()
	udp, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(localIP, 0)))
	if err != nil {
		_ = socksReply(conn, socksFailure, netip.AddrPort{})
		return
	}
	defer udp.Close()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stream, err := client.open(ctx, trusttunnel.UDPAuthority)
	if err != nil {
		log.Printf("UDP tunnel setup: %v", err)
		_ = socksReply(conn, socksFailure, netip.AddrPort{})
		return
	}
	defer stream.Close()
	if err := socksReply(conn, socksSucceeded, udp.LocalAddr().(*net.UDPAddr).AddrPort()); err != nil {
		return
	}
	stop := context.AfterFunc(ctx, func() {
		_ = udp.Close()
		_ = conn.Close()
	})
	defer stop()
	var workers sync.WaitGroup
	var source atomic.Pointer[netip.AddrPort]
	workers.Go(func() {
		defer cancel()
		_, _ = io.Copy(io.Discard, conn)
	})
	workers.Go(func() {
		defer cancel()
		for {
			packet, err := trusttunnel.ReadResponse(stream)
			if err != nil {
				return
			}
			if peer := source.Load(); peer != nil && packet.Destination == *peer {
				data := appendSOCKSAddress([]byte{0, 0, 0}, packet.Source)
				_, _ = udp.WriteToUDPAddrPort(append(data, packet.Payload...), *peer)
			}
		}
	})
	defer func() {
		cancel()
		workers.Wait()
	}()
	var packet [65535]byte
	for {
		n, sender, err := udp.ReadFromUDPAddrPort(packet[:])
		if err != nil {
			return
		}
		sender = netip.AddrPortFrom(sender.Addr().Unmap(), sender.Port())
		if sender.Addr() != peerIP || (requestedPort != 0 && sender.Port() != requestedPort) {
			continue
		}
		if selected := source.Load(); selected != nil && sender != *selected {
			continue
		}
		if n < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
			continue
		}
		data := bytes.NewReader(packet[3:n])
		host, port, err := readSOCKSAddress(data)
		if err != nil || port == 0 || !validHost(host) {
			continue
		}
		target, err := udpTarget(ctx, host, port)
		if err != nil {
			continue
		}
		if source.Load() == nil {
			source.Store(&sender)
		}
		if err := trusttunnel.WriteRequest(stream, trusttunnel.Datagram{
			Source: sender, Destination: target, Payload: packet[n-data.Len() : n],
		}); err != nil {
			return
		}
	}
}

func socksReply(w io.Writer, status byte, addr netip.AddrPort) error {
	_, err := w.Write(appendSOCKSAddress([]byte{socksVersion, status, 0}, addr))
	return err
}

func appendSOCKSAddress(data []byte, addr netip.AddrPort) []byte {
	ip := addr.Addr().Unmap()
	if !ip.IsValid() {
		ip = netip.IPv4Unspecified()
	}
	if ip.Is4() {
		data = append(data, socksIPv4)
	} else {
		data = append(data, socksIPv6)
	}
	return binary.BigEndian.AppendUint16(append(data, ip.AsSlice()...), addr.Port())
}

func readSOCKSAddress(r io.Reader) (string, uint16, error) {
	var kind [1]byte
	if _, err := io.ReadFull(r, kind[:]); err != nil {
		return "", 0, err
	}
	var host string
	switch kind[0] {
	case socksIPv4:
		var ip [4]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return "", 0, err
		}
		host = netip.AddrFrom4(ip).String()
	case socksIPv6:
		var ip [16]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return "", 0, err
		}
		host = netip.AddrFrom16(ip).Unmap().String()
	case socksDomain:
		var size [1]byte
		if _, err := io.ReadFull(r, size[:]); err != nil {
			return "", 0, err
		}
		if size[0] == 0 {
			return "", 0, errors.New("empty SOCKS5 hostname")
		}
		name := make([]byte, size[0])
		if _, err := io.ReadFull(r, name); err != nil {
			return "", 0, err
		}
		host = string(name)
	default:
		return "", 0, errors.New("unsupported SOCKS5 address type")
	}
	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return "", 0, err
	}
	return host, binary.BigEndian.Uint16(port[:]), nil
}
