package photonwindows

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Exercises the real OS IP stack in both directions on a disposable adapter:
// UDP socket -> routing -> Wintun.Read -> reply -> Wintun.Write -> UDP socket.
// No physical network listener, firewall change or external peer is involved.
func TestWintunNativeUDPRoundTrip(t *testing.T) {
	if os.Getenv("PHOTON_IPHELPER_SMOKE") != "1" {
		t.Skip("requires elevated Windows VM and pinned adjacent wintun.dll")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	device, err := openWintun(ctx, fmt.Sprintf("PhotonUDPTest-%d", os.Getpid()), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(device.Close)
	want := ipHelperTestIntent()
	driver, err := newIPHelperDriver(device, want.Routes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := driver.Reconcile(ctx, want); err != nil {
		t.Fatal(err)
	}
	for {
		o, err := driver.Observe(ctx)
		if err != nil {
			t.Fatal(err)
		}
		ready := len(o.addresses) == len(want.Addresses)
		for _, row := range o.addresses {
			ready = ready && row.DadState == 4
		}
		if ready {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("addresses did not become usable")
		case <-time.After(50 * time.Millisecond):
		}
	}
	for _, pair := range []struct{ local, remote string }{
		{"198.18.254.1", "198.18.254.2"},
		{"fd00:7068:ffff::1", "fd00:7068:ffff::2"},
	} {
		t.Run(pair.local, func(t *testing.T) {
			local, remote := netip.MustParseAddr(pair.local), netip.MustParseAddr(pair.remote)
			network := "udp6"
			if local.Is4() {
				network = "udp4"
			}
			conn, err := net.ListenUDP(network, net.UDPAddrFromAddrPort(netip.AddrPortFrom(local, 0)))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			payload := []byte("photon-wintun-native-" + network)
			peer := netip.AddrPortFrom(remote, 43210)
			if _, err := conn.WriteToUDPAddrPort(payload, peer); err != nil {
				t.Fatal(err)
			}
			readCtx, stopRead := context.WithTimeout(ctx, 5*time.Second)
			defer stopRead()
			for {
				packet, err := device.Read(readCtx)
				if err != nil {
					t.Fatal(err)
				}
				reply := wintunUDPReply(packet, local, remote, payload)
				if reply == nil {
					continue
				} // skip Windows-generated IPv6 control traffic
				if err := device.Write(reply); err != nil {
					t.Fatal(err)
				}
				break
			}
			buffer := make([]byte, 256)
			n, source, err := conn.ReadFromUDPAddrPort(buffer)
			if err != nil {
				t.Fatal(err)
			}
			if source != peer || !bytes.Equal(buffer[:n], payload) {
				t.Fatalf("unexpected reply: %s %q", source, buffer[:n])
			}
			t.Logf("%s OS UDP -> Wintun.Read -> Wintun.Write -> OS UDP: %d bytes", network, n)
		})
	}
	device.Close()
	var routes *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(windows.AF_UNSPEC, &routes); err != nil {
		t.Fatal(err)
	}
	defer windows.FreeMibTable(unsafe.Pointer(routes))
	for _, row := range routes.Rows() {
		if row.InterfaceLuid == device.luid {
			t.Fatalf("route survived adapter close: %+v", row)
		}
	}
	var addresses *windows.MibUnicastIpAddressTable
	if err := windows.GetUnicastIpAddressTable(windows.AF_UNSPEC, &addresses); err != nil {
		t.Fatal(err)
	}
	defer windows.FreeMibTable(unsafe.Pointer(addresses))
	for _, row := range unsafe.Slice(&addresses.Table[0], addresses.NumEntries) {
		if row.InterfaceLuid == device.luid {
			t.Fatalf("address survived adapter close: %+v", row)
		}
	}
	t.Log("both address families have no adapter routes or addresses after Close")
}

// Return a checksummed UDP echo response only for the packet emitted by this
// test's socket; other traffic on the fresh adapter is ignored.
func wintunUDPReply(packet []byte, local, remote netip.Addr, payload []byte) []byte {
	header := 40
	if local.Is4() {
		header = 20
	}
	if len(packet) != header+8+len(payload) {
		return nil
	}
	if local.Is4() {
		if packet[0] != 0x45 || packet[9] != 17 || !bytes.Equal(packet[12:16], local.AsSlice()) || !bytes.Equal(packet[16:20], remote.AsSlice()) {
			return nil
		}
	} else {
		if packet[0]>>4 != 6 || packet[6] != 17 || !bytes.Equal(packet[8:24], local.AsSlice()) || !bytes.Equal(packet[24:40], remote.AsSlice()) {
			return nil
		}
	}
	if !bytes.Equal(packet[header+8:], payload) || binary.BigEndian.Uint16(packet[header+2:header+4]) != 43210 {
		return nil
	}
	reply := bytes.Clone(packet)
	if local.Is4() {
		copy(reply[12:16], remote.AsSlice())
		copy(reply[16:20], local.AsSlice())
		reply[10], reply[11] = 0, 0
		binary.BigEndian.PutUint16(reply[10:12], wintunTestChecksum(reply[:20]))
	} else {
		copy(reply[8:24], remote.AsSlice())
		copy(reply[24:40], local.AsSlice())
	}
	udp := reply[header:]
	udp[0], udp[1], udp[2], udp[3] = udp[2], udp[3], udp[0], udp[1]
	udp[6], udp[7] = 0, 0
	pseudo := append([]byte(nil), remote.AsSlice()...)
	pseudo = append(pseudo, local.AsSlice()...)
	if local.Is4() {
		pseudo = append(pseudo, 0, 17, byte(len(udp)>>8), byte(len(udp)))
	} else {
		pseudo = append(pseudo, 0, 0, byte(len(udp)>>8), byte(len(udp)), 0, 0, 0, 17)
	}
	checksum := wintunTestChecksum(append(pseudo, udp...))
	if checksum == 0 {
		checksum = 65535
	}
	binary.BigEndian.PutUint16(udp[6:8], checksum)
	return reply
}

func wintunTestChecksum(data []byte) uint16 {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) == 1 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	return ^uint16(sum)
}
