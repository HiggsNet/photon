//go:build linux

package babel

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/routing/bird"
)

// TestBIRDLeafInterop runs only inside windows-babel-interop-smoke.sh's isolated
// container. UDP carries the actual codec messages; reconstructed IPv6 frames
// adapt the socket API to the production ESP-facing Leaf.Receive API.
func TestBIRDLeafInterop(t *testing.T) {
	if os.Getenv("PHOTON_BABEL_INTEROP") != "1" {
		t.Skip("opt-in isolated BIRD fixture")
	}
	iface, err := net.InterfaceByName("leafph")
	if err != nil {
		t.Fatal(err)
	}
	socket, err := net.ListenUDP("udp6", &net.UDPAddr{Port: Port})
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	raw, err := socket.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var socketErr error
	err = raw.Control(func(fd uintptr) {
		group := &syscall.IPv6Mreq{Multiaddr: Multicast.As16(), Interface: uint32(iface.Index)}
		if e := syscall.SetsockoptIPv6Mreq(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_JOIN_GROUP, group); e != nil {
			socketErr = e
			return
		}
		socketErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, 1)
	})
	if err != nil || socketErr != nil {
		t.Fatal(err, socketErr)
	}
	leaf, err := NewLeaf(neighborLocal, neighborPeer, [8]byte{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0}, 100)
	if err != nil {
		t.Fatal(err)
	}
	local := []Origin{{Prefix: netip.MustParsePrefix("192.0.2.0/24")}, {Prefix: netip.MustParsePrefix("2001:db8:cafe::/64")}}
	send := func(messages []Message) {
		t.Helper()
		// One message per packet intentionally exercises independent parser context.
		for _, m := range messages {
			if m.Type == TLVUpdate && m.Metric != MetricInfinity && m.Prefix != local[0].Prefix && m.Prefix != local[1].Prefix {
				t.Fatal("transit advertisement", m)
			}
			payload, e := Encode([]Message{m})
			if e != nil {
				t.Fatal(e)
			}
			if _, e = socket.WriteToUDP(payload, &net.UDPAddr{IP: net.IP(neighborPeer.AsSlice()), Port: Port, Zone: iface.Name}); e != nil {
				t.Fatal(e)
			}
		}
	}
	changes, err := leaf.SetLocal(local)
	if err != nil {
		t.Fatal(err)
	}
	send(changes)
	birdc := func(command string) string {
		t.Helper()
		out, e := exec.Command(os.Getenv("BIRDC_BIN"), "-s", "/tmp/bird.ctl", command).CombinedOutput()
		if e != nil {
			t.Fatalf("birdc %s: %v: %s", command, e, out)
		}
		return string(out)
	}
	pump := func(until time.Time, ready func() bool) bool {
		t.Helper()
		buf := make([]byte, MaxPacket)
		for time.Now().Before(until) {
			send(leaf.Tick(time.Now()))
			socket.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, from, e := socket.ReadFromUDP(buf)
			if e == nil {
				if from.Port != Port {
					t.Fatal("unexpected sender", from)
				}
				source, ok := netip.AddrFromSlice(from.IP)
				if !ok {
					t.Fatal(from)
				}
				packet, e := BuildPacket(source, neighborLocal, buf[:n])
				if e != nil {
					t.Fatal(e)
				}
				replies, e := leaf.Receive(packet, time.Now(), allowCandidate)
				if e != nil {
					t.Fatalf("BIRD packet rejected: %v payload=%x", e, buf[:n])
				}
				send(replies)
			} else if ne, ok := e.(net.Error); !ok || !ne.Timeout() {
				t.Fatal(e)
			}
			if ready() {
				return true
			}
		}
		return false
	}
	var observedID [8]byte
	ready := pump(time.Now().Add(35*time.Second), func() bool {
		routes := leaf.Candidates(time.Now(), allowCandidate)
		found4, found6 := false, false
		for _, r := range routes {
			if r.NextHop != neighborPeer {
				t.Fatal("unexpected next hop", r)
			}
			if r.Destination.String() == "198.51.100.0/24" {
				found4 = true
				observedID = r.RouterID
			}
			if r.Destination.String() == "2001:db8:beef::/64" {
				found6 = true
			}
		}
		if !found4 || !found6 {
			return false
		}
		routesText := birdc("show route protocol leaf_interop all")
		return strings.Contains(routesText, "192.0.2.0/24") && strings.Contains(routesText, "2001:db8:cafe::/64")
	})
	if !ready {
		t.Fatalf("bidirectional convergence failed: candidates=%+v\n%s\n%s", leaf.Candidates(time.Now(), allowCandidate), birdc("show protocols all leaf_interop"), birdc("show route all"))
	}
	t.Logf("learned IPv4-via-IPv6 and IPv6 from BIRD router ID %x", observedID)
	t.Log("BIRD protocols:\n" + birdc("show protocols all leaf_interop"))
	t.Log("BIRD local routes:\n" + birdc("show route protocol leaf_interop all"))
	entries := birdc("show babel entries leaf_interop")
	idParts := make([]string, len(observedID))
	for i, b := range observedID {
		idParts[i] = fmt.Sprintf("%02x", b)
	}
	if !strings.Contains(entries, strings.Join(idParts, ":")) {
		t.Fatalf("BIRD control ID does not match full on-wire ID %x:\n%s", observedID, entries)
	}
	identity, err := bird.LocalBabelIdentity(entries, "leaf_interop", []netip.Prefix{
		netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("2001:db8:beef::/64"),
	})
	if err != nil || identity != fmt.Sprintf("%x", observedID) {
		t.Fatalf("production observer did not bind local BIRD identity: %q %v", identity, err)
	}
	t.Log("BIRD Babel entries:\n" + entries)
	// Explicit requests for learned destinations must produce only retractions.
	req := Message{Type: TLVRouteRequest, Prefix: netip.MustParsePrefix("198.51.100.0/24")}
	payload, _ := Encode([]Message{req})
	packet, _ := BuildPacket(neighborPeer, neighborLocal, payload)
	replies, err := leaf.Receive(packet, time.Now(), allowCandidate)
	if err != nil {
		t.Fatal(err)
	}
	if len(replies) != 1 || replies[0].Metric != MetricInfinity {
		t.Fatal("learned request exported", replies)
	}
	send(replies)
	changes, err = leaf.SetLocal(nil)
	if err != nil {
		t.Fatal(err)
	}
	send(changes)
	if !pump(time.Now().Add(10*time.Second), func() bool {
		out := birdc("show route protocol leaf_interop all")
		// BIRD retains unreachable tombstones until its hold timer expires.
		return !strings.Contains(out, "via fe80::1")
	}) {
		t.Fatal("BIRD retained retracted local origins")
	}
	t.Log("BIRD withdrew both local origins:\n" + birdc("show route protocol leaf_interop all"))
	// Keep the last candidate table but stop BIRD control traffic. Real elapsed
	// timers (rather than injected clock jumps) must make every route unusable.
	pid, err := strconv.Atoi(os.Getenv("BIRD_PID"))
	if err != nil {
		t.Fatal(err)
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Signal(syscall.SIGSTOP); err != nil {
		t.Fatal(err)
	}
	defer process.Signal(syscall.SIGCONT)
	expired := pump(time.Now().Add(16*time.Second), func() bool {
		return leaf.neighbor.Cost(time.Now()) == MetricInfinity && len(leaf.Candidates(time.Now(), allowCandidate)) == 0
	})
	if !expired {
		t.Fatal("neighbor loss did not stop route selection")
	}
	t.Log(fmt.Sprintf("neighbor expired, selected routes=%d", len(leaf.Candidates(time.Now(), allowCandidate))))
}
