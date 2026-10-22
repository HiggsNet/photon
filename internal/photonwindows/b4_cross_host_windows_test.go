package photonwindows

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type b4CrossLog struct {
	mu sync.Mutex
	bytes.Buffer
}

func (b *b4CrossLog) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.Write(p)
}

func (b *b4CrossLog) text() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.String()
}

// This is the actual Daemon and the Windows TCP/IP stack, not a manually pumped
// tunnel or an allow-all packet verdict. The isolated fixture owns all trust.
func TestWindowsB4DaemonCrossHost(t *testing.T) {
	dir := os.Getenv("PHOTON_WINDOWS_B4_CONFIG")
	if dir == "" {
		t.Skip("run windows-b4-cross-host-smoke.sh on the Windows VM")
	}
	encoded, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var config Config
	if err := json.Unmarshal(encoded, &config); err != nil {
		t.Fatal("invalid isolated B4 config")
	}
	config.State.Path = filepath.Join(dir, "windows.db")
	config.Wintun.AdapterName = fmt.Sprintf("PhotonB4-%d", os.Getpid())
	ctx, cancel := context.WithTimeout(t.Context(), 180*time.Second)
	defer cancel()
	authority := startB4AuthorityPeer(t, ctx, &config)
	log := &b4CrossLog{}
	daemon := NewDaemon(&config, slog.New(slog.NewTextHandler(log, &slog.HandlerOptions{Level: slog.LevelDebug})))
	counters := &b4DeviceCounters{}
	daemon.deviceFactory = counters.open
	done := make(chan error, 1)
	go func() { done <- daemon.Run(ctx) }()
	stopped := false
	ownedLUIDs := make(map[uint64]bool)
	t.Cleanup(func() {
		defer func() {
			if t.Failed() {
				t.Logf("real platform device diagnostics: %s", counters)
				t.Log(log.text())
			}
		}()
		// Also discover an adapter created before the first successful probe.
		assertOwnedDeviceGone(t, config.Wintun.AdapterName, 0)
		for luid := range ownedLUIDs {
			assertOwnedDeviceGone(t, config.Wintun.AdapterName, luid)
			for _, family := range []uint16{windows.AF_INET, windows.AF_INET6} {
				row := ipHelperInterfaceRow{InterfaceLuid: luid, Family: family}
				if getIPHelperInterface(&row) == nil {
					t.Errorf("owned IP adapter %d family %d survived shutdown", luid, family)
				}
			}
		}
	})
	observeOwned := func() uint64 {
		t.Helper()
		var interfaces *windows.MibIfTable2
		if err := windows.GetIfTable2Ex(windows.MibIfTableNormalWithoutStatistics, &interfaces); err != nil {
			t.Fatal(err)
		}
		defer windows.FreeMibTable(unsafe.Pointer(interfaces))
		var active uint64
		for _, row := range unsafe.Slice(&interfaces.Table[0], interfaces.NumEntries) {
			if windows.UTF16ToString(row.Alias[:]) != config.Wintun.AdapterName {
				continue
			}
			ip := ipHelperInterfaceRow{InterfaceLuid: row.InterfaceLuid, Family: windows.AF_INET}
			if getIPHelperInterface(&ip) != nil {
				continue // NDIS may briefly retain a deleted adapter inventory row.
			}
			if active != 0 && active != row.InterfaceLuid {
				t.Fatal("multiple active adapters have the fixture's owned name")
			}
			active = row.InterfaceLuid
			ownedLUIDs[active] = true
		}
		if active == 0 {
			t.Fatal("successful echo has no active owned Wintun adapter")
		}
		var routes *windows.MibIpForwardTable2
		if err := windows.GetIpForwardTable2(windows.AF_UNSPEC, &routes); err != nil {
			t.Fatal(err)
		}
		defer windows.FreeMibTable(unsafe.Pointer(routes))
		for _, prefix := range config.Overlay.SplitRoutes {
			found := false
			for _, row := range routes.Rows() {
				if row.InterfaceLuid == active && ipHelperRoutePrefix(row) == prefix {
					found = true
				}
			}
			if !found {
				t.Fatalf("owned adapter %d lacks configured split route %s", active, prefix)
			}
		}
		return active
	}
	defer func() {
		cancel()
		if !stopped {
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("daemon stop: %v", err)
				}
			case <-time.After(15 * time.Second):
				t.Error("daemon failed to join")
			}
		}
	}()
	probe := func(network, local, remote, phase string) uint64 {
		t.Helper()
		deadline := time.Now().Add(35 * time.Second)
		var last error
		for ctx.Err() == nil && time.Now().Before(deadline) {
			select {
			case err := <-done:
				stopped = true
				t.Fatalf("daemon exited before %s: %v", phase, err)
			default:
			}
			conn, err := net.ListenUDP(network, net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr(local), 0)))
			if err == nil {
				_ = conn.SetDeadline(time.Now().Add(600 * time.Millisecond))
				peer := netip.AddrPortFrom(netip.MustParseAddr(remote), 19096)
				payload := []byte("photon-b4-" + phase + "-" + network)
				_, err = conn.WriteToUDPAddrPort(payload, peer)
				if err == nil {
					response := make([]byte, 2048)
					var n int
					var from netip.AddrPort
					n, from, err = conn.ReadFromUDPAddrPort(response)
					if err == nil && (from != peer || !bytes.Equal(response[:n], payload)) {
						err = fmt.Errorf("wrong echo source or payload")
					}
				}
				_ = conn.Close()
				if err == nil {
					active := observeOwned()
					t.Logf("%s %s: Windows UDP -> Wintun -> Babel/SADR -> ESP -> Linux UDP and reverse passed", phase, network)
					return active
				}
			}
			last = err
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatalf("%s %s timed out: %v", phase, network, last)
		return 0
	}
	initialLUID := probe("udp4", "198.18.253.2", "198.18.253.1", "initial")
	probe("udp6", "fd00:7068:b4::2", "fd00:7068:b4::1", "initial")
	waitForWindowsState(t, time.Second, func() bool { return strings.Contains(log.text(), "msg=tunnel_ready_changed tunnel_ready=true") })
	initialDevice := counters.current()
	initialOpens := counters.opens.Load()
	if initialDevice == nil || initialDevice.closed.Load() {
		t.Fatal("successful initial echo has no live tracked platform device")
	}
	beforeRebindLog := log.text()
	if err := daemon.Rebind(ctx); err != nil {
		t.Fatal("explicit rebind", err)
	}
	reboundLUID := probe("udp4", "198.18.253.2", "198.18.253.1", "rebound")
	if !initialDevice.closed.Load() || counters.opens.Load() <= initialOpens || counters.current() == initialDevice {
		t.Fatalf("explicit rebind did not close the old device and open a new lifetime: %s", counters)
	}
	probe("udp6", "fd00:7068:b4::2", "fd00:7068:b4::1", "rebound")
	waitForWindowsState(t, time.Second, func() bool {
		transition := log.text()[len(beforeRebindLog):]
		down := strings.Index(transition, "msg=tunnel_ready_changed tunnel_ready=false")
		up := strings.Index(transition, "msg=tunnel_ready_changed tunnel_ready=true")
		return down >= 0 && up > down && strings.Contains(transition, "msg=gossip_rebound")
	})
	t.Logf("rebind replaced device lifetime with ready false -> true; initial LUID=%d rebound LUID=%d (OS reuse allowed); %s", initialLUID, reboundLUID, counters)
	// A steady period exposes self-generated adapter notifications/rebind loops.
	time.Sleep(2 * time.Second)
	probe("udp4", "198.18.253.2", "198.18.253.1", "stable")
	// Hold actual OS sockets across signed revocation. The sidecar commits to
	// its own authority DB and uses production gossip to change this daemon;
	// the running Windows DB remains exclusively owned by Daemon throughout.
	type heldProbe struct {
		socket *net.UDPConn
		peer   netip.AddrPort
		family string
	}
	var held []heldProbe
	for _, pair := range []struct{ family, local, remote string }{{"udp4", "198.18.253.2", "198.18.253.1"}, {"udp6", "fd00:7068:b4::2", "fd00:7068:b4::1"}} {
		socket, err := net.ListenUDP(pair.family, net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr(pair.local), 0)))
		if err != nil {
			t.Fatal("bind revocation probe", err)
		}
		defer socket.Close()
		held = append(held, heldProbe{socket, netip.AddrPortFrom(netip.MustParseAddr(pair.remote), 19096), pair.family})
	}
	prefixes := []string{"198.18.253.2/32", "fd00:7068:b4::2/128"}
	authority.waitAssignments(t, ctx, prefixes, true)
	beforeRevocation := log.text()
	revokedDevice := counters.current()
	opensBeforeRevocation := counters.opens.Load()
	authority.setHostAssignments(t, ctx, prefixes, false)
	authority.waitAssignments(t, ctx, prefixes, false)
	waitForWindowsState(t, 10*time.Second, func() bool {
		return revokedDevice.closed.Load() && counters.opens.Load() == counters.closes.Load() && strings.Contains(log.text()[len(beforeRevocation):], "msg=tunnel_ready_changed tunnel_ready=false")
	})
	for luid := range ownedLUIDs {
		assertOwnedDeviceGone(t, config.Wintun.AdapterName, luid)
	}
	assertOwnedDeviceGone(t, config.Wintun.AdapterName, 0)
	for _, held := range held {
		if err := held.socket.SetDeadline(time.Now().Add(600 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		payload := []byte("photon-b4-must-not-pass-after-signed-revocation-" + held.family)
		if _, err := held.socket.WriteToUDPAddrPort(payload, held.peer); err == nil {
			buffer := make([]byte, 2048)
			if _, _, err := held.socket.ReadFromUDPAddrPort(buffer); err == nil {
				t.Fatal("business packet delivered after signed assignment revocation", held.family)
			}
		}
	}
	if counters.opens.Load() != opensBeforeRevocation {
		t.Fatalf("device reopened without local host authorization: %s", counters)
	}
	t.Log("signed dual-stack host assignment revocation converged over gossip; ready false, business stopped, owned adapter/address/routes removed")
	authority.setHostAssignments(t, ctx, prefixes, true)
	authority.waitAssignments(t, ctx, prefixes, true)
	probe("udp4", "198.18.253.2", "198.18.253.1", "authorization-restored")
	probe("udp6", "fd00:7068:b4::2", "fd00:7068:b4::1", "authorization-restored")
	if counters.current() == revokedDevice || counters.opens.Load() <= opensBeforeRevocation {
		t.Fatal("restoration did not create a fresh device lifetime")
	}
	waitForWindowsState(t, time.Second, func() bool {
		transition := log.text()[len(beforeRevocation):]
		down := strings.Index(transition, "msg=tunnel_ready_changed tunnel_ready=false")
		up := strings.Index(transition, "msg=tunnel_ready_changed tunnel_ready=true")
		return down >= 0 && up > down
	})
	t.Log("signed host assignment restoration converged over gossip; fresh platform lifetime and both business families recovered")
	cancel()
	select {
	case err := <-done:
		stopped = true
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("daemon shutdown did not finish")
	}
	if count := strings.Count(log.text(), "gossip_rebound"); count < 1 || count > 2 {
		t.Fatalf("unexpected rebind count %d", count)
	}
	if counters.opens.Load() != counters.closes.Load() {
		t.Fatalf("platform device lifetime leaked: %s", counters)
	}
	t.Logf("real platform device diagnostics: %s", counters)
	t.Log("full Windows daemon dual-stack flow, explicit rebind, signed authorization revoke/restore and shutdown cleanup passed")
}
