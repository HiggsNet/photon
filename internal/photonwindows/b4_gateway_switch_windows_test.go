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
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestWindowsB4GatewaySwitch(t *testing.T) {
	dir := os.Getenv("PHOTON_WINDOWS_B4_SWITCH_CONFIG")
	if dir == "" {
		t.Skip("run windows-b4-gateway-switch-smoke.sh")
	}
	data, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal("invalid switch fixture config")
	}
	if len(config.Gateway.AllowedZones) != 2 || config.Gateway.AllowedZones[0] != "gateway-a.catofes." || config.Gateway.AllowedZones[1] != "gateway-b.catofes." {
		t.Fatal("requires ordered independent gateway pair")
	}
	config.State.Path = filepath.Join(dir, "windows.db")
	config.Wintun.AdapterName = fmt.Sprintf("PhotonSwitch-%d", os.Getpid())
	ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)
	defer cancel()
	authority := startB4AuthorityPeer(t, ctx, &config)
	log := &b4CrossLog{}
	daemon := NewDaemon(&config, slog.New(slog.NewTextHandler(log, &slog.HandlerOptions{Level: slog.LevelDebug})))
	counters := &b4DeviceCounters{}
	daemon.deviceFactory = counters.open
	done := make(chan error, 1)
	go func() { done <- daemon.Run(ctx) }()
	stopped := false
	luids := make(map[uint64]bool)
	defer func() {
		cancel()
		if !stopped {
			select {
			case err := <-done:
				if err != nil {
					t.Error(err)
				}
			case <-time.After(15 * time.Second):
				t.Error("switch daemon failed to join")
			}
		}
	}()
	t.Cleanup(func() {
		defer func() {
			if t.Failed() {
				t.Logf("platform: %s\n%s", counters, log.text())
			}
		}()
		assertOwnedDeviceGone(t, config.Wintun.AdapterName, 0)
		for luid := range luids {
			assertOwnedDeviceGone(t, config.Wintun.AdapterName, luid)
		}
	})
	observe := func() {
		t.Helper()
		tracked := counters.current()
		if tracked == nil || tracked.closed.Load() {
			t.Fatal("echo without live owned device")
		}
		device, ok := tracked.ownedPacketDevice.(*configuredPacketDevice)
		if !ok {
			t.Fatal("fixture replaced native platform device")
		}
		o, err := device.driver.Observe(ctx)
		if err != nil {
			t.Fatal(err)
		}
		luids[o.luid] = true
		for _, prefix := range config.Overlay.SplitRoutes {
			found := false
			for _, row := range o.routes {
				found = found || ipHelperRoutePrefix(row) == prefix
			}
			if !found {
				t.Fatalf("owned device lacks %s", prefix)
			}
		}
	}
	exchange := func(network, local, remote, phase string) error {
		conn, err := net.ListenUDP(network, net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr(local), 0)))
		if err != nil {
			return err
		}
		defer conn.Close()
		if err := conn.SetDeadline(time.Now().Add(600 * time.Millisecond)); err != nil {
			return err
		}
		peer := netip.AddrPortFrom(netip.MustParseAddr(remote), 19096)
		payload := []byte("photon-switch-" + phase + "-" + network)
		if _, err := conn.WriteToUDPAddrPort(payload, peer); err != nil {
			return err
		}
		buffer := make([]byte, 2048)
		n, from, err := conn.ReadFromUDPAddrPort(buffer)
		if err != nil {
			return err
		}
		if from != peer || !bytes.Equal(payload, buffer[:n]) {
			return fmt.Errorf("unexpected switch echo")
		}
		return nil
	}
	probe := func(network, local, remote, phase string) {
		t.Helper()
		var last error
		for deadline := time.Now().Add(35 * time.Second); ctx.Err() == nil && time.Now().Before(deadline); {
			select {
			case err := <-done:
				stopped = true
				t.Fatalf("daemon exited: %v", err)
			default:
			}
			last = exchange(network, local, remote, phase)
			if last == nil {
				observe()
				t.Logf("%s %s true Windows/Wintun/ESP/BIRD/Linux UDP roundtrip passed", phase, network)
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatalf("%s %s failed: %v", phase, network, last)
	}
	probe("udp4", "198.18.252.2", "198.18.252.1", "gateway-a")
	probe("udp6", "fd00:7068:b5::2", "fd00:7068:b5::1", "gateway-a")
	waitForWindowsState(t, time.Second, func() bool { return strings.Contains(log.text(), "msg=tunnel_ready_changed tunnel_ready=true") })
	if !strings.Contains(log.text(), "msg=tunnel_authenticated gateway=gateway-a.catofes.") {
		t.Fatal("business did not authenticate gateway A")
	}
	old := counters.current()
	opens := counters.opens.Load()
	before := log.text()
	// Both remote services remain alive. Only a current signed profile changes;
	// no local config edit, network failure or test-only packet verdict triggers it.
	authority.setGatewayEnabled(t, ctx, config.Gateway.AllowedZones[0], false)
	authority.waitGatewayEnabled(t, ctx, config.Gateway.AllowedZones[0], false)
	waitForWindowsState(t, 10*time.Second, func() bool { return old.closed.Load() })
	probe("udp4", "198.18.252.2", "198.18.252.3", "gateway-b")
	probe("udp6", "fd00:7068:b5::2", "fd00:7068:b5::3", "gateway-b")
	if counters.current() == old || counters.opens.Load() <= opens {
		t.Fatal("gateway switch retained old device lifetime")
	}
	waitForWindowsState(t, time.Second, func() bool {
		part := log.text()[len(before):]
		down := strings.Index(part, "msg=tunnel_ready_changed tunnel_ready=false")
		up := strings.Index(part, "msg=tunnel_ready_changed tunnel_ready=true")
		return down >= 0 && up > down && strings.Contains(part, "msg=tunnel_authenticated gateway=gateway-b.catofes.")
	})
	for range 3 {
		if exchange("udp4", "198.18.252.2", "198.18.252.1", "disabled-a") == nil {
			t.Fatal("old gateway IPv4 business still accepted")
		}
		if exchange("udp6", "fd00:7068:b5::2", "fd00:7068:b5::1", "disabled-a") == nil {
			t.Fatal("old gateway IPv6 business still accepted")
		}
	}
	probe("udp4", "198.18.252.2", "198.18.252.3", "gateway-b-stable")
	probe("udp6", "fd00:7068:b5::2", "fd00:7068:b5::3", "gateway-b-stable")
	if strings.Contains(log.text()[len(before):], "msg=tunnel_authenticated gateway=gateway-a.catofes.") {
		t.Fatal("disabled gateway A was reauthenticated")
	}
	cancel()
	select {
	case err := <-done:
		stopped = true
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("shutdown timeout")
	}
	if counters.opens.Load() != counters.closes.Load() {
		t.Fatalf("device leak: %s", counters)
	}
	// Verify every observed LUID has lost both families, even when Windows reused
	// one LUID for successive adapter instances.
	var table *windows.MibUnicastIpAddressTable
	if err := windows.GetUnicastIpAddressTable(windows.AF_UNSPEC, &table); err != nil {
		t.Fatal(err)
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	for _, row := range unsafe.Slice(&table.Table[0], table.NumEntries) {
		if luids[row.InterfaceLuid] {
			t.Fatal("switch adapter address survived stop")
		}
	}
	t.Logf("signed A-disable -> old device closed -> B authenticated -> dual-stack recovered; A remained denied; %s", counters)
}
