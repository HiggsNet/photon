package photonwindows

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
)

func TestConfiguredPacketDeviceInputBoundaries(t *testing.T) {
	for _, mutate := range []func(*ipHelperIntent){
		func(w *ipHelperIntent) { w.Addresses = nil },
		func(w *ipHelperIntent) { w.Routes = nil },
		func(w *ipHelperIntent) { w.Addresses = []netip.Prefix{netip.MustParsePrefix("198.19.1.1/32")} },
		func(w *ipHelperIntent) { w.Addresses = w.Addresses[:1] },
		func(w *ipHelperIntent) { w.Routes = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")} },
		func(w *ipHelperIntent) { w.Metric = 0 },
	} {
		want := ipHelperTestIntent()
		mutate(&want)
		device, err := openConfiguredPacketDevice(context.Background(), "must-not-create", want.Addresses, want.Routes, want.MTU, want.Metric)
		if err == nil || device != nil {
			t.Fatal("invalid intent reached platform creation")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	want := ipHelperTestIntent()
	if _, err := openConfiguredPacketDevice(ctx, "must-not-create", want.Addresses, want.Routes, want.MTU, want.Metric); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled open: %v", err)
	}
}

func TestConfiguredPacketDeviceNativeLifecycle(t *testing.T) {
	if os.Getenv("PHOTON_IPHELPER_SMOKE") != "1" {
		t.Skip("requires elevated Windows VM and pinned adjacent wintun.dll")
	}
	name := fmt.Sprintf("PhotonOwnedTest-%d", os.Getpid())
	changes, stopWatching, err := watchNetworkChanges(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := stopWatching(); err != nil {
			t.Error(err)
		}
	})
	want := ipHelperTestIntent()
	for _, cancelFirst := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		raw, err := openConfiguredPacketDevice(ctx, name, want.Addresses, want.Routes, want.MTU, want.Metric)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		device := raw.(*configuredPacketDevice)
		t.Cleanup(func() { cancel(); _ = device.Close() })
		observation, err := device.driver.Observe(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range observation.addresses {
			if row.DadState != 4 {
				t.Fatalf("factory returned tentative address: %+v", row)
			}
		}
		for _, row := range observation.interfaces {
			if row.ForwardingEnabled != 0 {
				t.Fatal("owned interface has IP forwarding enabled")
			}
		}
		// A blocked device reader must be joined by both explicit stop and parent
		// cancellation. Discard OS-generated control packets until closure.
		reader := make(chan error, 1)
		go func() {
			for {
				if _, err := device.Read(context.Background()); err != nil {
					reader <- err
					return
				}
			}
		}()
		if cancelFirst {
			cancel()
		} else if err := device.Close(); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-reader:
			if !errors.Is(err, io.ErrClosedPipe) {
				t.Fatalf("closed reader: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("stop did not release packet reader")
		}
		if err := device.Close(); err != nil {
			t.Fatalf("cleanup: %v", err)
		}
		if err := device.Close(); err != nil {
			t.Fatalf("repeated cleanup: %v", err)
		}
		if err := device.Write([]byte{1}); !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("write after close: %v", err)
		}
		assertOwnedDeviceGone(t, name, device.device.luid)
		cancel()
		t.Logf("DAD-ready device reclaimed, blocked reader released, repeated close safe; parent_cancel=%v", cancelFirst)
	}
	// Cancellation during the asynchronous address initialization must leave no
	// adapter, even though its raw lifetime intentionally ignores parent cancel.
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	device, err := openConfiguredPacketDevice(ctx, name, want.Addresses, want.Routes, want.MTU, want.Metric)
	if device != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("initialization cancellation: %v %v", device, err)
	}
	assertOwnedDeviceGone(t, name, 0)
	select {
	case <-changes:
		t.Fatal("owned adapter create/configure/delete triggered underlay rebind")
	case <-time.After(250 * time.Millisecond):
	}
	// A separate temporary Wintun adapter is NOT ours. Its appearance must
	// still count as an underlay change; filtering every Wintun would hide VPNs.
	externalName := fmt.Sprintf("PhotonUnderlayTest-%d", os.Getpid())
	beforeExternal, beforeErr := underlaySnapshot()
	external, err := wintun.CreateAdapter(externalName, "PhotonTest", nil)
	if err != nil {
		t.Fatal(err)
	}
	externalLUID := external.LUID()
	externalSession, err := external.StartSession(1 << 20)
	if err != nil {
		_ = external.Close()
		t.Fatal(err)
	}
	externalClosed := false
	t.Cleanup(func() {
		if !externalClosed {
			externalSession.End()
			_ = external.Close()
		}
	})
	select {
	case <-changes:
		t.Log("owned creation window ignored; independent temporary interface change delivered")
	case <-time.After(2 * time.Second):
		afterExternal, afterErr := underlaySnapshot()
		ip := ipHelperInterfaceRow{InterfaceLuid: externalLUID, Family: windows.AF_INET}
		ipErr := getIPHelperInterface(&ip)
		ifrow := windows.MibIfRow2{InterfaceLuid: externalLUID}
		ifErr := windows.GetIfEntry2Ex(windows.MibIfTableNormalWithoutStatistics, &ifrow)
		t.Errorf("independent interface change swallowed; snapshot changed=%v errors=%v/%v ip=%v if=%v guid=%v", beforeExternal != afterExternal, beforeErr, afterErr, ipErr, ifErr, ifrow.InterfaceGuid)
	}
	externalSession.End()
	_ = external.Close()
	externalClosed = true
	assertOwnedDeviceGone(t, externalName, externalLUID)
}

func assertOwnedDeviceGone(t *testing.T, name string, luid uint64) {
	t.Helper()
	var interfaces *windows.MibIfTable2
	if err := windows.GetIfTable2Ex(windows.MibIfTableNormalWithoutStatistics, &interfaces); err != nil {
		t.Fatal(err)
	}
	defer windows.FreeMibTable(unsafe.Pointer(interfaces))
	removed := make(map[uint64]bool)
	if luid != 0 {
		removed[luid] = true
	}
	for _, row := range unsafe.Slice(&interfaces.Table[0], interfaces.NumEntries) {
		if windows.UTF16ToString(row.Alias[:]) == name {
			removed[row.InterfaceLuid] = true
			for _, family := range []uint16{windows.AF_INET, windows.AF_INET6} {
				ip := ipHelperInterfaceRow{InterfaceLuid: row.InterfaceLuid, Family: family}
				if err := getIPHelperInterface(&ip); err == nil {
					t.Fatal("owned IP interface survived stop")
				}
			}
		}
	}
	var routes *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(windows.AF_UNSPEC, &routes); err != nil {
		t.Fatal(err)
	}
	defer windows.FreeMibTable(unsafe.Pointer(routes))
	for _, row := range routes.Rows() {
		if removed[row.InterfaceLuid] {
			t.Fatal("owned route survived stop")
		}
	}
	var addresses *windows.MibUnicastIpAddressTable
	if err := windows.GetUnicastIpAddressTable(windows.AF_UNSPEC, &addresses); err != nil {
		t.Fatal(err)
	}
	defer windows.FreeMibTable(unsafe.Pointer(addresses))
	for _, row := range unsafe.Slice(&addresses.Table[0], addresses.NumEntries) {
		if removed[row.InterfaceLuid] {
			t.Fatal("owned address survived stop")
		}
	}
}
