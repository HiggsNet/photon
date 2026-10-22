package photonwindows

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestWintunOwnedNameRejectsInvalidInput(t *testing.T) {
	for _, name := range []string{"", "bad\x00name", strings.Repeat("x", 128)} {
		if adapter, err := createWintunWithOwnedName(name, &windows.GUID{}); err == nil || adapter != nil {
			t.Fatalf("accepted invalid name %q", name)
		}
	}
}

// An independently owned, configured NIC is a sentinel: a conflicting create
// must neither adopt it nor move its alias to "name 1", as Wintun 0.14.1 does.
func TestWintunNativeForeignNamePreserved(t *testing.T) {
	if os.Getenv("PHOTON_IPHELPER_SMOKE") != "1" {
		t.Skip("requires isolated elevated Windows VM")
	}
	name := fmt.Sprintf("PhotonForeign-%d", os.Getpid())
	want := ipHelperTestIntent()
	foreign, err := openConfiguredPacketDevice(t.Context(), name, want.Addresses, want.Routes, want.MTU, want.Metric)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := foreign.Close(); err != nil {
			t.Error(err)
		}
	})
	owner := foreign.(*configuredPacketDevice)
	before := windows.MibIfRow2{InterfaceLuid: owner.device.luid}
	if err := windows.GetIfEntry2Ex(windows.MibIfEntryNormalWithoutStatistics, &before); err != nil {
		t.Fatal(err)
	}
	rejected, err := windows.GenerateGUID()
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := openWintun(context.Background(), strings.ToUpper(name), &rejected)
	if attempt != nil {
		attempt.Close()
		t.Fatal("adopted or renamed an existing adapter")
	}
	if !errors.Is(err, windows.ERROR_DUP_NAME) {
		t.Fatalf("name collision error: %v", err)
	}
	after := windows.MibIfRow2{InterfaceLuid: owner.device.luid}
	if err := windows.GetIfEntry2Ex(windows.MibIfEntryNormalWithoutStatistics, &after); err != nil {
		t.Fatal(err)
	}
	if before.InterfaceGuid != after.InterfaceGuid || windows.UTF16ToString(after.Alias[:]) != name {
		t.Fatal("foreign identity or name changed")
	}
	have, err := owner.driver.Observe(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	plan, err := planIPHelper(want, have)
	if err != nil || !plan.empty() {
		t.Fatalf("foreign address/route configuration changed: %v", err)
	}
	var table *windows.MibIfTable2
	if err := windows.GetIfTable2Ex(windows.MibIfTableNormalWithoutStatistics, &table); err != nil {
		t.Fatal(err)
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	for _, row := range unsafe.Slice(&table.Table[0], table.NumEntries) {
		if row.InterfaceGuid == rejected {
			assertOwnedDeviceGone(t, "", row.InterfaceLuid)
		}
	}
	ownedAdapterGUIDs.RLock()
	refs := ownedAdapterGUIDs.refs[rejected]
	ownedAdapterGUIDs.RUnlock()
	if refs != 0 {
		t.Fatal("failed create retained ownership registration")
	}
	if err := foreign.Close(); err != nil {
		t.Fatal(err)
	}
	assertOwnedDeviceGone(t, name, owner.device.luid)
	replacement, err := openWintun(t.Context(), name, nil)
	if err != nil {
		t.Fatal(err)
	}
	replacement.Close()
	assertOwnedDeviceGone(t, name, replacement.luid)
	t.Log("foreign alias, GUID, dual-stack addresses and split routes preserved; failed temporary adapter released; name reused only after foreign owner closed")
}
