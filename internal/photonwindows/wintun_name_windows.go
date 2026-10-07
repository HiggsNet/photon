package photonwindows

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
)

var setOwnedConnectionName = windows.NewLazySystemDLL("nci.dll").NewProc("NciSetConnectionName")

// Wintun 0.14.1 api/nci.h declares DWORD WINAPI(const GUID *, LPCWSTR).
// Unlike WintunCreateAdapter's NciSetAdapterName convenience loop (adapter.c),
// this primitive returns ERROR_DUP_NAME without renaming the conflicting NIC.
// https://github.com/WireGuard/wintun/blob/0.14.1/api/nci.h
func createWintunWithOwnedName(name string, guid *windows.GUID) (*wintun.Adapter, error) {
	target, err := windows.UTF16FromString(name)
	if err != nil {
		return nil, err
	}
	if len(target) < 2 || len(target) > 128 {
		return nil, errors.New("invalid Wintun adapter name length")
	}
	if err := setOwnedConnectionName.Find(); err != nil {
		return nil, fmt.Errorf("load owned adapter naming API: %w", err)
	}
	aliasID, err := windows.GenerateGUID()
	if err != nil {
		return nil, err
	}
	adapter, err := wintun.CreateAdapter("Photon-"+aliasID.String(), "Photon", guid)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*wintun.Adapter, error) {
		_ = adapter.Close() // WintunCloseAdapter is void; never adopt another adapter.
		return nil, err
	}
	row := windows.MibIfRow2{InterfaceLuid: adapter.LUID()}
	if err := windows.GetIfEntry2Ex(windows.MibIfEntryNormalWithoutStatistics, &row); err != nil {
		return fail(fmt.Errorf("observe newly created adapter: %w", err))
	}
	if row.InterfaceGuid != *guid {
		return fail(errors.New("created Wintun GUID does not match requested ownership"))
	}
	result, _, _ := setOwnedConnectionName.Call(uintptr(unsafe.Pointer(&row.InterfaceGuid)), uintptr(unsafe.Pointer(&target[0])))
	if result != 0 {
		return fail(fmt.Errorf("assign owned adapter name %q: %w", name, windows.Errno(result)))
	}
	return adapter, nil
}
