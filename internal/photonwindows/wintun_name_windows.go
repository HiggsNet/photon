package photonwindows

import (
	"errors"
	"fmt"
	"strings"
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
		var cause error = windows.Errno(result)
		if result == uintptr(windows.ERROR_DUP_NAME) {
			// PnP can retain an alias briefly after process death, even though
			// its IP interface is gone. DUP_NAME alone is not proof of a live
			// foreign owner and must keep the normal transient retry behavior.
			foreign, observeErr := observeForeignAlias(name, row.InterfaceGuid)
			cause = errors.Join(cause, observeErr)
			if foreign {
				cause = errors.Join(errPacketDeviceConflict, cause)
			}
		}
		return fail(fmt.Errorf("assign owned adapter name %q: %w", name, cause))
	}
	return adapter, nil
}

func observeForeignAlias(name string, own windows.GUID) (bool, error) {
	var interfaces *windows.MibIfTable2
	if err := windows.GetIfTable2Ex(windows.MibIfTableNormalWithoutStatistics, &interfaces); err != nil {
		return false, fmt.Errorf("observe conflicting adapter: %w", err)
	}
	defer windows.FreeMibTable(unsafe.Pointer(interfaces))
	ipInterfaces, err := getIPHelperInterfaceTable()
	if err != nil {
		return false, fmt.Errorf("observe conflicting IP interface: %w", err)
	}
	defer windows.FreeMibTable(unsafe.Pointer(ipInterfaces))
	active := make(map[uint64]bool)
	for _, row := range unsafe.Slice(&ipInterfaces.Table[0], ipInterfaces.NumEntries) {
		active[row.InterfaceLuid] = true
	}
	return foreignAliasPresent(name, own, unsafe.Slice(&interfaces.Table[0], interfaces.NumEntries), active), nil
}

func foreignAliasPresent(name string, own windows.GUID, interfaces []windows.MibIfRow2, active map[uint64]bool) bool {
	for _, row := range interfaces {
		if row.InterfaceGuid != own && active[row.InterfaceLuid] && strings.EqualFold(windows.UTF16ToString(row.Alias[:]), name) {
			return true
		}
	}
	return false
}
