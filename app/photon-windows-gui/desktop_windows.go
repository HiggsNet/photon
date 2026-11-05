//go:build windows

package main

import (
	"errors"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

func desktopOpenConfig(path string) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	// Opening the reparse point itself prevents a replaced link from redirecting
	// the editor to another file. File.Stat also captures the native file ID now.
	handle, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open config", Path: path, Err: err}
	}
	return os.NewFile(uintptr(handle), path), nil
}

func desktopPrepareReplacement(path string, file *os.File, _ os.FileMode) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		user, tokenErr := windows.GetCurrentProcessToken().GetTokenUser()
		if tokenErr != nil {
			return tokenErr
		}
		sd, err = windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + user.User.Sid.String() + ")")
	}
	if err != nil {
		return err
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	err = windows.SetNamedSecurityInfo(file.Name(), windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
	runtime.KeepAlive(sd)
	return err
}

var desktopReplaceFile = windows.NewLazySystemDLL("kernel32.dll").NewProc("ReplaceFileW")

func desktopReplaceConfig(temp, path string, exists bool) error {
	from, err := windows.UTF16PtrFromString(temp)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	if !exists {
		return windows.MoveFileEx(from, to, windows.MOVEFILE_WRITE_THROUGH)
	}
	// ReplaceFile preserves the replaced file's DACL and attributes. Do not set
	// IGNORE_MERGE_ERRORS: inability to retain its ACL must fail the save.
	result, _, callErr := desktopReplaceFile.Call(uintptr(unsafe.Pointer(to)), uintptr(unsafe.Pointer(from)), 0, 0, 0, 0)
	if result == 0 {
		return callErr
	}
	return nil
}
