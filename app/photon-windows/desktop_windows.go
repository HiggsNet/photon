//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"unsafe"

	"github.com/HiggsNet/photon/internal/photonwindows"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
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

func (b *desktopBackend) Snapshot(ctx context.Context) desktopSnapshot {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := desktopSnapshot{ServiceState: "unknown"}
	fail := func(err error) desktopSnapshot { out.Error = err.Error(); out.Observation = nil; return out }
	manager, err := mgr.Connect()
	if err != nil {
		return fail(fmt.Errorf("connect SCM: %w", err))
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(b.options.ServiceName)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		out.ServiceState = "not-installed"
		return out
	}
	if err != nil {
		return fail(err)
	}
	defer service.Close()
	installed, err := service.Config()
	if err != nil {
		return fail(err)
	}
	if err := validateOwnedService(installed, b.options.ServiceName, b.options.ConfigPath); err != nil {
		return fail(err)
	}
	status, err := service.Query()
	if err != nil {
		return fail(err)
	}
	switch status.State {
	case svc.Running:
		out.ServiceState = "running"
	case svc.Stopped:
		out.ServiceState = "stopped"
	case svc.StartPending:
		out.ServiceState = "start-pending"
	case svc.StopPending:
		out.ServiceState = "stop-pending"
	case svc.Paused:
		out.ServiceState = "paused"
	default:
		out.ServiceState = "transitioning"
	}
	if status.State != svc.Running {
		if status.State == svc.Stopped {
			b.activeStatePath = ""
			b.activePID, b.activeCreated = 0, 0
			if status.Win32ExitCode != 0 || status.ServiceSpecificExitCode != 0 {
				return fail(fmt.Errorf("service stopped with failure: Win32=%d service=%d", status.Win32ExitCode, status.ServiceSpecificExitCode))
			}
		}
		return out
	}
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, status.ProcessId)
	if err != nil {
		return fail(fmt.Errorf("service process unavailable: %w", err))
	}
	defer windows.CloseHandle(process)
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(process, &created, &exited, &kernel, &user); err != nil {
		return fail(err)
	}
	creation := uint64(created.HighDateTime)<<32 | uint64(created.LowDateTime)
	if b.activeStatePath == "" || b.activePID != status.ProcessId || b.activeCreated != creation {
		text, _, err := desktopReadConfig(b.options.ConfigPath)
		if err != nil {
			return fail(err)
		}
		config, err := desktopParseConfig(string(text))
		if err != nil {
			return fail(err)
		}
		b.activeStatePath = config.State.Path
		b.activePID, b.activeCreated = status.ProcessId, creation
	}
	response, err := photonwindows.CallControlForProcess(ctx, b.activeStatePath, "status", status.ProcessId)
	if err != nil {
		return fail(fmt.Errorf("live status unavailable: %w", err))
	}
	observation, err := desktopObservation(response)
	if err != nil {
		return fail(err)
	}
	// A stop/restart concurrent with IPC must clear the previous generation.
	after, err := service.Query()
	if err != nil {
		return fail(err)
	}
	if after.State != svc.Running || after.ProcessId != status.ProcessId {
		return fail(errors.New("service changed while reading live status"))
	}
	out.Observation = observation
	return out
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
