//go:build windows

package main

import (
	"errors"
	"fmt"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Deliberately independent of executable and configuration paths: unpacking an
// update must not create a second tray owner in the same interactive session.
const desktopInstanceName = `Local\Photon.Windows.Desktop.v1`
const guiActivateMessage = 0x8003

// The first handle keeps the named object alive; no thread owns the mutex.
// This avoids thread-affine ReleaseMutex and lets process death release it too.
func claimDesktopInstance(name string) (windows.Handle, bool, error) {
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, false, err
	}
	handle, err := windows.CreateMutexEx(nil, p, 0, windows.SYNCHRONIZE)
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		if handle != 0 {
			if closeErr := windows.CloseHandle(handle); closeErr != nil {
				return 0, false, closeErr
			}
		}
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("保护 Photon 单实例: %w", err)
	}
	return handle, true, nil
}

func existingDesktopWindow() uintptr {
	hwnd, _, _ := guiUser32.NewProc("FindWindowW").Call(uintptr(unsafe.Pointer(guiUTF16("PhotonWindowsDesktop"))), 0)
	return hwnd
}

func activateDesktopWindow(hwnd uintptr) {
	var pid uint32
	guiUser32.NewProc("GetWindowThreadProcessId").Call(hwnd, uintptr(unsafe.Pointer(&pid)))
	if pid != 0 {
		guiUser32.NewProc("AllowSetForegroundWindow").Call(uintptr(pid))
	}
	// The owner processes activation on its own window thread. The asynchronous
	// restore also supports earlier executables without this message handler,
	// and never waits on an unresponsive window procedure.
	guiPostMessage.Call(hwnd, guiActivateMessage, 0, 0)
	guiUser32.NewProc("ShowWindowAsync").Call(hwnd, 9)
	guiSetForegroundWindow.Call(hwnd)
}

func activateDesktopInstance(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if hwnd := existingDesktopWindow(); hwnd != 0 {
			activateDesktopWindow(hwnd)
			return nil
		}
		// Another process may still be between claiming the mutex and creating
		// its window. Never fall through to starting another backend on timeout.
		if !time.Now().Before(deadline) {
			return errors.New("Photon 已在运行或正在退出，请稍后从托盘打开，或退出已有程序后重试。")
		}
		time.Sleep(50 * time.Millisecond)
	}
}
