//go:build windows

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
	"unsafe"
)

func TestDesktopNativeDuplicateActivationRestoresHiddenWindow(t *testing.T) {
	if os.Getenv("PHOTON_WINDOWS_GUI_NATIVE") != "1" {
		t.Skip("set PHOTON_WINDOWS_GUI_NATIVE=1 for native Win32 controls")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	config := filepath.Join(t.TempDir(), "missing.yaml")
	backend, err := newDesktopBackend(desktopOptions{ConfigPath: config})
	if err != nil {
		t.Fatal(err)
	}
	w, err := newDesktopWindow(backend)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := w.dispose(); err != nil {
			t.Error(err)
		}
		var message guiMessage
		guiUser32.NewProc("PeekMessageW").Call(uintptr(unsafe.Pointer(&message)), 0, 0x12, 0x12, 1)
	}()
	guiShowWindow.Call(w.hwnd, 0)
	activateDesktopWindow(w.hwnd)
	deadline := time.Now().Add(time.Second)
	for {
		var message guiMessage
		if present, _, _ := guiUser32.NewProc("PeekMessageW").Call(uintptr(unsafe.Pointer(&message)), w.hwnd, guiActivateMessage, guiActivateMessage, 1); present != 0 {
			guiDispatchMessage.Call(uintptr(unsafe.Pointer(&message)))
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("duplicate activation was not posted to the owner window")
		}
		time.Sleep(time.Millisecond)
	}
	if visible, _, _ := guiUser32.NewProc("IsWindowVisible").Call(w.hwnd); visible == 0 {
		t.Fatal("duplicate activation did not restore the existing window")
	}
	if backend.run != nil || len(w.requests) != 0 {
		t.Fatal("activation started a runtime or queued a backend operation")
	}
	if _, err := os.Stat(config); !os.IsNotExist(err) {
		t.Fatalf("activation touched missing configuration: %v", err)
	}
}
