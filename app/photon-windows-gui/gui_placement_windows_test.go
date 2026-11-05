//go:build windows

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"unsafe"
)

func TestGUIFitWindowRect(t *testing.T) {
	for _, test := range []struct {
		name               string
		bounds, work, want guiRect
	}{
		{"already visible", guiRect{100, 100, 800, 700}, guiRect{0, 0, 1280, 752}, guiRect{100, 100, 800, 700}},
		{"taskbar overlap", guiRect{112, 40, 1032, 800}, guiRect{0, 0, 1280, 752}, guiRect{112, 0, 1032, 752}},
		{"left monitor", guiRect{-1600, 400, -680, 1160}, guiRect{-1920, 0, 0, 1040}, guiRect{-1600, 280, -680, 1040}},
		{"taskbar on left", guiRect{0, 0, 920, 760}, guiRect{48, 0, 1280, 800}, guiRect{48, 0, 968, 760}},
		{"scaled window", guiRect{200, 120, 1580, 1260}, guiRect{0, 0, 1920, 1200}, guiRect{200, 60, 1580, 1200}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := guiFitWindowRect(test.bounds, test.work); got != test.want {
				t.Fatalf("got %+v, want %+v", got, test.want)
			}
		})
	}
}

func TestDesktopNativeInitialWindowsFitWorkArea(t *testing.T) {
	if os.Getenv("PHOTON_WINDOWS_GUI_NATIVE") != "1" {
		t.Skip("set PHOTON_WINDOWS_GUI_NATIVE=1 for native Win32 controls")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	backend, err := newDesktopBackend(desktopOptions{ConfigPath: filepath.Join(t.TempDir(), "missing.yaml")})
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
	for _, hwnd := range []uintptr{w.hwnd, w.settings, w.diagnostics} {
		monitor, _, _ := guiUser32.NewProc("MonitorFromWindow").Call(hwnd, 2)
		info := guiMonitorInfo{Size: uint32(unsafe.Sizeof(guiMonitorInfo{}))}
		if ok, _, err := guiUser32.NewProc("GetMonitorInfoW").Call(monitor, uintptr(unsafe.Pointer(&info))); ok == 0 {
			t.Fatal(err)
		}
		if info.Work.Right-info.Work.Left < int32(w.guiScale(700)) || info.Work.Bottom-info.Work.Top < int32(w.guiScale(700)) {
			t.Skip("work area is smaller than the settings window's minimum size")
		}
		var bounds guiRect
		if ok, _, err := guiUser32.NewProc("GetWindowRect").Call(hwnd, uintptr(unsafe.Pointer(&bounds))); ok == 0 {
			t.Fatal(err)
		}
		if bounds != guiFitWindowRect(bounds, info.Work) {
			t.Errorf("initial window outside work area: bounds=%+v work=%+v", bounds, info.Work)
		}
	}
}
