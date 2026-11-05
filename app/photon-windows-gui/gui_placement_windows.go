//go:build windows

package main

import "unsafe"

type guiMonitorInfo struct {
	Size          uint32
	Monitor, Work guiRect
	Flags         uint32
}

func guiFitWindowRect(bounds, work guiRect) guiRect {
	width := min(bounds.Right-bounds.Left, work.Right-work.Left)
	height := min(bounds.Bottom-bounds.Top, work.Bottom-work.Top)
	left := max(work.Left, min(bounds.Left, work.Right-width))
	top := max(work.Top, min(bounds.Top, work.Bottom-height))
	return guiRect{Left: left, Top: top, Right: left + width, Bottom: top + height}
}

// Initial Windows placement can extend under the taskbar on a small display.
// Use the nearest monitor's work area for each of the three top-level windows.
func guiFitInitialWindow(hwnd uintptr) error {
	monitor, _, err := guiUser32.NewProc("MonitorFromWindow").Call(hwnd, 2)
	if monitor == 0 {
		return guiCallError("MonitorFromWindow", err)
	}
	info := guiMonitorInfo{Size: uint32(unsafe.Sizeof(guiMonitorInfo{}))}
	if ok, _, err := guiUser32.NewProc("GetMonitorInfoW").Call(monitor, uintptr(unsafe.Pointer(&info))); ok == 0 {
		return guiCallError("GetMonitorInfo", err)
	}
	var bounds guiRect
	if ok, _, err := guiUser32.NewProc("GetWindowRect").Call(hwnd, uintptr(unsafe.Pointer(&bounds))); ok == 0 {
		return guiCallError("GetWindowRect", err)
	}
	fitted := guiFitWindowRect(bounds, info.Work)
	if fitted == bounds {
		return nil
	}
	if ok, _, err := guiUser32.NewProc("SetWindowPos").Call(hwnd, 0, uintptr(fitted.Left), uintptr(fitted.Top), uintptr(fitted.Right-fitted.Left), uintptr(fitted.Bottom-fitted.Top), 0x0014); ok == 0 {
		return guiCallError("SetWindowPos initial placement", err)
	}
	return nil
}
