//go:build windows

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestDesktopDrawItemABI(t *testing.T) {
	size, windowOffset, dcOffset, rectOffset, dataOffset := uintptr(48), uintptr(20), uintptr(24), uintptr(28), uintptr(44)
	if unsafe.Sizeof(uintptr(0)) == 8 {
		size, windowOffset, dcOffset, rectOffset, dataOffset = 64, 24, 32, 40, 56
	}
	if unsafe.Sizeof(guiDrawItem{}) != size || unsafe.Offsetof(guiDrawItem{}.Window) != windowOffset || unsafe.Offsetof(guiDrawItem{}.DC) != dcOffset || unsafe.Offsetof(guiDrawItem{}.Rect) != rectOffset || unsafe.Offsetof(guiDrawItem{}.Data) != dataOffset {
		t.Fatalf("DRAWITEMSTRUCT layout does not match native %d-bit ABI", unsafe.Sizeof(uintptr(0))*8)
	}
}

// These are real Win32 HWNDs, fonts and tab traversal, with deliberately
// synthetic WM_DPICHANGED messages. They do not change monitor scaling or
// establish visual acceptance on a physical 144/192-DPI desktop.
func TestDesktopNativeDPIAndTabNavigation(t *testing.T) {
	if os.Getenv("PHOTON_WINDOWS_GUI_NATIVE") != "1" {
		t.Skip("set PHOTON_WINDOWS_GUI_NATIVE=1 for native Win32 DPI/layout controls")
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
			t.Errorf("dispose native DPI fixture: %v", err)
		}
		var message guiMessage
		guiUser32.NewProc("PeekMessageW").Call(uintptr(unsafe.Pointer(&message)), 0, 0x12, 0x12, 1)
	}()
	// An SSH-launched test process can inherit STARTUPINFO/SW_HIDE, which
	// overrides its first ShowWindow call. Match production restore/show and
	// require visible ancestors before testing their keyboard navigation.
	for _, hwnd := range []uintptr{w.hwnd, w.settings} {
		guiShowWindow.Call(hwnd, 9)
		guiShowWindow.Call(hwnd, 5)
		shown, _, _ := guiUser32.NewProc("IsWindowVisible").Call(hwnd)
		if shown == 0 {
			style, _, _ := guiUser32.NewProc("GetWindowLongPtrW").Call(hwnd, ^uintptr(15))
			parent, _, _ := guiUser32.NewProc("GetParent").Call(hwnd)
			t.Fatalf("native fixture top-level window is hidden: hwnd=%x parent=%x style=%x main=%x settings=%x", hwnd, parent, style, w.hwnd, w.settings)
		}
	}
	for _, id := range []int{guiStartID, guiSaveID} {
		style, _, _ := guiUser32.NewProc("GetWindowLongPtrW").Call(w.controls[id], ^uintptr(15))
		if style&0xf != 0xb || style&0x10000 == 0 {
			t.Fatalf("primary button %d lost BS_OWNERDRAW or keyboard tab behavior: style=%x", id, style)
		}
	}
	actualDPI, _, _ := guiUser32.NewProc("GetDpiForWindow").Call(w.hwnd)
	t.Logf("OS HWND DPI=%d; injected handler DPI=96/144/192; monitor scale unchanged", actualDPI)
	defer func() {
		// Restore each owned window's DPI before disposal; no monitor or
		// process-wide setting was modified by the synthetic notifications.
		for _, hwnd := range []uintptr{w.hwnd, w.settings} {
			var rect guiRect
			guiUser32.NewProc("GetWindowRect").Call(hwnd, uintptr(unsafe.Pointer(&rect)))
			dpi, _, _ := guiUser32.NewProc("GetDpiForWindow").Call(hwnd)
			guiSendMessage.Call(hwnd, 0x02e0, dpi|dpi<<16, uintptr(unsafe.Pointer(&rect)))
		}
	}()

	rectInParent := func(child, parent uintptr) guiRect {
		var r guiRect
		if ok, _, err := guiUser32.NewProc("GetWindowRect").Call(child, uintptr(unsafe.Pointer(&r))); ok == 0 {
			t.Fatalf("GetWindowRect: %v", err)
		}
		guiUser32.NewProc("MapWindowPoints").Call(0, parent, uintptr(unsafe.Pointer(&r)), 2)
		return r
	}
	type nativeFont struct {
		height int32
		face   string
	}
	readFont := func(hwnd uintptr) nativeFont {
		font, _, _ := guiSendMessage.Call(hwnd, 0x31, 0, 0) // WM_GETFONT
		if font == 0 {
			t.Fatal("styled control has no owned font")
		}
		var description [92]byte // LOGFONTW has no pointer-sized fields.
		if size, _, err := guiGDI32.NewProc("GetObjectW").Call(font, uintptr(len(description)), uintptr(unsafe.Pointer(&description[0]))); size != uintptr(len(description)) {
			t.Fatalf("GetObjectW font: size=%d error=%v", size, err)
		}
		height := *(*int32)(unsafe.Pointer(&description[0]))
		if height < 0 {
			height = -height
		}
		face := windows.UTF16ToString((*[32]uint16)(unsafe.Pointer(&description[28]))[:])
		if face == "" {
			t.Fatal("styled control has no font face")
		}
		return nativeFont{height, face}
	}
	fontHeight := func(hwnd uintptr) int32 { return readFont(hwnd).height }
	checkSettings := func() {
		var client guiRect
		guiGetClientRect.Call(w.settings, uintptr(unsafe.Pointer(&client)))
		visible := make(map[uintptr]int)
		eligible := make(map[uintptr]int)
		for id, hwnd := range w.controls {
			parent, _, _ := guiUser32.NewProc("GetParent").Call(hwnd)
			shown, _, _ := guiUser32.NewProc("IsWindowVisible").Call(hwnd)
			if parent != w.settings || shown == 0 {
				continue
			}
			r := rectInParent(hwnd, w.settings)
			if r.Left < 0 || r.Top < 0 || r.Right > client.Right || r.Bottom > client.Bottom || r.Right <= r.Left || r.Bottom <= r.Top {
				t.Fatalf("page=%d dpi=%d control=%d outside client: %+v client=%+v", w.settingsPage, w.guiDPI(w.settings), id, r, client)
			}
			if fontHeight(hwnd) <= 0 {
				t.Fatalf("control %d has an empty native font", id)
			}
			// All interactive controls, including the editable ComboBox, must
			// be separate rectangles. Static help/labels are checked above.
			style, _, _ := guiUser32.NewProc("GetWindowLongPtrW").Call(hwnd, ^uintptr(15))
			if style&0x10000 == 0 { // WS_TABSTOP
				continue
			}
			visible[hwnd] = id
			enabled, _, _ := guiUser32.NewProc("IsWindowEnabled").Call(hwnd)
			if enabled != 0 {
				eligible[hwnd] = id
			}
		}
		for left, leftID := range visible {
			a := rectInParent(left, w.settings)
			for right, rightID := range visible {
				if leftID >= rightID {
					continue
				}
				b := rectInParent(right, w.settings)
				if a.Left < b.Right && b.Left < a.Right && a.Top < b.Bottom && b.Top < a.Bottom {
					t.Fatalf("page=%d controls %d/%d overlap: %+v %+v", w.settingsPage, leftID, rightID, a, b)
				}
			}
		}
		for id, label := range w.formLabels {
			shown, _, _ := guiUser32.NewProc("IsWindowVisible").Call(label)
			length, _, _ := guiGetWindowTextLength.Call(label)
			if shown == 0 || length == 0 {
				continue // The list-input row intentionally has no label.
			}
			r := rectInParent(label, w.settings)
			field := rectInParent(w.controls[id], w.settings)
			if r.Left < 0 || r.Top < 0 || r.Right > client.Right || r.Bottom > client.Bottom || r.Bottom > field.Top {
				t.Fatalf("page=%d label %d clipped or overlaps its field: %+v field=%+v", w.settingsPage, id, r, field)
			}
		}
		seen := make(map[uintptr]bool)
		current := uintptr(0)
		for range len(w.controls) + 1 {
			next, _, _ := guiUser32.NewProc("GetNextDlgTabItem").Call(w.settings, current, 0)
			if seen[next] {
				break
			}
			if _, ok := eligible[next]; !ok {
				id, _, _ := guiUser32.NewProc("GetDlgCtrlID").Call(next)
				parent, _, _ := guiUser32.NewProc("GetParent").Call(next)
				style, _, _ := guiUser32.NewProc("GetWindowLongPtrW").Call(next, ^uintptr(15))
				shown, _, _ := guiUser32.NewProc("IsWindowVisible").Call(next)
				enabled, _, _ := guiUser32.NewProc("IsWindowEnabled").Call(next)
				var class [256]uint16
				guiUser32.NewProc("GetClassNameW").Call(next, uintptr(unsafe.Pointer(&class[0])), uintptr(len(class)))
				t.Fatalf("page=%d dpi=%d tab traversal reached unknown/hidden/disabled/non-tab HWND=%x id=%d class=%q parent=%x settings=%x style=%x visible=%t enabled=%t previous=%x eligible=%v visibleTabControls=%v", w.settingsPage, w.guiDPI(w.settings), next, id, windows.UTF16ToString(class[:]), parent, w.settings, style, shown != 0, enabled != 0, current, eligible, visible)
			}
			seen[next] = true
			current = next
		}
		if len(seen) != len(eligible) {
			t.Fatalf("page=%d tab traversal misses controls: visited=%d eligible=%d", w.settingsPage, len(seen), len(eligible))
		}
		for _, id := range []int{guiBasicPageID, guiGatewayPageID, guiRoutePageID, guiAdvancedPageID, guiReloadID} {
			if !seen[w.controls[id]] {
				t.Fatalf("page=%d missing essential keyboard target %d", w.settingsPage, id)
			}
		}
	}
	fontsBefore := make(map[int]nativeFont)
	for _, id := range []int{guiRootFieldID, guiManagedFieldID, guiAllowedFieldID, guiStateFieldID, guiMTUFieldID, guiPageTitleID} {
		fontsBefore[id] = readFont(w.controls[id])
	}
	var lastHeight int32
	for _, dpi := range []uint32{96, 144, 192} {
		for _, top := range []struct {
			hwnd   uintptr
			height int32
		}{{w.hwnd, 620}, {w.settings, 700}} {
			suggested := guiRect{Left: 20, Top: 20, Right: 20 + int32(700*dpi/96), Bottom: 20 + top.height*int32(dpi)/96}
			guiSendMessage.Call(top.hwnd, 0x02e0, uintptr(dpi|dpi<<16), uintptr(unsafe.Pointer(&suggested)))
			if got := w.guiDPI(top.hwnd); got != dpi {
				t.Fatalf("WM_DPICHANGED did not update its top-level owner: got %d want %d", got, dpi)
			}
			limits := [5]guiPoint{}
			guiSendMessage.Call(top.hwnd, guiWMGetMinMaxInfo, 0, uintptr(unsafe.Pointer(&limits[0])))
			if limits[3] != (guiPoint{int32(700 * dpi / 96), top.height * int32(dpi) / 96}) {
				t.Fatalf("dpi=%d scaled minimum=%+v", dpi, limits[3])
			}
		}
		for _, page := range []int{guiBasicPageID, guiGatewayPageID, guiRoutePageID, guiAdvancedPageID} {
			w.showSettingsPage(page)
			for _, id := range []int{guiBasicPageID, guiGatewayPageID, guiRoutePageID, guiAdvancedPageID} {
				style, _, _ := guiUser32.NewProc("GetWindowLongPtrW").Call(w.controls[id], ^uintptr(15))
				want := uintptr(0)
				if id == page {
					want = 0xb
				}
				if style&0xf != want {
					t.Fatalf("page=%d navigation button %d has style=%x want type=%x", page, id, style, want)
				}
			}
			checkSettings()
		}
		for id, before := range fontsBefore {
			if got := readFont(w.controls[id]); got.face != before.face {
				t.Fatalf("dpi=%d changed control %d font role: face=%q want=%q", dpi, id, got.face, before.face)
			}
		}
		if fontHeight(w.controls[guiPageTitleID]) <= fontHeight(w.controls[guiMTUFieldID]) {
			t.Fatalf("dpi=%d lost title/body font hierarchy", dpi)
		}
		height := fontHeight(w.controls[guiManagedFieldID])
		if height <= lastHeight {
			t.Fatalf("native font did not grow with injected DPI: dpi=%d height=%d previous=%d", dpi, height, lastHeight)
		}
		lastHeight = height
	}
}
