//go:build windows

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestDesktopNativeMainDetailsAndResizableRoutes(t *testing.T) {
	if os.Getenv("PHOTON_WINDOWS_GUI_NATIVE") != "1" {
		t.Skip("set PHOTON_WINDOWS_GUI_NATIVE=1 for native Win32 controls")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	b, err := newDesktopBackend(desktopOptions{ConfigPath: filepath.Join(t.TempDir(), "missing.yaml")})
	if err != nil {
		t.Fatal(err)
	}
	w, err := newDesktopWindow(b)
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
	text := func(id int) string {
		value, err := guiControlText(w.controls[id])
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	operation := "操作失败：MTU 无效，请修改后重新保存。"
	detail := strings.Repeat("reserve local control endpoint: Access is denied. ", 32)
	w.note(operation)
	w.render(desktopSnapshot{RuntimeState: "failed", Error: detail})
	if text(guiStatusID) != "连接：状态不可用" || !strings.HasPrefix(text(guiNoteID), operation) || !strings.Contains(text(guiNoteID), detail) {
		t.Fatal("long runtime diagnostics replaced the operation error or filled the title")
	}
	guiSendMessage.Call(w.controls[guiNoteID], 0xb1, 0, ^uintptr(0)) // EM_SETSEL: native text selection/copy remains available.
	w.render(desktopSnapshot{RuntimeState: "failed", Error: detail})
	var selectedStart, selectedEnd uint32
	guiSendMessage.Call(w.controls[guiNoteID], 0xb0, uintptr(unsafe.Pointer(&selectedStart)), uintptr(unsafe.Pointer(&selectedEnd)))
	encoded, err := windows.UTF16FromString(text(guiNoteID))
	if err != nil || selectedStart != 0 || selectedEnd != uint32(len(encoded)-1) {
		t.Fatal("unchanged status polling reset selection of the complete diagnostics")
	}
	w.render(desktopSnapshot{RuntimeState: "stopped"})
	if text(guiNoteID) != operation {
		t.Fatal("successful status polling replaced the last operation failure")
	}
	styleIndex := int32(-16) // GWL_STYLE is 32 bits on both Windows ABIs.
	style, _, _ := guiUser32.NewProc("GetWindowLongW").Call(w.controls[guiNoteID], uintptr(styleIndex))
	if style&0x0800 == 0 || style&0x0004 == 0 || style&0x00200000 == 0 {
		t.Fatal("complete diagnostics require a read-only multiline scrolling control")
	}
	var class [32]uint16
	guiUser32.NewProc("GetClassNameW").Call(w.controls[guiRoutesID], uintptr(unsafe.Pointer(&class[0])), uintptr(len(class)))
	if !strings.EqualFold(windows.UTF16ToString(class[:]), "EDIT") {
		t.Fatal("route control changed its public Win32 access contract")
	}
	rect := func(hwnd uintptr) guiRect {
		var bounds guiRect
		if ok, _, err := guiUser32.NewProc("GetWindowRect").Call(hwnd, uintptr(unsafe.Pointer(&bounds))); ok == 0 {
			t.Fatal(err)
		}
		return bounds
	}
	for _, pending := range []bool{false, true} {
		w.admission.Pending = pending
		guiMoveWindow.Call(w.hwnd, 0, 0, uintptr(w.guiScale(700)), uintptr(w.guiScale(620)), 0)
		w.layout()
		smallRoutes := rect(w.controls[guiRoutesID])
		summary, settings, note := rect(w.controls[guiConfigSummaryID]), rect(w.controls[guiSettingsID]), rect(w.controls[guiNoteID])
		if smallRoutes.Bottom <= smallRoutes.Top || summary.Bottom > settings.Top || settings.Bottom > note.Top || note.Bottom-note.Top < int32(w.guiScale(64)) {
			t.Fatalf("pending=%t: compact layout clips or overlaps: routes=%+v summary=%+v settings=%+v note=%+v", pending, smallRoutes, summary, settings, note)
		}
		guiMoveWindow.Call(w.hwnd, 0, 0, uintptr(w.guiScale(920)), uintptr(w.guiScale(760)), 0)
		w.layout()
		largeRoutes := rect(w.controls[guiRoutesID])
		if largeRoutes.Bottom-largeRoutes.Top <= smallRoutes.Bottom-smallRoutes.Top+int32(w.guiScale(100)) {
			t.Fatalf("pending=%t: route viewport did not use additional window height", pending)
		}
	}
}
