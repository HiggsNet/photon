//go:build windows

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unsafe"
)

func TestDiagnosticsTextBoundPreservesUTF16Boundaries(t *testing.T) {
	for _, test := range []struct {
		text      string
		limit     int
		want      string
		truncated bool
	}{
		{"a😀b", 3, "a😀", true}, {"a😀b", 2, "a", true}, {"😀", 2, "😀", false}, {"", 0, "", false}, {"x", 0, "", true},
	} {
		got, truncated := guiBoundDiagnosticsText(test.text, test.limit)
		if got != test.want || truncated != test.truncated {
			t.Fatalf("bound(%q,%d)=%q,%v", test.text, test.limit, got, truncated)
		}
	}
}

// Real native controls and the existing worker read an owned temporary log.
// This is not interactive desktop/tray or live networking acceptance.
func TestDesktopNativeDiagnosticsReadPauseRefreshAndOffline(t *testing.T) {
	if os.Getenv("PHOTON_WINDOWS_GUI_NATIVE") != "1" {
		t.Skip("set PHOTON_WINDOWS_GUI_NATIVE=1 for native diagnostics controls")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	b, err := newDesktopBackend(desktopOptions{ConfigPath: filepath.Join(t.TempDir(), "missing.yaml")})
	if err != nil {
		t.Fatal(err)
	}
	tail, err := b.LogTail()
	if err != nil || tail.Path == "" || !tail.Missing {
		t.Fatalf("new config log source: %+v, %v", tail, err)
	}
	if err := os.MkdirAll(filepath.Dir(tail.Path), 0700); err != nil {
		t.Fatal(err)
	}
	logText := strings.Repeat("public historical event\n", 120) + "latest public event\n"
	if err := os.WriteFile(tail.Path, []byte(logText), 0600); err != nil {
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
	if w.diagnostics == 0 {
		t.Fatal("diagnostics owned window was not created")
	}
	for _, id := range []int{guiDiagnosticsLogID, guiDiagnosticsPeersID, guiDiagnosticsDetailsID, guiDiagnosticsTextID, guiDiagnosticsRefreshID, guiDiagnosticsPauseID, guiDiagnosticsCopyID, guiDiagnosticsMetadataID} {
		child, _, _ := guiUser32.NewProc("GetDlgItem").Call(w.diagnostics, uintptr(id))
		if child == 0 || child != w.controls[id] {
			t.Fatalf("missing native diagnostics control %d", id)
		}
	}
	style, _, _ := guiUser32.NewProc("GetWindowLongPtrW").Call(w.controls[guiDiagnosticsTextID], ^uintptr(15))
	if style&0x0800 == 0 || style&0x0004 == 0 {
		t.Fatal("diagnostics content is not a native readonly multiline edit")
	}
	get := func(id int) string {
		text, err := guiControlText(w.controls[id])
		if err != nil {
			t.Fatal(err)
		}
		return text
	}
	click := func(id int) { guiSendMessage.Call(w.diagnostics, guiWMCommand, uintptr(id), 0) }
	w.guiMove(w.diagnostics, 40, 40, 700, 620)
	w.startWorker()
	w.openDiagnostics()
	awaitDesktopNativeResult(t, w)
	first := get(guiDiagnosticsTextID)
	if first != strings.ReplaceAll(logText, "\n", "\r\n") || !strings.Contains(get(guiDiagnosticsMetadataID), tail.Path) {
		t.Fatal("worker log view lost public file text, source or native line breaks")
	}
	firstVisibleLine, _, _ := guiSendMessage.Call(w.controls[guiDiagnosticsTextID], 0xce, 0, 0) // EM_GETFIRSTVISIBLELINE
	if firstVisibleLine == 0 {
		t.Fatal("log tail did not scroll to the newest records at the minimum window size")
	}
	click(guiDiagnosticsPauseID)
	if !w.diagnosticsView.paused || w.diagnosticsReadLogs() || get(guiDiagnosticsPauseID) != "继续刷新" {
		t.Fatal("pause did not stop this window's file sampling")
	}
	if err := os.WriteFile(tail.Path, []byte("changed while paused\n"), 0600); err != nil {
		t.Fatal(err)
	}
	w.submit(guiRequest{Action: "refresh"})
	awaitDesktopNativeResult(t, w)
	if get(guiDiagnosticsTextID) != first {
		t.Fatal("main refresh changed the paused diagnostics view")
	}
	if line, _, _ := guiSendMessage.Call(w.controls[guiDiagnosticsTextID], 0xce, 0, 0); line != firstVisibleLine {
		t.Fatal("main refresh moved the paused log view's scroll position")
	}
	// Even when another request is admitted, the manual request is retained
	// until an actual log-bearing result arrives through the fixed worker.
	w.submit(guiRequest{Action: "refresh"})
	click(guiDiagnosticsRefreshID)
	awaitDesktopNativeResult(t, w)
	if get(guiDiagnosticsTextID) != "changed while paused\r\n" || !w.diagnosticsView.paused || w.diagnosticsView.force {
		t.Fatal("manual refresh was lost while paused or busy")
	}
	click(guiDiagnosticsDetailsID)
	var details struct {
		RuntimeState string          `json:"runtime_state"`
		Available    bool            `json:"available"`
		Observation  json.RawMessage `json:"observation"`
	}
	if err := json.Unmarshal([]byte(get(guiDiagnosticsTextID)), &details); err != nil {
		t.Fatal(err)
	}
	if details.RuntimeState != "stopped" || details.Available || len(details.Observation) != 0 {
		t.Fatal("offline details claimed a live observation")
	}
	click(guiDiagnosticsPeersID)
	if strings.Contains(get(guiDiagnosticsTextID), "changed while paused") {
		t.Fatal("peer navigation retained log content")
	}
	click(guiDiagnosticsLogID)
	if get(guiDiagnosticsTextID) != "changed while paused\r\n" {
		t.Fatal("paused navigation lost its retained log view")
	}
	// Use the top-level window's actual DPI for native minimum-size geometry.
	// A synthetic map override would not establish an OS DPI transition.
	w.guiMove(w.diagnostics, 40, 40, 700, 620)
	var client guiRect
	guiGetClientRect.Call(w.diagnostics, uintptr(unsafe.Pointer(&client)))
	controlRect := func(id int) guiRect {
		var rect guiRect
		guiUser32.NewProc("GetWindowRect").Call(w.controls[id], uintptr(unsafe.Pointer(&rect)))
		guiUser32.NewProc("MapWindowPoints").Call(0, w.diagnostics, uintptr(unsafe.Pointer(&rect)), 2)
		if rect.Left < 0 || rect.Top < 0 || rect.Right > client.Right || rect.Bottom > client.Bottom || rect.Right <= rect.Left || rect.Bottom <= rect.Top {
			t.Fatalf("diagnostics control %d outside actual client at DPI %d: %+v / %+v", id, w.guiDPI(w.diagnostics), rect, client)
		}
		return rect
	}
	for _, page := range []int{guiDiagnosticsLogID, guiDiagnosticsPeersID, guiDiagnosticsDetailsID} {
		click(page)
		metadata := controlRect(guiDiagnosticsMetadataID)
		content := controlRect(guiDiagnosticsTextID)
		if metadata.Bottom > content.Top {
			t.Fatal("diagnostics metadata overlaps the readonly content")
		}
		for _, id := range []int{guiDiagnosticsRefreshID, guiDiagnosticsPauseID, guiDiagnosticsCopyID} {
			if footer := controlRect(id); content.Bottom > footer.Top {
				t.Fatal("diagnostics content overlaps footer action")
			}
		}
	}
	guiSendMessage.Call(w.diagnostics, guiWMClose, 0, 0)
	if w.diagnosticsVisible() || w.ctx.Err() != nil {
		t.Fatal("closing diagnostics destroyed the runtime owner")
	}
}
