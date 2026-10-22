//go:build windows

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/HiggsNet/photon/internal/photonwindows"
	"golang.org/x/sys/windows"
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

// Synthetic public observations exercise real LISTBOX selection notifications;
// runtime/network authority and I/O are covered by their separate fixtures.
func TestDesktopNativeDiagnosticsPeerSelectionTracksCurrentSnapshot(t *testing.T) {
	if os.Getenv("PHOTON_WINDOWS_GUI_NATIVE") != "1" {
		t.Skip("set PHOTON_WINDOWS_GUI_NATIVE=1 for native diagnostics controls")
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
	guiShowWindow.Call(w.diagnostics, 5)
	w.diagnosticsView.paused = true
	guiSendMessage.Call(w.diagnostics, guiWMCommand, guiDiagnosticsPeersID, 0)
	var class [32]uint16
	guiUser32.NewProc("GetClassNameW").Call(w.controls[guiDiagnosticsPeerListID], uintptr(unsafe.Pointer(&class[0])), uintptr(len(class)))
	if !strings.EqualFold(windows.UTF16ToString(class[:]), "LISTBOX") {
		t.Fatal("peer navigation is not a native LISTBOX")
	}
	get := func(id int) string {
		text, err := guiControlText(w.controls[id])
		if err != nil {
			t.Fatal(err)
		}
		return text
	}
	listCount := func() int {
		count, _, _ := guiSendMessage.Call(w.controls[guiDiagnosticsPeerListID], 0x18b, 0, 0)
		return int(int32(count))
	}
	selected := func() int {
		index, _, _ := guiSendMessage.Call(w.controls[guiDiagnosticsPeerListID], 0x188, 0, 0)
		return int(int32(index))
	}
	sample := func(snapshot desktopSnapshot) {
		w.diagnosticsView.force = true
		w.renderDiagnostics(snapshot, desktopLogTail{}, nil, false)
	}
	now := time.Now()
	observation := &photonwindows.Observation{Running: true, ObservedAt: now, Peers: []photonwindows.PeerObservation{
		{Peer: "a.example.", PullState: "completed", PullAttempts: 1, PullSuccesses: 1},
		{Peer: "m.example.", PullState: "failed", PullAttempts: 9, PullFailures: 9},
		{Peer: "z.example.", PullState: "idle"},
	}}
	sample(desktopSnapshot{RuntimeState: "running", Observation: observation})
	if listCount() != 3 || selected() != 0 || w.diagnosticsView.peerID == "" || !strings.Contains(get(guiDiagnosticsTextID), "节点："+w.diagnosticsView.peerID) {
		t.Fatal("initial live peer list did not select its first real row")
	}
	index := -1
	for i, id := range w.diagnosticsView.peerIDs {
		if id == "m.example." {
			index = i
		}
	}
	if index < 0 {
		t.Fatal("expected peer absent from native sidebar")
	}
	guiSendMessage.Call(w.controls[guiDiagnosticsPeerListID], 0x186, uintptr(index), 0)
	guiSendMessage.Call(w.diagnostics, guiWMCommand, guiDiagnosticsPeerListID|1<<16, w.controls[guiDiagnosticsPeerListID])
	if w.diagnosticsView.peerID != "m.example." || !strings.Contains(get(guiDiagnosticsTextID), "节点：m.example.") || strings.Contains(get(guiDiagnosticsTextID), "节点：a.example.") {
		t.Fatal("native peer selection did not show only the selected peer")
	}
	observation = &photonwindows.Observation{Running: true, ObservedAt: now.Add(time.Second), Peers: []photonwindows.PeerObservation{
		{Peer: "z.example.", PullState: "idle"},
		{Peer: "m.example.", PullState: "completed", PullAttempts: 10, PullSuccesses: 1, PullFailures: 9},
		{Peer: "a.example.", PullState: "completed", PullAttempts: 1, PullSuccesses: 1},
	}}
	sample(desktopSnapshot{RuntimeState: "running", Observation: observation})
	if w.diagnosticsView.peerID != "m.example." || selected() < 0 || w.diagnosticsView.peerIDs[selected()] != "m.example." || !strings.Contains(get(guiDiagnosticsTextID), "尝试 10") {
		t.Fatal("peer refresh lost selection by identity or failed to refresh its counters")
	}
	observation = &photonwindows.Observation{Running: true, ObservedAt: now.Add(2 * time.Second), Peers: []photonwindows.PeerObservation{{Peer: "z.example.", PullState: "completed"}, {Peer: "a.example.", PullState: "idle"}}}
	sample(desktopSnapshot{RuntimeState: "running", Observation: observation})
	if selected() != 0 || w.diagnosticsView.peerID != w.diagnosticsView.peerIDs[0] || strings.Contains(get(guiDiagnosticsTextID), "m.example.") {
		t.Fatal("disappearing selected peer did not fall back to the first current row")
	}
	for _, snapshot := range []desktopSnapshot{{RuntimeState: "stopped", Observation: observation}, {RuntimeState: "running", Observation: observation, Error: "owned IPC unavailable"}, {RuntimeState: "running", Observation: &photonwindows.Observation{Running: true, ObservedAt: now.Add(3 * time.Second)}}} {
		sample(snapshot)
		if listCount() != 0 || selected() != -1 || w.diagnosticsView.peerID != "" || strings.Contains(get(guiDiagnosticsTextID), "a.example.") || strings.Contains(get(guiDiagnosticsTextID), "z.example.") {
			t.Fatal("inactive or empty public snapshot retained a peer row, selection or details")
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
	for _, id := range []int{guiDiagnosticsOverviewID, guiDiagnosticsGatewayID, guiDiagnosticsLogID, guiDiagnosticsPeersID, guiDiagnosticsDetailsID, guiDiagnosticsPeerListID, guiDiagnosticsTextID, guiDiagnosticsRefreshID, guiDiagnosticsPauseID, guiDiagnosticsCopyID, guiDiagnosticsMetadataID, guiDiagnosticsLogFilterID} {
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
	if w.diagnosticsView.page != guiDiagnosticsOverviewID || !strings.Contains(get(guiDiagnosticsTextID), "运行概览") || strings.HasPrefix(strings.TrimSpace(get(guiDiagnosticsTextID)), "{") || strings.Contains(get(guiDiagnosticsTextID), "public historical event") {
		t.Fatal("diagnostics did not open a readable overview distinct from raw JSON/logs")
	}
	click(guiDiagnosticsLogID)
	guiSendMessage.Call(w.controls[guiDiagnosticsLogFilterID], 0x14e, 3, 0) // CB_SETCURSEL: all log records.
	guiSendMessage.Call(w.diagnostics, guiWMCommand, guiDiagnosticsLogFilterID|1<<16, 0)
	awaitDesktopNativeResult(t, w)
	first := get(guiDiagnosticsTextID)
	if first != strings.ReplaceAll(logText, "\n", "\r\n") || !strings.Contains(get(guiDiagnosticsMetadataID), tail.Path) {
		t.Fatal("worker log view lost public file text, source or native line breaks")
	}
	firstVisibleLine, _, _ := guiSendMessage.Call(w.controls[guiDiagnosticsTextID], 0xce, 0, 0) // EM_GETFIRSTVISIBLELINE
	if firstVisibleLine == 0 {
		t.Fatal("log tail did not scroll to the newest records at the minimum window size")
	}
	filteredLog := "time=2026-10-16T01:00:00Z level=INFO msg=runtime_started event_id=101\n" +
		"time=2026-10-16T01:00:01Z level=INFO msg=gossip_started event_id=201\n" +
		"time=2026-10-16T01:00:02Z level=DEBUG msg=packet_trace event_id=999\n" +
		"time=2026-10-16T01:00:03Z level=WARN msg=fixture_warning event_id=999\n" +
		"time=2026-10-16T01:00:04Z level=ERROR msg=fixture_error event_id=999\n"
	if err := os.WriteFile(tail.Path, []byte(filteredLog), 0600); err != nil {
		t.Fatal(err)
	}
	click(guiDiagnosticsRefreshID)
	awaitDesktopNativeResult(t, w)
	selectFilter := func(index uintptr) {
		guiSendMessage.Call(w.controls[guiDiagnosticsLogFilterID], 0x14e, index, 0)
		guiSendMessage.Call(w.diagnostics, guiWMCommand, guiDiagnosticsLogFilterID|1<<16, 0)
		awaitDesktopNativeResult(t, w)
	}
	selectFilter(0)
	if shown := get(guiDiagnosticsTextID); !strings.Contains(shown, "msg=runtime_started") || strings.Contains(shown, "msg=packet_trace") || strings.Contains(shown, "msg=gossip_started") {
		t.Fatal("default connection log filter exposed unrelated debug/Gossip records or hid runtime startup")
	}
	selectFilter(1)
	if shown := get(guiDiagnosticsTextID); !strings.Contains(shown, "msg=fixture_warning") || !strings.Contains(shown, "msg=fixture_error") || strings.Contains(shown, "msg=runtime_started") {
		t.Fatal("warning/error native filter did not use real record levels")
	}
	selectFilter(2)
	if shown := get(guiDiagnosticsTextID); !strings.Contains(shown, "msg=gossip_started") || strings.Contains(shown, "msg=runtime_started") {
		t.Fatal("Gossip native filter did not isolate Gossip records")
	}
	selectFilter(3)
	if get(guiDiagnosticsTextID) != strings.ReplaceAll(filteredLog, "\n", "\r\n") {
		t.Fatal("all-log selection did not preserve the complete bounded raw tail")
	}
	if err := os.WriteFile(tail.Path, []byte(logText), 0600); err != nil {
		t.Fatal(err)
	}
	click(guiDiagnosticsRefreshID)
	awaitDesktopNativeResult(t, w)
	if get(guiDiagnosticsTextID) != first {
		t.Fatal("restored log source was not sampled by the existing worker")
	}
	firstVisibleLine, _, _ = guiSendMessage.Call(w.controls[guiDiagnosticsTextID], 0xce, 0, 0)
	if firstVisibleLine == 0 {
		t.Fatal("all-log filter stopped following the newest records")
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
	visible := func(id int) bool {
		value, _, _ := guiUser32.NewProc("IsWindowVisible").Call(w.controls[id])
		return value != 0
	}
	for _, page := range []int{guiDiagnosticsOverviewID, guiDiagnosticsGatewayID, guiDiagnosticsLogID, guiDiagnosticsPeersID, guiDiagnosticsDetailsID} {
		click(page)
		metadata := controlRect(guiDiagnosticsMetadataID)
		content := controlRect(guiDiagnosticsTextID)
		if metadata.Bottom > content.Top {
			t.Fatal("diagnostics metadata overlaps the readonly content")
		}
		if visible(guiDiagnosticsPeerListID) != (page == guiDiagnosticsPeersID) || visible(guiDiagnosticsPeerTitleID) != (page == guiDiagnosticsPeersID) || visible(guiDiagnosticsLogFilterID) != (page == guiDiagnosticsLogID) {
			t.Fatal("diagnostics leaked peer navigation or log filtering into another page")
		}
		if page == guiDiagnosticsPeersID {
			list, title := controlRect(guiDiagnosticsPeerListID), controlRect(guiDiagnosticsPeerTitleID)
			if list.Right > content.Left || title.Bottom > list.Top {
				t.Fatal("peer sidebar overlaps selected-peer details or its title")
			}
		}
		if page == guiDiagnosticsLogID {
			filter := controlRect(guiDiagnosticsLogFilterID)
			if metadata.Bottom > filter.Top || filter.Bottom > content.Top {
				t.Fatal("log filter overlaps metadata or the log viewport")
			}
		}
		var previous guiRect
		for column, id := range []int{guiDiagnosticsOverviewID, guiDiagnosticsGatewayID, guiDiagnosticsPeersID, guiDiagnosticsLogID, guiDiagnosticsDetailsID} {
			button := controlRect(id)
			if column > 0 && previous.Right > button.Left {
				t.Fatal("five-page navigation overlaps at minimum diagnostics size")
			}
			previous = button
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
