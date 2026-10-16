//go:build windows

package main

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/HiggsNet/photon/internal/photonwindows"
	"github.com/HiggsNet/photon/pkg/core/gossip"
	"golang.org/x/sys/windows"
)

func TestDesktopWin32ABI(t *testing.T) {
	word := unsafe.Sizeof(uintptr(0))
	classSize, messageSize, notifySize, tipOffset := uintptr(48), uintptr(32), uintptr(956), uintptr(24)
	if word == 8 {
		classSize, messageSize, notifySize, tipOffset = 80, 48, 976, 40
	}
	if got := unsafe.Sizeof(guiWindowClass{}); got != classSize {
		t.Fatalf("WNDCLASSEXW size=%d want=%d", got, classSize)
	}
	if got := unsafe.Sizeof(guiMessage{}); got != messageSize {
		t.Fatalf("MSG size=%d want=%d", got, messageSize)
	}
	if got := unsafe.Sizeof(guiNotifyIcon{}); got != notifySize {
		t.Fatalf("NOTIFYICONDATAW size=%d want=%d", got, notifySize)
	}
	if got := unsafe.Offsetof(guiNotifyIcon{}.Tip); got != tipOffset {
		t.Fatalf("NOTIFYICONDATAW.szTip offset=%d want=%d", got, tipOffset)
	}
}

// This opts in to real user32 controls, including on a test-only session-0
// desktop. It does not establish Explorer/tray or interactive visual acceptance.
func TestDesktopNativeWindow(t *testing.T) {
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
		w.dispose()
		// WM_QUIT belongs to this test's message loop; do not leak it into a
		// later test that happens to reuse the same native thread.
		var message guiMessage
		guiUser32.NewProc("PeekMessageW").Call(uintptr(unsafe.Pointer(&message)), 0, 0x12, 0x12, 1)
	}()
	var processID uint32
	thread, _, _ := guiUser32.NewProc("GetWindowThreadProcessId").Call(w.hwnd, uintptr(unsafe.Pointer(&processID)))
	if uint32(thread) != windows.GetCurrentThreadId() || processID != uint32(os.Getpid()) {
		t.Fatal("window is not owned by the locked native thread/process")
	}
	// Exercise the native MINMAXINFO write, including its exact byte offset.
	// The owner must leave every field except ptMinTrackSize unchanged.
	limits := [5]guiPoint{{1, 2}, {3, 4}, {5, 6}, {7, 8}, {9, 10}}
	guiSendMessage.Call(w.hwnd, guiWMGetMinMaxInfo, 0, uintptr(unsafe.Pointer(&limits[0])))
	wantLimits := [5]guiPoint{{1, 2}, {3, 4}, {5, 6}, {700, 620}, {9, 10}}
	if limits != wantLimits {
		t.Fatalf("WM_GETMINMAXINFO changed wrong native fields: %v", limits)
	}
	// At the smallest supported window, a wrapped runtime error must fit
	// without covering the configuration summary or the settings button.
	guiMoveWindow.Call(w.hwnd, 0, 0, 700, 620, 0)
	windowRect := func(hwnd uintptr) guiRect {
		var rect guiRect
		if ok, _, err := guiUser32.NewProc("GetWindowRect").Call(hwnd, uintptr(unsafe.Pointer(&rect))); ok == 0 {
			t.Fatalf("GetWindowRect: %v", err)
		}
		return rect
	}
	for _, pending := range []bool{false, true} {
		w.admission.Pending = pending
		w.layout()
		summary := windowRect(w.controls[guiConfigSummaryID])
		settings := windowRect(w.controls[guiSettingsID])
		note := windowRect(w.controls[guiNoteID])
		if summary.Bottom-summary.Top < 64 || note.Bottom-note.Top < 64 || summary.Bottom > settings.Top || settings.Bottom > note.Top {
			t.Fatalf("pending=%t: smallest window clips summary/footer or overlaps controls: summary=%+v settings=%+v note=%+v", pending, summary, settings, note)
		}
	}
	w.admission.Pending = false
	w.layout()
	for _, id := range []int{guiStatusID, guiRuntimeID, guiGatewayID, guiRoutesID, guiNoteID, guiAdmissionID, guiJoinRequestID, guiStartID, guiStopID, guiRestartID, guiSaveID, guiReloadID, guiCopyRequestID} {
		parent := w.hwnd
		if id == guiSaveID || id == guiReloadID {
			parent = w.settings
		}
		hwnd, _, _ := guiUser32.NewProc("GetDlgItem").Call(parent, uintptr(id))
		if hwnd == 0 || hwnd != w.controls[id] {
			t.Fatalf("missing native child control %d", id)
		}
	}
	for _, parent := range []uintptr{w.hwnd, w.settings} {
		if raw, _, _ := guiUser32.NewProc("GetDlgItem").Call(parent, 1005); raw != 0 {
			t.Fatal("raw YAML editor still exists")
		}
	}
	if removed, _, _ := guiUser32.NewProc("GetDlgItem").Call(w.hwnd, 1101); removed != 0 {
		t.Fatal("service installation control still exists")
	}
	text := func(id int) string {
		size, _, _ := guiGetWindowTextLength.Call(w.controls[id])
		buffer := make([]uint16, int(size)+1)
		guiGetWindowText.Call(w.controls[id], uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)))
		return windows.UTF16ToString(buffer)
	}
	observation := &photonwindows.Observation{Running: true, TunnelReady: true, IKE: photonwindows.IKEObservation{Live: true, Gateway: "gateway.example."}, Babel: photonwindows.BabelObservation{Live: true, Routes: []photonwindows.RouteObservation{{Prefix: netip.MustParsePrefix("198.18.253.1/32"), Origin: "gateway.example.", Metric: 100}}}}
	joinRequest, request := desktopTestJoinRequest(t)
	observation.Admission = gossip.AdmissionDiagnosis{Pending: true, ManagedZone: joinRequest.Zone, Reason: gossip.AdmissionReasonMissingDelegation, JoinRequestB64: request}
	w.render(desktopSnapshot{RuntimeState: "running", Observation: observation})
	if text(guiJoinRequestID) != request || !strings.Contains(text(guiStatusID), "待授权") || strings.Contains(text(guiGatewayID), "gateway.example.") || strings.Contains(text(guiRoutesID), "198.18.253.1") {
		t.Fatal("pending admission retained connected state or truncated the public request")
	}
	if enabled, _, _ := guiUser32.NewProc("IsWindowEnabled").Call(w.controls[guiCopyRequestID]); enabled == 0 {
		t.Fatal("pending request copy button is disabled")
	}
	observation.Admission.Reason = gossip.AdmissionReasonDelegationKeyMismatch
	w.render(desktopSnapshot{RuntimeState: "running", Observation: observation})
	if !strings.Contains(text(guiAdmissionID), "本机公钥不匹配") || text(guiJoinRequestID) != request {
		t.Fatal("delegation key mismatch did not preserve the current complete request")
	}
	for _, unavailable := range []desktopSnapshot{{RuntimeState: "stopped", Observation: observation}, {RuntimeState: "running", Observation: observation, Error: "IPC disconnected"}} {
		w.render(unavailable)
		if text(guiJoinRequestID) != "" || w.admission.Request != "" {
			t.Fatal("unavailable observation retained admission request")
		}
		if enabled, _, _ := guiUser32.NewProc("IsWindowEnabled").Call(w.controls[guiCopyRequestID]); enabled != 0 {
			t.Fatal("unavailable admission request remains copyable")
		}
	}
	observation.Admission.Pending = false
	observation.Admission.Reason = gossip.AdmissionReasonAdopted
	// A leftover wire field must not preserve an old identity after adoption.
	observation.TunnelReady = false
	w.render(desktopSnapshot{RuntimeState: "running", Observation: observation})
	if text(guiJoinRequestID) != "" || !strings.Contains(text(guiAdmissionID), "已入网") || !strings.Contains(text(guiStatusID), "等待数据隧道") {
		t.Fatal("adopted state retained pending request or claimed a ready tunnel")
	}
	observation.Readiness = photonwindows.ReadinessObservation{Stage: photonwindows.ReadinessStageAddressAssignment, Reason: "current configuration has no usable signed host allocation"}
	observation.IKE.ChildLive = true
	observation.Babel.Live = true
	observation.Babel.Local = netip.MustParseAddr("fe80::1")
	observation.Babel.Neighbor = netip.MustParseAddr("fe80::2")
	w.render(desktopSnapshot{RuntimeState: "running", Observation: observation})
	if text(guiStatusID) != "连接：已入网，等待业务IP分配" || !strings.Contains(text(guiNoteID), observation.Readiness.Reason) || strings.Contains(text(guiNoteID), "198.18.253.2/32") || !strings.Contains(text(guiAdmissionID), "隧道链路 IPv6：fe80::1") || !strings.Contains(text(guiNoteID), "实时对端链路 IPv6：fe80::2") || text(guiJoinRequestID) != "" {
		t.Fatal("canonical missing business IP diagnosis was not displayed or retained an old request/address")
	}
	w.guiMove(w.hwnd, 0, 0, 700, 620)
	var admissionRect, routeLabelRect guiRect
	guiUser32.NewProc("GetWindowRect").Call(w.controls[guiAdmissionID], uintptr(unsafe.Pointer(&admissionRect)))
	guiUser32.NewProc("GetWindowRect").Call(w.labels[0], uintptr(unsafe.Pointer(&routeLabelRect)))
	if strings.Count(text(guiAdmissionID), "\r\n") != 2 || admissionRect.Bottom-admissionRect.Top < int32(guiAtDPI(66, w.guiDPI(w.hwnd))) || admissionRect.Bottom > routeLabelRect.Top {
		t.Fatal("minimum window clipped the three address/admission lines or overlapped the route section")
	}
	observation.Readiness.Stage = photonwindows.ReadinessStageAddressAnnouncement
	w.render(desktopSnapshot{RuntimeState: "running", Observation: observation})
	if text(guiStatusID) != "连接：已入网，等待地址同步" || !strings.Contains(text(guiNoteID), "已有当前配置可用") {
		t.Fatal("authorized allocation and its address announcement were conflated")
	}
	observation.Readiness = photonwindows.ReadinessObservation{}
	observation.TunnelReady = true
	observation.Wintun = photonwindows.WintunObservation{Configured: true, Addresses: []netip.Prefix{netip.MustParsePrefix("198.18.253.2/32"), netip.MustParsePrefix("fd00:7068:b4::2/128")}}
	w.render(desktopSnapshot{RuntimeState: "running", Observation: observation})
	if !strings.Contains(text(guiStatusID), "已连接") || !strings.Contains(text(guiGatewayID), "gateway.example.") || !strings.Contains(text(guiRoutesID), "metric 100") || !strings.Contains(text(guiAdmissionID), "接口业务 IP：198.18.253.2/32") || !strings.Contains(text(guiNoteID), "fd00:7068:b4::2/128") {
		t.Fatal("live status/route did not render")
	}
	// Multiline EDIT intentionally does not send EN_CHANGE for WM_SETTEXT.
	// Replace the selected text as an actual user edit to exercise the native
	// notification rather than depending on WM_SETTEXT's different contract.
	guiSendMessage.Call(w.controls[guiManagedFieldID], 0x00b1, 0, ^uintptr(0))                                       // EM_SETSEL
	guiSendMessage.Call(w.controls[guiManagedFieldID], 0x00c2, 1, uintptr(unsafe.Pointer(guiUTF16("new.example.")))) // EM_REPLACESEL
	revision := w.editRevision
	if !w.dirty {
		t.Fatal("native EN_CHANGE did not mark edits")
	}
	w.render(desktopSnapshot{RuntimeState: "stopped", Error: "IPC disconnected"})
	if strings.Contains(text(guiGatewayID), "gateway.example.") || strings.Contains(text(guiRoutesID), "198.18.253.1") || strings.Contains(text(guiStatusID), "已连接") {
		t.Fatal("offline result retained stale live status")
	}
	if strings.Contains(text(guiAdmissionID), "198.18.253.2") || strings.Contains(text(guiNoteID), "198.18.253.2") || strings.Contains(text(guiAdmissionID), "fe80::1") || strings.Contains(text(guiNoteID), "fe80::2") {
		t.Fatal("offline result retained actual business IPs")
	}
	if text(guiManagedFieldID) != "new.example." {
		t.Fatal("status polling replaced unsaved form")
	}
	w.applyResult(guiResult{Action: "load", Form: desktopConfigForm{ManagedZone: "old.example."}, EditRevision: revision - 1, Snapshot: desktopSnapshot{RuntimeState: "stopped"}})
	if text(guiManagedFieldID) != "new.example." || !w.dirty {
		t.Fatal("asynchronous load overwrote newer edits")
	}
	// A failed cleanup must leave a visible, usable window and preserve edits;
	// it must not turn a close error into an apparent successful exit.
	w.quitting, w.quitSubmitted = true, true
	w.applyResult(guiResult{Action: "quit", Err: errors.New("cleanup incomplete")})
	if _, exists := guiWindows.Load(w.hwnd); !exists || w.quitting || w.quitSubmitted || !strings.Contains(text(guiNoteID), "停止连接失败") || text(guiManagedFieldID) != "new.example." {
		t.Fatal("failed runtime cleanup destroyed the window or discarded edits")
	}
	// One fixed worker and one queued request remain bounded under repeated
	// timer/button submissions. No connection is started by this test.
	w.startWorker()
	w.submit(guiRequest{Action: "refresh"})
	for i := 0; i < 100; i++ {
		w.submit(guiRequest{Action: "refresh"})
	}
	if len(w.requests) > 1 || !w.busy {
		t.Fatal("request queue/busy guard is not bounded")
	}
	deadline := time.Now().Add(10 * time.Second)
	for w.busy && time.Now().Before(deadline) {
		var message guiMessage
		if exists, _, _ := guiUser32.NewProc("PeekMessageW").Call(uintptr(unsafe.Pointer(&message)), w.hwnd, guiResultMessage, guiResultMessage, 1); exists != 0 {
			guiDispatchMessage.Call(uintptr(unsafe.Pointer(&message)))
		} else {
			time.Sleep(5 * time.Millisecond)
		}
	}
	if w.busy {
		t.Fatal("bounded native worker did not return a result")
	}
	if got := text(guiManagedFieldID); got != "new.example." {
		t.Fatalf("worker status replaced edits: %q", got)
	}
	// An Exit during an admitted task must wait for its result, then stop/join
	// through the same worker instead of dropping the user's exit request.
	w.dirty = false
	w.tray = false
	if timer, _, _ := guiSetTimer.Call(w.hwnd, 1, 20, 0); timer == 0 {
		t.Fatal("native fallback timer unavailable")
	}
	w.submit(guiRequest{Action: "refresh"})
	guiSendMessage.Call(w.hwnd, guiWMClose, 0, 0)
	if !w.quitting || w.quitSubmitted {
		t.Fatal("busy Close did not defer owned runtime cleanup")
	}
	// Deliberately discard WM_APP instead of dispatching it. Both the
	// in-flight refresh and the following Close must finish solely through
	// real timer messages, exercising the notification-failure recovery path.
	timerMessages := 0
	deadline = time.Now().Add(5 * time.Second)
	for w.busy && time.Now().Before(deadline) {
		var message guiMessage
		guiUser32.NewProc("PeekMessageW").Call(uintptr(unsafe.Pointer(&message)), w.hwnd, guiResultMessage, guiResultMessage, 1)
		if exists, _, _ := guiUser32.NewProc("PeekMessageW").Call(uintptr(unsafe.Pointer(&message)), w.hwnd, guiWMTimer, guiWMTimer, 1); exists != 0 {
			timerMessages++
			guiDispatchMessage.Call(uintptr(unsafe.Pointer(&message)))
		} else {
			time.Sleep(5 * time.Millisecond)
		}
	}
	if w.busy || timerMessages < 2 {
		t.Fatal("exit lost its result-drain timer after missing WM_APP")
	}
	if _, exists := guiWindows.Load(w.hwnd); exists {
		t.Fatal("queued Close without tray retained a hidden owner")
	}
	if w.ctx.Err() == nil {
		t.Fatal("window destruction did not cancel its worker")
	}
}

func TestDesktopClipboardBounds(t *testing.T) {
	// All failures precede OpenClipboard, preserving the user's clipboard.
	for _, request := range []string{"", "request\x00tail", strings.Repeat("a", desktopJoinRequestLimit+1)} {
		if err := guiCopyPublicRequest(0, request); err == nil {
			t.Fatal("accepted empty, embedded-NUL or oversized clipboard request")
		}
	}
}

func awaitDesktopNativeResult(t *testing.T, w *desktopWindow) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for w.busy && time.Now().Before(deadline) {
		var message guiMessage
		if exists, _, _ := guiUser32.NewProc("PeekMessageW").Call(uintptr(unsafe.Pointer(&message)), w.hwnd, guiResultMessage, guiResultMessage, 1); exists != 0 {
			guiDispatchMessage.Call(uintptr(unsafe.Pointer(&message)))
		} else {
			time.Sleep(5 * time.Millisecond)
		}
	}
	if w.busy {
		t.Fatal("native form worker did not finish")
	}
}

func TestDesktopNativeMissingFormCreatesConfigThroughWorker(t *testing.T) {
	if os.Getenv("PHOTON_WINDOWS_GUI_NATIVE") != "1" {
		t.Skip("set PHOTON_WINDOWS_GUI_NATIVE=1 for native Win32 forms")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	path := filepath.Join(t.TempDir(), "first-setup.yaml")
	backend, err := newDesktopBackend(desktopOptions{ConfigPath: path})
	if err != nil {
		t.Fatal(err)
	}
	w, err := newDesktopWindow(backend)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		w.dispose()
		var message guiMessage
		guiUser32.NewProc("PeekMessageW").Call(uintptr(unsafe.Pointer(&message)), 0, 0x12, 0x12, 1)
	}()
	w.startWorker()
	w.submit(guiRequest{Action: "load"})
	awaitDesktopNativeResult(t, w)
	get := func(id int) string {
		text, err := guiControlText(w.controls[id])
		if err != nil {
			t.Fatal(err)
		}
		return text
	}
	edit := func(id int, text string) {
		guiSendMessage.Call(w.controls[id], 0xb1, 0, ^uintptr(0))
		guiSendMessage.Call(w.controls[id], 0xc2, 1, uintptr(unsafe.Pointer(guiUTF16(text))))
	}
	click := func(id int) { guiSendMessage.Call(w.settings, guiWMCommand, uintptr(id), 0) }
	if !w.formLoaded || !w.newConfig || w.dirty || get(guiRootFieldID) != "" || get(guiManagedFieldID) != "" || !filepath.IsAbs(get(guiStateFieldID)) {
		t.Fatal("missing config did not load clean, safe, editable defaults")
	}
	if enabled, _, _ := guiUser32.NewProc("IsWindowEnabled").Call(w.controls[guiSaveID]); enabled == 0 {
		t.Fatal("first setup requires a redundant reload before saving")
	}
	w.command(guiStartID)
	if w.busy || !strings.Contains(get(guiSettingsNoteID), "请先填写并保存") {
		t.Fatal("first setup attempted a connection before config existed")
	}
	// A failed reload is an unreadable existing file, not a confirmed first run.
	if err := os.WriteFile(path, []byte("invalid: ["), 0600); err != nil {
		t.Fatal(err)
	}
	w.command(guiReloadID)
	awaitDesktopNativeResult(t, w)
	if w.newConfig || w.formLoaded || w.formLoadError == "" || !strings.Contains(get(guiConfigSummaryID), "读取失败") {
		t.Fatal("failed reload retained a misleading first-run state")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	w.command(guiReloadID)
	awaitDesktopNativeResult(t, w)
	if !w.newConfig || !w.formLoaded || w.formLoadError != "" {
		t.Fatal("missing file retry did not restore first setup")
	}
	for _, group := range [][]int{guiBasicFields, guiGatewayFields, guiRouteFields, guiAdvancedFields} {
		for _, id := range group {
			hwnd, _, _ := guiUser32.NewProc("GetDlgItem").Call(w.settings, uintptr(id))
			if hwnd == 0 || hwnd != w.controls[id] {
				t.Fatalf("missing native setting control %d", id)
			}
		}
	}
	var limits [5]guiPoint
	guiSendMessage.Call(w.settings, guiWMGetMinMaxInfo, 0, uintptr(unsafe.Pointer(&limits[0])))
	if limits[3] != (guiPoint{700, 700}) {
		t.Fatal("settings minimum size changed")
	}
	w.command(guiSaveID)
	awaitDesktopNativeResult(t, w)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("blank trust/identity fields created a config")
	}
	config, err := desktopParseConfig(desktopTestConfig(get(guiStateFieldID)))
	if err != nil {
		t.Fatal(err)
	}
	form := desktopFormFromConfig(config)
	for id, value := range map[int]string{guiRootFieldID: form.RootPublicKey, guiManagedFieldID: form.ManagedZone} {
		edit(id, value)
	}
	for _, value := range desktopFormLines(form.AllowedGateways) {
		edit(guiAllowedInputID, value)
		click(guiAllowedAddID)
	}
	for _, value := range desktopFormLines(form.SplitRoutes) {
		edit(guiRouteInputID, value)
		click(guiRouteAddID)
	}
	// Allowed gateway entries are native list rows, with independent selection
	// and update/delete controls rather than an encoded multiline editor.
	allowed := w.optionLists[guiAllowedFieldID]
	beforeAllowed := len(allowed.Rows)
	edit(guiAllowedInputID, "temporary.example.")
	click(guiAllowedAddID)
	guiSendMessage.Call(w.controls[guiAllowedFieldID], 0x186, uintptr(beforeAllowed), 0)
	guiSendMessage.Call(w.settings, guiWMCommand, guiAllowedFieldID|1<<16, 0)
	if get(guiAllowedInputID) != "temporary.example." {
		t.Fatal("gateway list selection did not populate editor")
	}
	edit(guiAllowedInputID, "*.temporary.example.")
	click(guiAllowedUpdateID)
	if len(allowed.Rows) != beforeAllowed+1 || allowed.Rows[beforeAllowed] != "*.temporary.example." {
		t.Fatal("gateway list update failed")
	}
	guiSendMessage.Call(w.controls[guiAllowedFieldID], 0x186, uintptr(beforeAllowed), 0)
	guiSendMessage.Call(w.settings, guiWMCommand, guiAllowedFieldID|1<<16, 0)
	click(guiAllowedDeleteID)
	if len(allowed.Rows) != beforeAllowed || allowed.Dirty || get(guiAllowedInputID) != "" {
		t.Fatal("gateway list delete retained a draft or changed other rows")
	}
	// List drafts survive navigation and cannot silently enter a saved form.
	edit(guiAllowedInputID, "*.example.")
	click(guiRoutePageID)
	if w.settingsPage != guiRoutePageID || get(guiAllowedInputID) != "*.example." || !w.optionLists[guiAllowedFieldID].Dirty {
		t.Fatal("page switch lost an unapplied gateway draft")
	}
	w.command(guiSaveID)
	if w.busy || !strings.Contains(get(guiSettingsNoteID), "尚未添加或更新") {
		t.Fatal("save discarded an unapplied gateway draft")
	}
	click(guiAllowedClearID)
	beforeRoutes := len(w.optionLists[guiSplitFieldID].Rows)
	for _, invalid := range []string{"10.0.0.1/24", "0.0.0.0/0", "::/0"} {
		edit(guiRouteInputID, invalid)
		click(guiRouteAddID)
		if len(w.optionLists[guiSplitFieldID].Rows) != beforeRoutes {
			t.Fatalf("invalid split route %q was silently changed or accepted", invalid)
		}
	}
	click(guiRouteClearID)
	edit(guiBootstrapPeerID, "*.gateway.")
	edit(guiBootstrapAddressID, "127.0.0.1:33434")
	click(guiBootstrapAddID)
	if len(w.bootstrapRows) != 0 || !strings.Contains(get(guiSettingsNoteID), "具体") {
		t.Fatal("bootstrap accepted a pattern in place of a concrete gateway identity")
	}
	click(guiBootstrapClearID)
	edit(guiBootstrapPeerID, "gateway.")
	edit(guiBootstrapAddressID, "127.0.0.1:33434")
	click(guiBootstrapAddID)
	if len(w.bootstrapRows) != 1 || w.bootstrapDirty {
		t.Fatal("bootstrap add did not apply and clear its draft")
	}
	// Same peer with a different address is a supported multi-address config.
	edit(guiBootstrapPeerID, "gateway.")
	edit(guiBootstrapAddressID, "127.0.0.2:33434")
	click(guiBootstrapAddID)
	if len(w.bootstrapRows) != 2 {
		t.Fatal("same peer with another address was rejected")
	}
	detached, err := w.collectForm()
	if err != nil {
		t.Fatal(err)
	}
	w.bootstrapRows[0].Address = "127.0.0.3:33434"
	if detached.BootstrapHints[0].Address != "127.0.0.1:33434" {
		t.Fatal("worker form aliases mutable UI rows")
	}
	w.bootstrapRows[0].Address = "127.0.0.1:33434"
	guiSendMessage.Call(w.controls[guiBootstrapListID], 0x186, 1, 0)
	guiSendMessage.Call(w.settings, guiWMCommand, guiBootstrapListID|1<<16, 0)
	if get(guiBootstrapPeerID) != "gateway." || get(guiBootstrapAddressID) != "127.0.0.2:33434" {
		t.Fatal("selected bootstrap row did not populate both fields")
	}
	click(guiBootstrapDeleteID)
	if len(w.bootstrapRows) != 1 || w.bootstrapDirty || get(guiBootstrapPeerID) != "" || get(guiBootstrapAddressID) != "" {
		t.Fatal("delete retained an unapplied draft")
	}
	edit(guiBootstrapPeerID, "unapplied.example.")
	w.command(guiSaveID)
	if w.busy || !strings.Contains(get(guiSettingsNoteID), "尚未添加或更新") {
		t.Fatal("save silently discarded an unapplied bootstrap draft")
	}
	click(guiAdvancedPageID)
	if w.settingsPage != guiAdvancedPageID || !w.bootstrapDirty || get(guiBootstrapPeerID) != "unapplied.example." {
		t.Fatal("page switch lost an unapplied bootstrap draft")
	}
	click(guiBootstrapClearID)
	click(guiAdvancedPageID)
	if w.settingsPage != guiAdvancedPageID {
		t.Fatal("advanced page did not open")
	}
	edit(guiMTUFieldID, "1360")
	edit(guiMaxFieldID, "31s")
	w.command(guiSaveID)
	awaitDesktopNativeResult(t, w)
	saved, err := photonwindows.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if saved.ManagedZone != config.ManagedZone || saved.Wintun.MTU != 1360 || saved.Reconnect.MaxBackoff != 31*time.Second || len(saved.Gateway.BootstrapHints) != 1 || w.dirty || w.newConfig {
		t.Fatal("native worker save did not persist the complete form")
	}
	if _, err := os.Stat(saved.State.Path); !os.IsNotExist(err) {
		t.Fatal("GUI first setup created or opened an identity DB")
	}
	w.command(guiReloadID)
	awaitDesktopNativeResult(t, w)
	if get(guiMTUFieldID) != "1360" || get(guiMaxFieldID) != "31s" || len(w.bootstrapRows) != 1 || w.dirty {
		t.Fatal("native worker reload lost settings or marked programmatic changes dirty")
	}
	w.openSettings()
	guiSendMessage.Call(w.settings, guiWMClose, 0, 0)
	if w.settings == 0 || w.ctx.Err() != nil {
		t.Fatal("settings Close destroyed the desktop worker")
	}
	w.dirty = false
}
