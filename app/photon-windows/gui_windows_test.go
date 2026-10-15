//go:build windows

package main

import (
	"fmt"
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
	backend, err := newDesktopBackend(desktopOptions{ConfigPath: filepath.Join(t.TempDir(), "missing.yaml"), ServiceName: fmt.Sprintf("Photon-GUI-Native-Test-%d", os.Getpid())})
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
	for _, id := range []int{guiStatusID, guiServiceID, guiGatewayID, guiRoutesID, guiConfigID, guiNoteID, guiAdmissionID, guiJoinRequestID, guiInstallID, guiStartID, guiStopID, guiRestartID, guiSaveID, guiReloadID, guiCopyRequestID} {
		hwnd, _, _ := guiUser32.NewProc("GetDlgItem").Call(w.hwnd, uintptr(id))
		if hwnd == 0 || hwnd != w.controls[id] {
			t.Fatalf("missing native child control %d", id)
		}
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
	w.render(desktopSnapshot{ServiceState: "running", Observation: observation})
	if text(guiJoinRequestID) != request || !strings.Contains(text(guiStatusID), "待授权") || strings.Contains(text(guiGatewayID), "gateway.example.") || strings.Contains(text(guiRoutesID), "198.18.253.1") {
		t.Fatal("pending admission retained connected state or truncated the public request")
	}
	if enabled, _, _ := guiUser32.NewProc("IsWindowEnabled").Call(w.controls[guiCopyRequestID]); enabled == 0 {
		t.Fatal("pending request copy button is disabled")
	}
	observation.Admission.Reason = gossip.AdmissionReasonDelegationKeyMismatch
	w.render(desktopSnapshot{ServiceState: "running", Observation: observation})
	if !strings.Contains(text(guiAdmissionID), "本机公钥不匹配") || text(guiJoinRequestID) != request {
		t.Fatal("delegation key mismatch did not preserve the current complete request")
	}
	for _, unavailable := range []desktopSnapshot{{ServiceState: "stopped", Observation: observation}, {ServiceState: "running", Observation: observation, Error: "IPC disconnected"}} {
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
	w.render(desktopSnapshot{ServiceState: "running", Observation: observation})
	if text(guiJoinRequestID) != "" || !strings.Contains(text(guiAdmissionID), "已入网") || !strings.Contains(text(guiStatusID), "已入网，正在连接") {
		t.Fatal("adopted state retained pending request or claimed a ready tunnel")
	}
	observation.TunnelReady = true
	w.render(desktopSnapshot{ServiceState: "running", Observation: observation})
	if !strings.Contains(text(guiStatusID), "已连接") || !strings.Contains(text(guiGatewayID), "gateway.example.") || !strings.Contains(text(guiRoutesID), "metric 100") {
		t.Fatal("live status/route did not render")
	}
	// Multiline EDIT intentionally does not send EN_CHANGE for WM_SETTEXT.
	// Replace the selected text as an actual user edit to exercise the native
	// notification rather than depending on WM_SETTEXT's different contract.
	guiSendMessage.Call(w.controls[guiConfigID], 0x00b1, 0, ^uintptr(0))                                         // EM_SETSEL
	guiSendMessage.Call(w.controls[guiConfigID], 0x00c2, 1, uintptr(unsafe.Pointer(guiUTF16("# new edit\r\n")))) // EM_REPLACESEL
	revision := w.editRevision
	if !w.dirty {
		t.Fatal("native EN_CHANGE did not mark edits")
	}
	w.render(desktopSnapshot{ServiceState: "stopped", Error: "IPC disconnected"})
	if strings.Contains(text(guiGatewayID), "gateway.example.") || strings.Contains(text(guiRoutesID), "198.18.253.1") || strings.Contains(text(guiStatusID), "已连接") {
		t.Fatal("offline result retained stale live status")
	}
	if text(guiConfigID) != "# new edit\r\n" {
		t.Fatal("status polling replaced unsaved YAML")
	}
	w.applyResult(guiResult{Action: "load", Text: "old: file\n", EditRevision: revision - 1, Snapshot: desktopSnapshot{ServiceState: "stopped"}})
	if text(guiConfigID) != "# new edit\r\n" || !w.dirty {
		t.Fatal("asynchronous load overwrote newer edits")
	}
	// One fixed worker and one queued request remain bounded under repeated
	// timer/button submissions. No SCM mutations are performed by this test.
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
	if got := text(guiConfigID); got != "# new edit\r\n" {
		t.Fatalf("worker status replaced edits: %q", got)
	}
	// Missing Explorer must not turn Close into an unfindable hidden process.
	// This branch deliberately tests the no-tray fallback, not a real tray.
	w.dirty = false
	w.tray = false
	guiSendMessage.Call(w.hwnd, guiWMClose, 0, 0)
	if _, exists := guiWindows.Load(w.hwnd); exists {
		t.Fatal("Close without tray retained a hidden owner")
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
