//go:build windows

package main

import (
	"image"
	"image/png"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
	"time"
	"unsafe"

	"github.com/HiggsNet/photon/internal/photonwindows"
	"github.com/HiggsNet/photon/pkg/core/gossip"
)

func TestDesktopNativeDashboardNavigation(t *testing.T) {
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
		var m guiMessage
		guiUser32.NewProc("PeekMessageW").Call(uintptr(unsafe.Pointer(&m)), 0, 0x12, 0x12, 1)
	}()
	w.show()
	for len(w.requests) > 0 {
		<-w.requests
	}
	w.refreshing = false
	o := &photonwindows.Observation{Running: true, ObservedAt: time.Now(), TunnelReady: true, Admission: gossip.AdmissionDiagnosis{Reason: gossip.AdmissionReasonAdopted}, Peers: []photonwindows.PeerObservation{
		{Peer: "venus.example.", PullState: "completed"}, {Peer: "road.example.", PullState: "completed"}, {Peer: "less.example.", PullState: "failed"},
	}, Connections: []photonwindows.ConnectionObservation{
		{Peer: "venus.example.", IKE: photonwindows.IKEObservation{Gateway: "venus.example.", Live: true, ChildLive: true}, BabelLive: true, TunnelReady: true},
		{Peer: "road.example.", IKE: photonwindows.IKEObservation{Gateway: "road.example.", Live: true, ChildLive: true}, BabelLive: true, TunnelReady: true},
		{Peer: "less.example.", IKE: photonwindows.IKEObservation{AttemptGateway: "less.example.", AttemptActive: true}},
	}, Babel: photonwindows.BabelObservation{Routes: []photonwindows.RouteObservation{
		{Peer: "venus.example.", Prefix: netip.MustParsePrefix("10.16.0.0/16")}, {Peer: "venus.example.", Prefix: netip.MustParsePrefix("fd00::/64")}, {Peer: "road.example.", Prefix: netip.MustParsePrefix("fd00::/64")},
	}}}
	w.render(desktopSnapshot{RuntimeState: "running", Observation: o})
	list := w.controls[guiNodeListID]
	if w.nodeRows[0].Peer != "venus.example." {
		t.Fatal("native list lost descending order")
	}
	guiSendMessage.Call(list, 0x0186, 1, 0)
	o.Peers = append(o.Peers, photonwindows.PeerObservation{Peer: "zulu.example.", PullState: "completed"})
	w.render(desktopSnapshot{RuntimeState: "running", Observation: o})
	selected, _, _ := guiSendMessage.Call(list, 0x0188, 0, 0)
	if selected >= uintptr(len(w.nodeRows)) || w.nodeRows[selected].Peer != "road.example." {
		t.Fatal("node insertion changed selected identity")
	}
	// Two real BUTTON clicks are bounded by the existing worker admission guard.
	w.command(guiConnectID)
	select {
	case request := <-w.requests:
		if request.Action != "stop" {
			t.Fatal(request.Action)
		}
	default:
		t.Fatal("connected switch did not request stop")
	}
	w.busy = false
	w.render(desktopSnapshot{RuntimeState: "stopped"})
	w.command(guiConnectID)
	select {
	case request := <-w.requests:
		if request.Action != "start" {
			t.Fatal(request.Action)
		}
	default:
		t.Fatal("disconnected switch did not request start")
	}
	w.busy = false
	w.render(desktopSnapshot{RuntimeState: "running", Observation: o})
	for _, page := range []int{guiNavGossipID, guiNavTunnelID, guiNavBabelID, guiNavLogsID, guiSettingsID, guiNavDashboardID} {
		w.command(page)
		if page == guiSettingsID {
			parent, _, _ := guiUser32.NewProc("GetParent").Call(w.settings)
			if parent != w.hwnd {
				t.Fatal("settings escaped main window")
			}
			guiSendMessage.Call(w.controls[guiManagedFieldID], 0x00c2, 1, uintptr(unsafe.Pointer(guiUTF16("draft.example."))))
		}
	}
	text, _ := guiControlText(w.controls[guiManagedFieldID])
	if text != "draft.example." || !w.dirty {
		t.Fatal("navigation discarded settings draft")
	}
	for _, pending := range []bool{false, true} {
		w.admission.Pending = pending
		for _, size := range [][2]int{{920, 700}, {1100, 760}} {
			w.guiMove(w.hwnd, 0, 0, size[0], size[1])
			w.layout()
			guiCheckVisibleDashboardBounds(t, w)
		}
	}
	for _, size := range [][2]int{{920, 700}, {1100, 760}} {
		w.guiMove(w.hwnd, 0, 0, size[0], size[1])
		w.layout()
		for _, nav := range []int{guiNavGossipID, guiNavTunnelID, guiNavBabelID, guiNavLogsID, guiDiagnosticsID, guiSettingsID} {
			w.command(nav)
			if nav == guiSettingsID {
				for _, page := range []int{guiBasicPageID, guiGatewayPageID, guiRoutePageID, guiAdvancedPageID} {
					w.showSettingsPage(page)
					guiCheckPageBounds(t, w, w.settings)
				}
			} else {
				style, _, _ := guiUser32.NewProc("GetWindowLongPtrW").Call(w.controls[guiDiagnosticsPeerListID], ^uintptr(15))
				peerPage := nav == guiNavGossipID || nav == guiNavTunnelID
				if (style&0x10000000 != 0) != peerPage {
					t.Fatalf("sidebar page %d did not lay out its node list", nav)
				}
				guiCheckPageBounds(t, w, w.diagnostics)
			}
		}
	}
	w.showSettingsPage(guiBasicPageID)
	w.command(guiNavDashboardID)
	w.admission.Pending = false
	w.applyResult(guiResult{Action: "start", Snapshot: desktopSnapshot{RuntimeState: "running", Observation: o}})
	w.layout()
	if dir := os.Getenv("PHOTON_WINDOWS_GUI_ARTIFACT_DIR"); dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		for _, page := range []int{guiNavDashboardID, guiNavGossipID, guiNavTunnelID, guiSettingsID} {
			w.command(page)
			if w.diagnosticsView != nil {
				w.diagnosticsView.snapshot = w.snapshot
				w.diagnosticsView.sampledAt = time.Now()
				w.drawDiagnostics()
			}
			guiSaveWindowPNG(t, w, filepath.Join(dir, map[int]string{guiNavDashboardID: "dashboard.png", guiNavGossipID: "gossip.png", guiNavTunnelID: "tunnel.png", guiSettingsID: "settings.png"}[page]))
		}
		for page, name := range map[int]string{guiGatewayPageID: "settings-nodes.png", guiRoutePageID: "settings-routes.png", guiAdvancedPageID: "settings-advanced.png"} {
			w.command(guiSettingsID)
			w.showSettingsPage(page)
			guiSaveWindowPNG(t, w, filepath.Join(dir, name))
		}
		w.command(guiNavDashboardID)
		request, encoded := desktopTestJoinRequest(t)
		o.Admission = gossip.AdmissionDiagnosis{Pending: true, ManagedZone: request.Zone, Reason: gossip.AdmissionReasonMissingDelegation, JoinRequestB64: encoded}
		w.render(desktopSnapshot{RuntimeState: "running", Observation: o})
		guiSaveWindowPNG(t, w, filepath.Join(dir, "pending.png"))
		o.Admission = gossip.AdmissionDiagnosis{Reason: gossip.AdmissionReasonAdopted}
		w.render(desktopSnapshot{RuntimeState: "stopped"})
		guiSaveWindowPNG(t, w, filepath.Join(dir, "disconnected.png"))
	}
	w.command(guiNavDashboardID)
	w.render(desktopSnapshot{RuntimeState: "running", Observation: o, Error: "sample failed"})
	if len(w.nodeRows) != 0 {
		t.Fatal("failed refresh kept live dashboard")
	}
}

func guiCheckPageBounds(t *testing.T, w *desktopWindow, parent uintptr) {
	t.Helper()
	var client guiRect
	guiGetClientRect.Call(parent, uintptr(unsafe.Pointer(&client)))
	children := make(map[uintptr]bool)
	for _, h := range w.controls {
		children[h] = true
	}
	for _, h := range w.formLabels {
		children[h] = true
	}
	for child := range children {
		p, _, _ := guiUser32.NewProc("GetParent").Call(child)
		if p != parent {
			continue
		}
		style, _, _ := guiUser32.NewProc("GetWindowLongPtrW").Call(child, ^uintptr(15))
		if style&0x10000000 == 0 {
			continue
		}
		var r guiRect
		guiUser32.NewProc("GetWindowRect").Call(child, uintptr(unsafe.Pointer(&r)))
		guiUser32.NewProc("MapWindowPoints").Call(0, parent, uintptr(unsafe.Pointer(&r)), 2)
		// Empty input labels intentionally occupy a zero-sized rectangle.
		if r.Right == r.Left && r.Bottom == r.Top {
			continue
		}
		if r.Left < 0 || r.Top < 0 || r.Right > client.Right || r.Bottom > client.Bottom {
			id, _, _ := guiUser32.NewProc("GetDlgCtrlID").Call(child)
			t.Fatalf("page %d/%d control %d clipped: %+v / %+v", w.mainPage, w.settingsPage, id, r, client)
		}
	}
}

func guiCheckVisibleDashboardBounds(t *testing.T, w *desktopWindow) {
	t.Helper()
	var client guiRect
	guiGetClientRect.Call(w.hwnd, uintptr(unsafe.Pointer(&client)))
	ids := append(slices.Clone(guiSidebarIDs), guiDashboardIDs...)
	if w.admission.Pending {
		ids = append(ids, guiJoinRequestID, guiCopyRequestID)
	}
	for _, id := range ids {
		child := w.controls[id]
		style, _, _ := guiUser32.NewProc("GetWindowLongPtrW").Call(child, ^uintptr(15))
		if style&0x10000000 == 0 {
			continue
		}
		var rect guiRect
		guiUser32.NewProc("GetWindowRect").Call(child, uintptr(unsafe.Pointer(&rect)))
		guiUser32.NewProc("MapWindowPoints").Call(0, w.hwnd, uintptr(unsafe.Pointer(&rect)), 2)
		if rect.Left < 0 || rect.Top < 0 || rect.Right > client.Right || rect.Bottom > client.Bottom || rect.Right <= rect.Left || rect.Bottom <= rect.Top {
			t.Fatalf("control %d outside client: %+v / %+v", id, rect, client)
		}
	}
}

// WM_PRINT captures actual Win32 control rendering on a test desktop.
// These synthetic states are visual fixtures, not live network acceptance.
func guiSaveWindowPNG(t *testing.T, w *desktopWindow, path string) {
	t.Helper()
	guiUser32.NewProc("RedrawWindow").Call(w.hwnd, 0, 0, 0x185)
	var rect guiRect
	guiUser32.NewProc("GetWindowRect").Call(w.hwnd, uintptr(unsafe.Pointer(&rect)))
	width, height := rect.Right-rect.Left, rect.Bottom-rect.Top
	dc, _, _ := guiGDI32.NewProc("CreateCompatibleDC").Call(0)
	if dc == 0 {
		t.Fatal("CreateCompatibleDC")
	}
	defer guiGDI32.NewProc("DeleteDC").Call(dc)
	info := struct {
		Size                   uint32
		Width, Height          int32
		Planes, BitCount       uint16
		Compression, SizeImage uint32
		XPels, YPels           int32
		Used, Important        uint32
	}{Size: 40, Width: width, Height: -height, Planes: 1, BitCount: 32}
	var bits unsafe.Pointer
	bitmap, _, _ := guiGDI32.NewProc("CreateDIBSection").Call(dc, uintptr(unsafe.Pointer(&info)), 0, uintptr(unsafe.Pointer(&bits)), 0, 0)
	if bitmap == 0 || bits == nil {
		t.Fatal("CreateDIBSection")
	}
	defer guiDeleteObject.Call(bitmap)
	previous, _, _ := guiGDI32.NewProc("SelectObject").Call(dc, bitmap)
	defer guiGDI32.NewProc("SelectObject").Call(dc, previous)
	// Ask Win32 controls to paint into the bitmap directly. DWM PrintWindow
	// may return a black frame on a noninteractive test desktop.
	guiSendMessage.Call(w.hwnd, 0x0317, dc, 0x001e) // WM_PRINT: NONCLIENT | CLIENT | ERASEBKGND | CHILDREN
	pixels := unsafe.Slice((*byte)(bits), int(width*height*4))
	img := image.NewRGBA(image.Rect(0, 0, int(width), int(height)))
	nonBlack := false
	for i := 0; i < len(pixels); i += 4 {
		if pixels[i] != 0 || pixels[i+1] != 0 || pixels[i+2] != 0 {
			nonBlack = true
		}
		img.Pix[i], img.Pix[i+1], img.Pix[i+2], img.Pix[i+3] = pixels[i+2], pixels[i+1], pixels[i], 255
	}
	if !nonBlack {
		t.Fatal("native capture returned a black frame")
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := png.Encode(f, img); err != nil {
		t.Fatal(err)
	}
}
