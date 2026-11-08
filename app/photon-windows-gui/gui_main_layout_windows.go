//go:build windows

package main

import (
	"fmt"
	"slices"
	"strings"
	"time"
	"unsafe"
)

const guiMainDefaultNote = "保存后需重新连接生效；关闭窗口隐藏到托盘，退出 Photon 会停止连接。"
const (
	guiConnectID = 1120 + iota
	guiNavDashboardID
	guiNavGossipID
	guiNavTunnelID
	guiNavBabelID
	guiNavLogsID
	guiBrandID
	guiBrandNoteID
	guiHeroTitleID
	guiHeroDetailID
	guiNodeTitleID
	guiNodeHintID
	guiNodeHeaderID
	guiNodeListID
	guiNodeEmptyID
	guiDashboardNoteID
	guiLegendID
)

var guiSidebarIDs = []int{guiNavDashboardID, guiNavGossipID, guiNavTunnelID, guiNavBabelID, guiNavLogsID, guiDiagnosticsID, guiProxyOpenID, guiSettingsID}
var guiDashboardIDs = []int{guiHeroTitleID, guiHeroDetailID, guiConnectID, guiRestartID, guiNodeTitleID, guiNodeHintID, guiNodeHeaderID, guiNodeListID, guiNodeEmptyID, guiDashboardNoteID, guiLegendID}

func (w *desktopWindow) createMainControls() error {
	specs := []struct {
		id                int
		class, text, kind string
		style, ex         uintptr
	}{
		{guiBrandID, "STATIC", "Photon", "title", 0x50000000, 0},
		{guiBrandNoteID, "STATIC", "安全连接你的网络", "muted", 0x50000000, 0},
		{guiNavDashboardID, "BUTTON", "◫  Dashboard", "navActive", 0x50010000, 0},
		{guiNavGossipID, "BUTTON", "◎  Gossip", "nav", 0x50010000, 0},
		{guiNavTunnelID, "BUTTON", "⇄  Tunnel", "nav", 0x50010000, 0},
		{guiNavBabelID, "BUTTON", "⑂  Babel", "nav", 0x50010000, 0},
		{guiNavLogsID, "BUTTON", "≡  日志", "nav", 0x50010000, 0},
		{guiDiagnosticsID, "BUTTON", "⋯  诊断", "nav", 0x50010000, 0},
		{guiProxyOpenID, "BUTTON", "⇄  代理", "nav", 0x50010000, 0},
		{guiSettingsID, "BUTTON", "⚙  设置", "nav", 0x50010000, 0},
		{guiHeroTitleID, "STATIC", "未连接", "cardTitle", 0x50000000, 0},
		{guiHeroDetailID, "STATIC", "开启右上角开关，连接 Photon 网络", "cardMuted", 0x50000000, 0},
		{guiConnectID, "BUTTON", "○  连接网络", "primary", 0x50010000, 0},
		{guiRestartID, "BUTTON", "重新连接", "secondary", 0x50010000, 0},
		{guiNodeTitleID, "STATIC", "节点", "section", 0x50000000, 0},
		{guiNodeHintID, "STATIC", "名称倒序 · 双击查看详情", "muted", 0x50000000, 0},
		{guiNodeHeaderID, "STATIC", "", "body", 0x5000000d, 0},
		{guiNodeListID, "LISTBOX", "", "edit", 0x50010000 | 0x0001 | 0x0010 | 0x0040 | 0x0100 | 0x00200000, 0},
		{guiNodeEmptyID, "STATIC", "连接后，节点状态将显示在这里", "cardMuted", 0x40000000 | 0x0001, 0},
		{guiLegendID, "STATIC", "✓ IPv4 / ✓ IPv6 表示对应协议可用；双栈显示两个勾。\r\nGossip 显示最近同步结果；健康监测依据 Babel 邻居状态。", "muted", 0x50000000, 0},
		{guiDashboardNoteID, "STATIC", "", "muted", 0x50000000, 0},
		// Retain the complete diagnostic text and route selection model. These
		// controls are hidden; the sidebar exposes their full reading views.
		{guiStatusID, "STATIC", "连接：读取中…", "title", 0x40000000, 0},
		{guiRuntimeID, "STATIC", "", "muted", 0x40000000, 0},
		{guiGatewayID, "STATIC", "", "section", 0x40000000, 0},
		{guiAdmissionID, "STATIC", "", "body", 0x40000000, 0},
		{guiStartID, "BUTTON", "启动连接", "primary", 0x40010000, 0},
		{guiStopID, "BUTTON", "停止连接", "body", 0x40010000, 0},
		{guiRoutesID, "LISTBOX", "", "edit", 0x40010000 | 0x0001 | 0x0100 | 0x00200000, 0},
		{guiConfigSummaryID, "STATIC", "", "body", 0x40000000, 0},
		{guiNoteID, "EDIT", guiMainDefaultNote, "edit", 0x40010000 | 0x0004 | 0x0040 | 0x0800 | 0x00200000, 0},
		{guiJoinRequestID, "EDIT", "", "mono", 0x40010000 | 0x0080 | 0x0800, 0x200},
		{guiCopyRequestID, "BUTTON", "复制入网请求", "secondary", 0x40010000, 0},
	}
	for _, s := range specs {
		hwnd, _, err := guiCreateWindow.Call(s.ex, uintptr(unsafe.Pointer(guiUTF16(s.class))), uintptr(unsafe.Pointer(guiUTF16(s.text))), s.style, 0, 0, 0, 0, w.hwnd, uintptr(s.id), w.instance, 0)
		if hwnd == 0 {
			return guiCallError("CreateWindowEx "+s.class, err)
		}
		w.controls[s.id] = hwnd
		w.guiStyleControl(hwnd, s.kind)
	}
	return nil
}

func (w *desktopWindow) refreshMainNote() {
	text := w.operationNote
	if text == "" {
		text = guiMainDefaultNote
	}
	if w.liveError != "" && !strings.Contains(text, w.liveError) {
		text += "\r\n\r\n实时状态详情：" + w.liveError
	}
	if readiness := desktopReadinessPresentation(w.snapshot.Observation, desktopLiveSnapshot(w.snapshot)); readiness.Detail != "" {
		text += "\r\n\r\n连接详情：" + readiness.Detail
	}
	w.setText(w.controls[guiNoteID], text)
	summary := w.operationNote
	if summary == "" || summary == guiMainDefaultNote {
		summary = "关闭窗口后保持连接 · 从托盘退出可停止 Photon"
	}
	summary = strings.ReplaceAll(strings.ReplaceAll(summary, "\r", " "), "\n", " ")
	w.setText(w.controls[guiDashboardNoteID], summary)
}

func (w *desktopWindow) mainNavigation(id int) bool {
	page, ok := map[int]int{guiNavDashboardID: 0, guiNavGossipID: guiDiagnosticsPeersID, guiNavTunnelID: guiDiagnosticsGatewayID, guiNavBabelID: guiDiagnosticsRoutesID, guiNavLogsID: guiDiagnosticsLogID, guiDiagnosticsID: guiDiagnosticsOverviewID, guiSettingsID: guiSettingsID}[id]
	if !ok {
		return false
	}
	if !w.quitting {
		w.selectMainPage(page)
	}
	return true
}

func (w *desktopWindow) selectMainPage(page int) {
	if w.quitting {
		return
	}
	w.mainPage = page
	if page != 0 && page != guiSettingsID && w.diagnosticsView != nil {
		v := w.diagnosticsView
		v.page = page
		if !v.paused || v.sampledAt.IsZero() {
			v.snapshot, v.sampledAt = w.snapshot, time.Now()
		}
	}
	w.layout()
	if page != 0 && page != guiSettingsID && w.diagnosticsView != nil {
		w.layoutDiagnostics()
		w.drawDiagnostics()
		if !w.diagnosticsView.paused {
			w.refreshDiagnostics()
		}
	}
	// Move focus out of a page before it disappears. Native Tab can then enter
	// the visible page, including its nested edit and list controls.
	guiUser32.NewProc("SetFocus").Call(w.controls[w.sidebarSelection()])
	guiUser32.NewProc("RedrawWindow").Call(w.hwnd, 0, 0, 0x185)
}

func (w *desktopWindow) sidebarSelection() int {
	switch w.mainPage {
	case 0:
		return guiNavDashboardID
	case guiSettingsID:
		return guiSettingsID
	case guiDiagnosticsPeersID:
		return guiNavGossipID
	case guiDiagnosticsGatewayID:
		return guiNavTunnelID
	case guiDiagnosticsRoutesID:
		return guiNavBabelID
	case guiDiagnosticsLogID:
		return guiNavLogsID
	default:
		return guiDiagnosticsID
	}
}

func (w *desktopWindow) renderDashboard() {
	title, detail := desktopDashboardStatus(w.snapshot, w.admission)
	w.setText(w.controls[guiHeroTitleID], title)
	w.setText(w.controls[guiHeroDetailID], detail)
	label := "○  连接网络"
	if w.snapshot.RuntimeState == "running" || w.snapshot.RuntimeState == "starting" {
		label = "●  断开连接"
	}
	w.setText(w.controls[guiConnectID], label)
	rows := desktopDashboardNodes(w.snapshot)
	list := w.controls[guiNodeListID]
	if !slices.Equal(rows, w.nodeRows) {
		selected, _, _ := guiSendMessage.Call(list, 0x0188, 0, 0)
		top, _, _ := guiSendMessage.Call(list, 0x018e, 0, 0)
		selectedPeer, topPeer := "", ""
		if selected < uintptr(len(w.nodeRows)) {
			selectedPeer = w.nodeRows[selected].Peer
		}
		if top < uintptr(len(w.nodeRows)) {
			topPeer = w.nodeRows[top].Peer
		}
		w.nodeRows = rows
		guiSendMessage.Call(list, 0x000b, 0, 0)
		guiSendMessage.Call(list, 0x0184, 0, 0)
		sel := ^uintptr(0)
		for i, r := range rows {
			accessible := r.Peer + " · Gossip " + r.Gossip + " · Tunnel " + r.Tunnel + " · 健康 " + r.Health
			guiSendMessage.Call(list, 0x0180, 0, uintptr(unsafe.Pointer(guiUTF16(accessible))))
			if r.Peer == selectedPeer {
				sel = uintptr(i)
			}
			if r.Peer == topPeer {
				top = uintptr(i)
			}
		}
		guiSendMessage.Call(list, 0x0186, sel, 0)
		if len(rows) > 0 {
			guiSendMessage.Call(list, 0x0197, min(top, uintptr(len(rows)-1)), 0)
		}
		guiSendMessage.Call(list, 0x000b, 1, 0)
		guiUser32.NewProc("RedrawWindow").Call(list, 0, 0, 0x405)
	}
	suffix := ""
	if o := w.snapshot.Observation; desktopLiveSnapshot(w.snapshot) && (o.PeersTruncated || o.ConnectionsTruncated || o.RoutesTruncated) {
		suffix = " · 样本已截断"
	}
	w.setText(w.controls[guiNodeTitleID], fmt.Sprintf("节点  %d%s", len(rows), suffix))
	empty := "连接后，节点状态将显示在这里"
	if desktopLiveSnapshot(w.snapshot) {
		empty = "尚无节点，正在等待发现与同步"
	}
	if w.snapshot.Error != "" {
		empty = "状态读取失败，请到诊断页查看详情"
	}
	w.setText(w.controls[guiNodeEmptyID], empty)
	if w.mainPage == 0 {
		show := uintptr(0)
		if len(rows) == 0 {
			show = 5
		}
		guiShowWindow.Call(w.controls[guiNodeEmptyID], show)
	}
}

func (w *desktopWindow) openDashboardNode() {
	selected, _, _ := guiSendMessage.Call(w.controls[guiNodeListID], 0x0188, 0, 0)
	if selected >= uintptr(len(w.nodeRows)) || w.diagnosticsView == nil {
		return
	}
	id := w.nodeRows[selected].Peer
	page := guiDiagnosticsPeersID
	if slices.Contains(desktopGatewayNodes(w.snapshot), id) {
		page = guiDiagnosticsGatewayID
		w.diagnosticsView.gatewayID = id
	} else {
		w.diagnosticsView.peerID = id
	}
	w.selectMainPage(page)
}

func (w *desktopWindow) layout() {
	width, height := w.guiClientSize(w.hwnd)
	if width <= 0 || height <= 0 {
		return
	}
	const rail = 184
	x, content := rail+28, width-rail-56
	for _, id := range guiSidebarIDs {
		kind := "nav"
		if id == w.sidebarSelection() {
			kind = "navActive"
		}
		if w.appearance.roles[w.controls[id]] != kind {
			w.guiStyleControl(w.controls[id], kind)
		}
	}
	w.guiMove(w.controls[guiBrandID], 28, 28, 144, 36)
	w.guiMove(w.controls[guiBrandNoteID], 28, 70, 148, 24)
	for i, id := range guiSidebarIDs[:len(guiSidebarIDs)-1] {
		w.guiMove(w.controls[id], 16, 124+i*52, 152, 44)
	}
	w.guiMove(w.controls[guiSettingsID], 16, height-68, 152, 44)
	dashboard := w.mainPage == 0
	show := uintptr(0)
	if dashboard {
		show = 5
	}
	for _, id := range guiDashboardIDs {
		guiShowWindow.Call(w.controls[id], show)
	}
	requestShow := uintptr(0)
	if dashboard && w.admission.Pending {
		requestShow = 5
	}
	guiShowWindow.Call(w.controls[guiJoinRequestID], requestShow)
	guiShowWindow.Call(w.controls[guiCopyRequestID], requestShow)
	settingsShow, diagnosticsShow := uintptr(0), uintptr(0)
	if w.mainPage == guiSettingsID {
		settingsShow = 5
	} else if !dashboard {
		diagnosticsShow = 5
	}
	if w.settings != 0 {
		w.guiMove(w.settings, rail, 0, width-rail, height)
		guiShowWindow.Call(w.settings, settingsShow)
	}
	if w.diagnostics != 0 {
		w.guiMove(w.diagnostics, rail, 0, width-rail, height)
		guiShowWindow.Call(w.diagnostics, diagnosticsShow)
	}
	if !dashboard {
		return
	}
	w.guiMove(w.controls[guiHeroTitleID], x+24, 52, content-244, 38)
	w.guiMove(w.controls[guiHeroDetailID], x+24, 100, content-244, 72)
	w.guiMove(w.controls[guiConnectID], width-28-184, 48, 160, 42)
	w.guiMove(w.controls[guiRestartID], width-28-184, 108, 160, 34)
	top := 210
	if w.admission.Pending {
		w.guiMove(w.controls[guiJoinRequestID], x, 204, content-164, 32)
		w.guiMove(w.controls[guiCopyRequestID], width-28-152, 204, 152, 32)
		top = 266
	}
	w.guiMove(w.controls[guiNodeTitleID], x, top, content-280, 28)
	w.guiMove(w.controls[guiNodeHintID], width-28-264, top+3, 264, 24)
	w.guiMove(w.controls[guiNodeHeaderID], x, top+44, content, 28)
	w.guiMove(w.controls[guiNodeListID], x, top+80, content, max(0, height-top-180))
	guiSendMessage.Call(w.controls[guiNodeListID], 0x01a0, 0, uintptr(w.guiScale(68))) // LB_SETITEMHEIGHT
	w.guiMove(w.controls[guiNodeEmptyID], x+24, top+110, content-48, 36)
	emptyShow := uintptr(0)
	if len(w.nodeRows) == 0 {
		emptyShow = 5
	}
	guiShowWindow.Call(w.controls[guiNodeEmptyID], emptyShow)
	w.guiMove(w.controls[guiLegendID], x, height-86, content, 44)
	w.guiMove(w.controls[guiDashboardNoteID], x, height-32, content, 24)
}
