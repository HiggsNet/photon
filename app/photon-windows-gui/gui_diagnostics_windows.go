//go:build windows

package main

import (
	"fmt"
	"slices"
	"strings"
	"time"
	"unsafe"

	"github.com/HiggsNet/photon/internal/photonwindows"
)

const (
	guiDiagnosticsLogID       = 2301
	guiDiagnosticsPeersID     = 2302
	guiDiagnosticsDetailsID   = 2303
	guiDiagnosticsOverviewID  = 2304
	guiDiagnosticsGatewayID   = 2305
	guiDiagnosticsTextID      = 2310
	guiDiagnosticsRefreshID   = 2311
	guiDiagnosticsPauseID     = 2312
	guiDiagnosticsCopyID      = 2313
	guiDiagnosticsMetadataID  = 2314
	guiDiagnosticsTitleID     = 2315
	guiDiagnosticsPeerListID  = 2316
	guiDiagnosticsPeerTitleID = 2317
	guiDiagnosticsLogFilterID = 2318
	guiDiagnosticsNodeTitleID = 2319
	guiDiagnosticsRoutesID    = 2320
	guiDiagnosticsAddressesID = 2321
	guiDiagnosticsTextLimit   = 1 << 20 // UTF-16 code units, including copied text.
)

// This is presentation state on the window thread. The existing backend and
// single worker remain the only runtime and I/O owners. Pausing retains this
// window's public view while the main window continues receiving snapshots.
type guiDiagnosticsView struct {
	page                    int
	route                   routeKey
	logFilter               int
	peerID                  string
	gatewayID               string
	listPage                int
	peerIDs, peerRows       []string
	textView                string
	reading                 map[string]guiDiagnosticsReading
	paused, force           bool
	snapshot                desktopSnapshot
	tail                    desktopLogTail
	logErr                  error
	sampledAt, logSampledAt time.Time
}

func (w *desktopWindow) createDiagnosticsWindow() error {
	hwnd, _, err := guiCreateWindow.Call(0x10000, uintptr(unsafe.Pointer(guiUTF16("PhotonWindowsDiagnostics"))), uintptr(unsafe.Pointer(guiUTF16("Photon Windows · 日志与诊断"))), 0x40000000|0x02000000, 0, 0, uintptr(w.guiScale(940)), uintptr(w.guiScale(720)), w.hwnd, 0, w.instance, 0)
	if hwnd == 0 {
		return guiCallError("CreateWindowEx diagnostics", err)
	}
	w.diagnostics = hwnd
	w.diagnosticsView = &guiDiagnosticsView{page: guiDiagnosticsOverviewID}
	guiWindows.Store(hwnd, w)
	for _, spec := range []struct {
		id                int
		class, text, role string
		style, ex         uintptr
	}{
		{guiDiagnosticsOverviewID, "BUTTON", "概览", "primary", 0x50010000, 0},
		{guiDiagnosticsGatewayID, "BUTTON", "网关与隧道", "body", 0x50010000, 0},
		{guiDiagnosticsPeersID, "BUTTON", "Gossip", "body", 0x50010000, 0},
		{guiDiagnosticsLogID, "BUTTON", "日志", "body", 0x50010000, 0},
		{guiDiagnosticsRoutesID, "BUTTON", "Babel 路由", "body", 0x50010000, 0},
		{guiDiagnosticsAddressesID, "BUTTON", "节点地址", "body", 0x50010000, 0},
		{guiDiagnosticsDetailsID, "BUTTON", "原始 JSON", "body", 0x50010000, 0},
		{guiDiagnosticsTitleID, "STATIC", "日志与诊断", "title", 0x50000000, 0},
		{guiDiagnosticsMetadataID, "STATIC", "等待读取当前 Photon 的公开诊断…", "muted", 0x50000000, 0},
		// Native soft wrapping keeps long reasons readable at narrow widths;
		// copying still returns the original text, including intact raw JSON.
		{guiDiagnosticsTextID, "EDIT", "", "edit", 0x50010000 | 0x0004 | 0x0040 | 0x0800 | 0x00200000, 0x200},
		{guiDiagnosticsPeerTitleID, "STATIC", "节点", "body", 0x40000000, 0},
		{guiDiagnosticsNodeTitleID, "STATIC", "节点详情", "section", 0x40000000, 0},
		{guiDiagnosticsPeerListID, "LISTBOX", "", "edit", 0x40010000 | 0x0001 | 0x0100 | 0x00200000, 0x200},
		{guiDiagnosticsLogFilterID, "COMBOBOX", "", "edit", 0x40010000 | 0x0003 | 0x00200000, 0},
		{guiDiagnosticsRefreshID, "BUTTON", "刷新一次", "body", 0x50010000, 0},
		{guiDiagnosticsPauseID, "BUTTON", "暂停刷新", "body", 0x50010000, 0},
		{guiDiagnosticsCopyID, "BUTTON", "复制当前内容", "body", 0x50010000, 0},
	} {
		child, _, callErr := guiCreateWindow.Call(spec.ex, uintptr(unsafe.Pointer(guiUTF16(spec.class))), uintptr(unsafe.Pointer(guiUTF16(spec.text))), spec.style, 0, 0, 0, 0, hwnd, uintptr(spec.id), w.instance, 0)
		if child == 0 {
			return guiCallError("CreateWindowEx diagnostics "+spec.class, callErr)
		}
		w.controls[spec.id] = child
		w.guiStyleControl(child, spec.role)
	}
	w.guiApplyFont(w.controls[guiDiagnosticsTextID], "mono")
	for _, label := range []string{"连接与网关", "警告与错误", "Gossip 同步", "全部日志"} {
		guiSendMessage.Call(w.controls[guiDiagnosticsLogFilterID], 0x0143, 0, uintptr(unsafe.Pointer(guiUTF16(label)))) // CB_ADDSTRING
	}
	guiSendMessage.Call(w.controls[guiDiagnosticsLogFilterID], 0x014e, 0, 0)
	guiSendMessage.Call(w.controls[guiDiagnosticsTextID], 0xc5, guiDiagnosticsTextLimit, 0)
	w.layoutDiagnostics()
	return nil
}

func (w *desktopWindow) diagnosticsVisible() bool {
	if w.diagnostics == 0 {
		return false
	}
	visible, _, _ := guiUser32.NewProc("IsWindowVisible").Call(w.diagnostics)
	return visible != 0
}

func (w *desktopWindow) diagnosticsReadLogs() bool {
	v := w.diagnosticsView
	return v != nil && w.diagnosticsVisible() && v.page == guiDiagnosticsLogID && (!v.paused || v.force)
}

func (w *desktopWindow) openDiagnostics() {
	if w.diagnostics == 0 || w.quitting {
		return
	}
	w.selectMainPage(w.diagnosticsView.page)
	w.show()
	w.drawDiagnostics()
}

func (w *desktopWindow) refreshDiagnostics() {
	if w.quitting || w.diagnosticsView == nil {
		return
	}
	w.diagnosticsView.force = true
	// submit is bounded. If another task is admitted, renderDiagnostics will
	// carry the request forward until its requested log sample actually arrives.
	w.submit(guiRequest{Action: "refresh"})
}

func (w *desktopWindow) renderDiagnostics(snapshot desktopSnapshot, tail desktopLogTail, logErr error, logsRead bool) {
	v := w.diagnosticsView
	if v == nil || !w.diagnosticsVisible() {
		return
	}
	if v.paused && !v.force {
		return
	}
	if v.force && v.page == guiDiagnosticsLogID && !logsRead {
		w.submit(guiRequest{Action: "refresh"})
		return
	}
	v.snapshot, v.sampledAt = snapshot, time.Now()
	if logsRead {
		v.tail, v.logErr, v.logSampledAt = tail, logErr, v.sampledAt
	}
	v.force = false
	w.drawDiagnostics()
}

func (w *desktopWindow) drawDiagnostics() {
	v := w.diagnosticsView
	if v == nil {
		return
	}
	text, source, detail := "", "当前 Photon 进程的公开状态", ""
	sampled := v.sampledAt
	w.syncDiagnosticsPeerList()
	switch v.page {
	case guiDiagnosticsOverviewID:
		text = desktopFormatOverview(v.snapshot)
		if w.operationNote != "" {
			text += "\r\n[最近操作]\r\n" + w.operationNote
		}
	case guiDiagnosticsGatewayID:
		text = desktopFormatGatewayNode(v.snapshot, v.gatewayID)
	case guiDiagnosticsLogID:
		source = v.tail.Path
		if source == "" {
			source = "当前连接的日志文件"
		}
		sampled = v.logSampledAt
		switch {
		case v.logErr != nil:
			text = "无法读取日志：" + v.logErr.Error()
			detail = "读取失败，详情见下方；未保留上一次日志内容"
		case v.tail.Missing:
			text = "尚无日志文件。启动连接后会在配置的日志目录生成日志。"
			detail = "日志文件尚未创建"
		default:
			text = desktopFilterDiagnosticLog(v.tail.Text, v.logFilter)
			if text == "" {
				text = "当前筛选下暂无日志；可切换“全部日志”查看最近记录。"
			}
			if v.tail.Truncated {
				detail = "已截断：仅显示文件末尾的最近日志"
			}
			if v.snapshot.RuntimeState == "stopped" {
				if detail != "" {
					detail += " · "
				}
				detail += "连接已停止，显示历史日志"
			}
		}
	case guiDiagnosticsPeersID:
		text = desktopFormatPeer(v.snapshot, v.peerID)
	case guiDiagnosticsRoutesID:
		text = desktopFormatRouteSelection(v.snapshot, v.route)
	case guiDiagnosticsAddressesID:
		text = desktopFormatNodeAddresses(v.snapshot)
	case guiDiagnosticsDetailsID:
		text = desktopFormatDiagnostics(v.snapshot)
	}
	if v.page != guiDiagnosticsLogID {
		if v.snapshot.Error != "" {
			detail = "实时状态读取失败，详情见下方"
		} else if !desktopLiveSnapshot(v.snapshot) {
			detail = "当前无实时样本，已清空上一次节点数据"
		}
		if desktopLiveSnapshot(v.snapshot) {
			if !v.snapshot.Observation.ObservedAt.IsZero() {
				sampled = v.snapshot.Observation.ObservedAt
			}
			if v.snapshot.Observation.PeersTruncated || v.snapshot.Observation.RoutesTruncated {
				detail = "公开样本已截断，详情见下方标记"
			}
		}
	}
	if sampled.IsZero() {
		text = "正在读取…"
		detail = "等待读取当前视图"
	}
	// Native multiline EDIT uses CRLF, while the public file/JSON helpers may
	// return LF. Normalize only the presentation, preserving content and JSON.
	text = strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\n", "\r\n")
	bounded, truncated := guiBoundDiagnosticsText(text, guiDiagnosticsTextLimit)
	if truncated {
		detail += " · 显示内容达到长度上限，已截断"
	}
	mode := "自动刷新"
	if v.paused {
		mode = "已暂停；“刷新一次”仍可读取一次"
	}
	stamp := "尚未采样"
	if !sampled.IsZero() {
		stamp = sampled.Local().Format("2006-01-02 15:04:05")
	}
	metadata := fmt.Sprintf("%s · 更新于 %s\r\n来源：%s", mode, stamp, source)
	if detail != "" {
		metadata += "\r\n" + detail
	}
	w.updateDiagnosticsText(bounded)
	w.setText(w.controls[guiDiagnosticsMetadataID], metadata)
	title := map[int]string{guiDiagnosticsOverviewID: "运行概览", guiDiagnosticsGatewayID: "网关与隧道", guiDiagnosticsPeersID: "Gossip 节点", guiDiagnosticsLogID: "运行日志", guiDiagnosticsRoutesID: "Babel 路由详情", guiDiagnosticsAddressesID: "节点地址与通告", guiDiagnosticsDetailsID: "原始 JSON · 供进一步排查"}[v.page]
	w.setText(w.controls[guiDiagnosticsTitleID], title)
	for _, id := range []int{guiDiagnosticsOverviewID, guiDiagnosticsGatewayID, guiDiagnosticsLogID, guiDiagnosticsPeersID, guiDiagnosticsRoutesID, guiDiagnosticsAddressesID, guiDiagnosticsDetailsID} {
		kind := "body"
		if id == v.page {
			kind = "primary"
		}
		if w.appearance == nil || w.appearance.roles[w.controls[id]] != kind {
			w.guiStyleControl(w.controls[id], kind)
		}
	}
	pause := "暂停刷新"
	if v.paused {
		pause = "继续刷新"
	}
	w.setText(w.controls[guiDiagnosticsPauseID], pause)
}

func (w *desktopWindow) syncDiagnosticsPeerList() {
	v := w.diagnosticsView
	if v == nil {
		return
	}
	if v.page != guiDiagnosticsPeersID && v.page != guiDiagnosticsGatewayID {
		return
	}
	var ids, rows []string
	selection := v.peerID
	if desktopLiveSnapshot(v.snapshot) {
		if v.page == guiDiagnosticsGatewayID {
			ids, rows = []string{""}, []string{"连接总览"}
			gatewayIDs := desktopGatewayNodes(v.snapshot)
			slices.Reverse(gatewayIDs)
			for _, id := range gatewayIDs {
				ids = append(ids, id)
				rows = append(rows, desktopGatewayState(v.snapshot.Observation, id)+" · "+desktopDebugCell(id, 128))
			}
		} else {
			peers := slices.Clone(v.snapshot.Observation.Peers)
			slices.SortFunc(peers, func(a, b photonwindows.PeerObservation) int { return strings.Compare(b.Peer, a.Peer) })
			for _, peer := range peers {
				ids = append(ids, peer.Peer)
				rows = append(rows, desktopPeerRow(peer))
			}
		}
	}
	if v.page == guiDiagnosticsGatewayID {
		selection = v.gatewayID
	}
	selected := slices.Index(ids, selection)
	if selected < 0 && len(ids) > 0 {
		selected = 0
	}
	selection = ""
	if selected >= 0 {
		selection = ids[selected]
	}
	if v.page == guiDiagnosticsGatewayID {
		v.gatewayID = selection
	} else {
		v.peerID = selection
	}
	if v.listPage != v.page || !slices.Equal(rows, v.peerRows) || !slices.Equal(ids, v.peerIDs) {
		list := w.controls[guiDiagnosticsPeerListID]
		top, _, _ := guiSendMessage.Call(list, 0x018e, 0, 0) // LB_GETTOPINDEX
		topID := ""
		if v.listPage == v.page && top < uintptr(len(v.peerIDs)) {
			topID = v.peerIDs[top]
		}
		guiSendMessage.Call(list, 0x000b, 0, 0) // WM_SETREDRAW
		guiSendMessage.Call(list, 0x0184, 0, 0) // LB_RESETCONTENT
		for _, row := range rows {
			guiSendMessage.Call(list, 0x0180, 0, uintptr(unsafe.Pointer(guiUTF16(row))))
		}
		guiSendMessage.Call(list, 0x0186, uintptr(selected), 0)
		if index := slices.Index(ids, topID); index >= 0 {
			top = uintptr(index)
		}
		if len(rows) > 0 {
			guiSendMessage.Call(list, 0x0197, min(top, uintptr(len(rows)-1)), 0) // LB_SETTOPINDEX after selection.
		}
		guiSendMessage.Call(list, 0x000b, 1, 0)
		guiUser32.NewProc("RedrawWindow").Call(list, 0, 0, 0x405) // Invalidate client and frame.
		v.peerIDs, v.peerRows = ids, rows
		v.listPage = v.page
	}
	label, title := fmt.Sprintf("Gossip 节点（%d）", len(ids)), "请选择节点"
	if v.page == guiDiagnosticsGatewayID {
		label, title = fmt.Sprintf("网关节点（%d）", max(len(ids)-1, 0)), "连接总览"
	}
	if selection != "" {
		title = selection
	}
	w.setText(w.controls[guiDiagnosticsPeerTitleID], label)
	w.setText(w.controls[guiDiagnosticsNodeTitleID], title)
}

func guiBoundDiagnosticsText(text string, limit int) (string, bool) {
	units := 0
	for index, r := range text {
		size := 1
		if r > 0xffff {
			size = 2
		}
		if units+size > limit {
			return text[:index], true
		}
		units += size
	}
	return text, false
}

func (w *desktopWindow) diagnosticsWindowProc(hwnd uintptr, message uint32, wp, lp uintptr) uintptr {
	switch message {
	case guiWMClose:
		w.selectMainPage(0)
		return 0
	case guiWMDestroy:
		guiWindows.Delete(hwnd)
		w.diagnostics = 0
		return 0
	case guiWMSize:
		w.layoutDiagnostics()
		return 0
	case guiWMCommand:
		v := w.diagnosticsView
		if v == nil {
			return 0
		}
		id, notification := int(wp&0xffff), uint16(wp>>16)
		if notification == 1 && id == guiDiagnosticsPeerListID {
			selected, _, _ := guiSendMessage.Call(w.controls[id], 0x0188, 0, 0)
			if selected < uintptr(len(v.peerIDs)) {
				if v.page == guiDiagnosticsGatewayID {
					v.gatewayID = v.peerIDs[selected]
				} else {
					v.peerID = v.peerIDs[selected]
				}
				w.drawDiagnostics()
			}
			return 0
		}
		if notification == 1 && id == guiDiagnosticsLogFilterID {
			selected, _, _ := guiSendMessage.Call(w.controls[id], 0x0147, 0, 0)
			if selected < 4 {
				v.logFilter = int(selected)
				w.drawDiagnostics()
			}
			return 0
		}
		if notification != 0 {
			return 0
		}
		switch int(wp & 0xffff) {
		case guiDiagnosticsOverviewID, guiDiagnosticsGatewayID, guiDiagnosticsLogID, guiDiagnosticsPeersID, guiDiagnosticsRoutesID, guiDiagnosticsAddressesID, guiDiagnosticsDetailsID:
			v.page = int(wp & 0xffff)
			w.mainPage = v.page
			w.layout()
			if v.page == guiDiagnosticsRoutesID {
				v.route = routeKey{}
			}
			w.layoutDiagnostics()
			w.drawDiagnostics()
			if !v.paused {
				w.refreshDiagnostics()
			}
		case guiDiagnosticsRefreshID:
			w.refreshDiagnostics()
		case guiDiagnosticsPauseID:
			v.paused = !v.paused
			v.force = false
			w.drawDiagnostics()
			if !v.paused {
				w.refreshDiagnostics()
			}
		case guiDiagnosticsCopyID:
			text, err := guiControlText(w.controls[guiDiagnosticsTextID])
			if err == nil {
				err = guiCopyUnicodeText(hwnd, text, guiDiagnosticsTextLimit)
			}
			if err != nil {
				w.setText(w.controls[guiDiagnosticsMetadataID], "复制失败："+err.Error())
			}
		}
		return 0
	}
	result, _, _ := guiDefWindowProc.Call(hwnd, uintptr(message), wp, lp)
	return result
}

func (w *desktopWindow) layoutDiagnostics() {
	if w.diagnostics == 0 {
		return
	}
	width, height := w.guiClientSize(w.diagnostics)
	if width <= 0 || height <= 0 {
		return
	}
	advanced := w.diagnosticsView != nil && (w.diagnosticsView.page == guiDiagnosticsOverviewID || w.diagnosticsView.page == guiDiagnosticsAddressesID || w.diagnosticsView.page == guiDiagnosticsDetailsID)
	x := 24
	for _, id := range []int{guiDiagnosticsOverviewID, guiDiagnosticsGatewayID, guiDiagnosticsPeersID, guiDiagnosticsLogID, guiDiagnosticsRoutesID, guiDiagnosticsAddressesID, guiDiagnosticsDetailsID} {
		show := uintptr(0)
		if advanced && (id == guiDiagnosticsOverviewID || id == guiDiagnosticsAddressesID || id == guiDiagnosticsDetailsID) {
			show = 5
			w.guiMove(w.controls[id], x, 16, 112, 32)
			x += 120
		}
		guiShowWindow.Call(w.controls[id], show)
	}
	offset := 0
	if !advanced {
		offset = 38
	}
	w.guiMove(w.controls[guiDiagnosticsTitleID], 24, 66-offset, width-48, 34)
	w.guiMove(w.controls[guiDiagnosticsMetadataID], 24, 108-offset, width-48, 64)
	left, top, contentWidth := 24, 184-offset, width-48
	peerPage := w.diagnosticsView != nil && (w.diagnosticsView.page == guiDiagnosticsPeersID || w.diagnosticsView.page == guiDiagnosticsGatewayID)
	logPage := w.diagnosticsView != nil && w.diagnosticsView.page == guiDiagnosticsLogID
	showPeers, showLogs := uintptr(0), uintptr(0)
	if peerPage {
		showPeers = 5
		listWidth := min(300, max(220, (width-60)/3))
		w.guiMove(w.controls[guiDiagnosticsPeerTitleID], 24, 184-offset, listWidth, 24)
		w.guiMove(w.controls[guiDiagnosticsPeerListID], 24, 216-offset, listWidth, max(height-288+offset, 0))
		left += listWidth + 12
		contentWidth -= listWidth + 12
		w.guiMove(w.controls[guiDiagnosticsNodeTitleID], left, 184-offset, contentWidth, 24)
		top = 216 - offset
	}
	if logPage {
		showLogs = 5
		w.guiMove(w.controls[guiDiagnosticsLogFilterID], 24, 176-offset, 260, 220)
		top = 216 - offset
	}
	guiShowWindow.Call(w.controls[guiDiagnosticsPeerTitleID], showPeers)
	guiShowWindow.Call(w.controls[guiDiagnosticsPeerListID], showPeers)
	guiShowWindow.Call(w.controls[guiDiagnosticsNodeTitleID], showPeers)
	guiShowWindow.Call(w.controls[guiDiagnosticsLogFilterID], showLogs)
	w.guiMove(w.controls[guiDiagnosticsTextID], left, top, contentWidth, max(height-top-72, 0))
	w.guiMove(w.controls[guiDiagnosticsRefreshID], 24, height-48, 112, 32)
	w.guiMove(w.controls[guiDiagnosticsPauseID], 148, height-48, 128, 32)
	w.guiMove(w.controls[guiDiagnosticsCopyID], width-172, height-48, 148, 32)
	font := "body"
	if w.diagnosticsView != nil && (logPage || w.diagnosticsView.page == guiDiagnosticsDetailsID) {
		font = "mono"
	}
	w.guiApplyFont(w.controls[guiDiagnosticsTextID], font)
}
