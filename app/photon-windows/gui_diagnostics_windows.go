//go:build windows

package main

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
	"unsafe"
)

const (
	guiDiagnosticsLogID      = 2301
	guiDiagnosticsPeersID    = 2302
	guiDiagnosticsDetailsID  = 2303
	guiDiagnosticsTextID     = 2310
	guiDiagnosticsRefreshID  = 2311
	guiDiagnosticsPauseID    = 2312
	guiDiagnosticsCopyID     = 2313
	guiDiagnosticsMetadataID = 2314
	guiDiagnosticsTitleID    = 2315
	guiDiagnosticsTextLimit  = 1 << 20 // UTF-16 code units, including copied text.
)

// This is presentation state on the window thread. The existing backend and
// single worker remain the only runtime and I/O owners. Pausing retains this
// window's public view while the main window continues receiving snapshots.
type guiDiagnosticsView struct {
	page                    int
	paused, force           bool
	snapshot                desktopSnapshot
	tail                    desktopLogTail
	logErr                  error
	sampledAt, logSampledAt time.Time
}

func (w *desktopWindow) createDiagnosticsWindow() error {
	hwnd, _, err := guiCreateWindow.Call(0, uintptr(unsafe.Pointer(guiUTF16("PhotonWindowsDiagnostics"))), uintptr(unsafe.Pointer(guiUTF16("Photon Windows · 日志与诊断"))), 0x00cf0000|0x02000000, 0x80000000, 0x80000000, uintptr(w.guiScale(940)), uintptr(w.guiScale(720)), w.hwnd, 0, w.instance, 0)
	if hwnd == 0 {
		return guiCallError("CreateWindowEx diagnostics", err)
	}
	w.diagnostics = hwnd
	w.diagnosticsView = &guiDiagnosticsView{page: guiDiagnosticsLogID}
	guiWindows.Store(hwnd, w)
	for _, spec := range []struct {
		id                int
		class, text, role string
		style, ex         uintptr
	}{
		{guiDiagnosticsLogID, "BUTTON", "日志", "primary", 0x50010000, 0},
		{guiDiagnosticsPeersID, "BUTTON", "Gossip / Peer", "body", 0x50010000, 0},
		{guiDiagnosticsDetailsID, "BUTTON", "诊断详情", "body", 0x50010000, 0},
		{guiDiagnosticsTitleID, "STATIC", "日志与诊断", "title", 0x50000000, 0},
		{guiDiagnosticsMetadataID, "STATIC", "等待读取当前 Photon 的公开诊断…", "muted", 0x50000000, 0},
		{guiDiagnosticsTextID, "EDIT", "", "edit", 0x50010000 | 0x0004 | 0x0040 | 0x0080 | 0x0800 | 0x00200000 | 0x00100000, 0x200},
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
	guiShowWindow.Call(w.diagnostics, 9)
	guiShowWindow.Call(w.diagnostics, 5)
	guiSetForegroundWindow.Call(w.diagnostics)
	w.drawDiagnostics()
	w.refreshDiagnostics()
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
	switch v.page {
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
			text = v.tail.Text
			if text == "" {
				text = "日志文件当前为空。"
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
		text = desktopFormatPeers(v.snapshot)
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
	lines := 0
	if bounded != "" {
		lines = strings.Count(strings.TrimRight(bounded, "\r\n"), "\n") + 1
	}
	metadata := fmt.Sprintf("来源：%s\r\n采样：%s · %s · 显示 %d 字符 / %d 行", source, stamp, mode, utf8.RuneCountInString(bounded), lines)
	if detail != "" {
		metadata += "\r\n" + detail
	}
	contentChanged := w.textCache[w.controls[guiDiagnosticsTextID]] != bounded
	w.setText(w.controls[guiDiagnosticsTextID], bounded)
	if contentChanged && v.page == guiDiagnosticsLogID {
		// A log tail opens on its newest records. Pause keeps this buffer and
		// its scroll position stable while the user reads or selects text.
		length, _, _ := guiGetWindowTextLength.Call(w.controls[guiDiagnosticsTextID])
		guiSendMessage.Call(w.controls[guiDiagnosticsTextID], 0xb1, length, length) // EM_SETSEL at the actual text end.
		guiSendMessage.Call(w.controls[guiDiagnosticsTextID], 0xb7, 0, 0)           // EM_SCROLLCARET
	}
	w.setText(w.controls[guiDiagnosticsMetadataID], metadata)
	for _, id := range []int{guiDiagnosticsLogID, guiDiagnosticsPeersID, guiDiagnosticsDetailsID} {
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
		guiShowWindow.Call(hwnd, 0)
		return 0
	case guiWMDestroy:
		guiWindows.Delete(hwnd)
		w.diagnostics = 0
		return 0
	case guiWMSize:
		w.layoutDiagnostics()
		return 0
	case guiWMCommand:
		if uint16(wp>>16) != 0 {
			return 0
		}
		v := w.diagnosticsView
		if v == nil {
			return 0
		}
		switch int(wp & 0xffff) {
		case guiDiagnosticsLogID, guiDiagnosticsPeersID, guiDiagnosticsDetailsID:
			v.page = int(wp & 0xffff)
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
	for col, id := range []int{guiDiagnosticsLogID, guiDiagnosticsPeersID, guiDiagnosticsDetailsID} {
		w.guiMove(w.controls[id], 24+col*164, 16, 152, 32)
	}
	w.guiMove(w.controls[guiDiagnosticsTitleID], 24, 66, width-48, 34)
	w.guiMove(w.controls[guiDiagnosticsMetadataID], 24, 112, width-48, 88)
	w.guiMove(w.controls[guiDiagnosticsTextID], 24, 212, width-48, max(height-284, 0))
	w.guiMove(w.controls[guiDiagnosticsRefreshID], 24, height-48, 112, 32)
	w.guiMove(w.controls[guiDiagnosticsPauseID], 148, height-48, 128, 32)
	w.guiMove(w.controls[guiDiagnosticsCopyID], width-172, height-48, 148, 32)
}
