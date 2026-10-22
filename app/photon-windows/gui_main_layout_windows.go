//go:build windows

package main

import (
	"strings"
	"unsafe"
)

const guiMainDefaultNote = "保存后需重新连接生效；关闭窗口隐藏到托盘，退出 Photon 会停止连接。"

func (w *desktopWindow) createMainControls() error {
	static := uint32(0x50000000)
	button := uint32(0x50010000)
	routes := uint32(0x50010000 | 0x0004 | 0x0040 | 0x0080 | 0x0800 | 0x00200000 | 0x00100000)
	// Wrap details and retain a vertical scrollbar so full diagnostics remain
	// selectable and readable without expanding the connection title.
	details := uint32(0x50010000 | 0x0004 | 0x0040 | 0x0800 | 0x00200000)
	specs := []struct {
		id             int
		class, text    string
		style, exStyle uint32
		kind           string
	}{
		{guiStatusID, "STATIC", "连接：读取中…", static, 0, "title"},
		{guiRuntimeID, "STATIC", "运行状态：读取中…", static, 0, "muted"},
		{guiStartID, "BUTTON", "启动连接", button, 0, "primary"},
		{guiStopID, "BUTTON", "停止连接", button, 0, "body"},
		{guiRestartID, "BUTTON", "重新连接", button, 0, "body"},
		{guiGatewayID, "STATIC", "活动网关：—", static, 0, "section"},
		{guiAdmissionID, "STATIC", "入网：读取中…", static, 0, "body"},
		{guiJoinRequestID, "EDIT", "", 0x50010000 | 0x0080 | 0x0800, 0x200, "mono"},
		{guiCopyRequestID, "BUTTON", "复制入网请求", button, 0, "body"},
		{guiRoutesID, "EDIT", "尚无实时路由", routes, 0x200, "mono"},
		{guiConfigSummaryID, "STATIC", "设置正在读取…", static, 0, "body"},
		{guiSettingsID, "BUTTON", "打开设置", button, 0, "body"},
		{guiDiagnosticsID, "BUTTON", "日志与诊断", button, 0, "body"},
		{guiNoteID, "EDIT", guiMainDefaultNote, details, 0x200, "edit"},
	}
	for _, spec := range specs {
		hwnd, _, err := guiCreateWindow.Call(uintptr(spec.exStyle), uintptr(unsafe.Pointer(guiUTF16(spec.class))), uintptr(unsafe.Pointer(guiUTF16(spec.text))), uintptr(spec.style), 0, 0, 0, 0, w.hwnd, uintptr(spec.id), w.instance, 0)
		if hwnd == 0 {
			return guiCallError("CreateWindowEx "+spec.class, err)
		}
		w.controls[spec.id] = hwnd
		w.guiStyleControl(hwnd, spec.kind)
	}
	for index, text := range []string{"实时 Babel 路由（目标 / 来源前缀 / origin / metric）", "配置文件 · " + w.backend.options.ConfigPath} {
		hwnd, _, err := guiCreateWindow.Call(0, uintptr(unsafe.Pointer(guiUTF16("STATIC"))), uintptr(unsafe.Pointer(guiUTF16(text))), uintptr(static), 0, 0, 0, 0, w.hwnd, 0, w.instance, 0)
		if hwnd == 0 {
			return guiCallError("CreateWindowEx label", err)
		}
		w.labels[index] = hwnd
		kind := "section"
		if index == 1 {
			kind = "muted"
		}
		w.guiStyleControl(hwnd, kind)
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
}

func (w *desktopWindow) layout() {
	width, height := w.guiClientSize(w.hwnd)
	if width <= 0 || height <= 0 {
		return
	}
	contentWidth := width - 48
	w.guiMove(w.controls[guiStatusID], 24, 20, contentWidth, 38)
	w.guiMove(w.controls[guiRuntimeID], 24, 62, contentWidth, 22)
	for column, id := range []int{guiStartID, guiStopID, guiRestartID} {
		w.guiMove(w.controls[id], 24+column*140, 96, 128, 34)
	}
	w.guiMove(w.controls[guiGatewayID], 24, 142, contentWidth, 24)
	admissionHeight, routesTop := 66, 254
	if w.admission.Pending {
		admissionHeight, routesTop = 44, 260
	}
	w.guiMove(w.controls[guiAdmissionID], 24, 172, contentWidth, admissionHeight)
	w.guiMove(w.controls[guiJoinRequestID], 24, 224, contentWidth-164, 30)
	w.guiMove(w.controls[guiCopyRequestID], width-176, 224, 152, 30)
	w.guiMove(w.labels[0], 24, routesTop, contentWidth, 22)
	// Keep the footer compact and anchored; all additional height goes to the
	// route viewport, including when the admission request is visible.
	noteTop := height - 88
	settingsTop := noteTop - 40
	summaryTop := settingsTop - 72
	configLabelTop := summaryTop - 24
	routesY := routesTop + 26
	w.guiMove(w.controls[guiRoutesID], 24, routesY, contentWidth, max(0, configLabelTop-6-routesY))
	w.guiMove(w.labels[1], 24, configLabelTop, contentWidth, 22)
	w.guiMove(w.controls[guiConfigSummaryID], 24, summaryTop, contentWidth, 64)
	w.guiMove(w.controls[guiSettingsID], 24, settingsTop, 136, 32)
	w.guiMove(w.controls[guiDiagnosticsID], 172, settingsTop, 152, 32)
	w.guiMove(w.controls[guiNoteID], 24, noteTop, contentWidth, 64)
}
