//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"unsafe"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	"golang.org/x/sys/windows"
)

const (
	guiStatusID             = 1001
	guiRuntimeID            = 1002
	guiGatewayID            = 1003
	guiRoutesID             = 1004
	guiNoteID               = 1006
	guiAdmissionID          = 1007
	guiJoinRequestID        = 1008
	guiStartID              = 1102
	guiStopID               = 1103
	guiRestartID            = 1104
	guiSaveID               = 1105
	guiReloadID             = 1106
	guiCopyRequestID        = 1107
	guiSettingsID           = 1110
	guiConfigSummaryID      = 1009
	guiOpenID               = 1201
	guiTrayStartID          = 1202
	guiTrayStopID           = 1203
	guiExitID               = 1204
	guiResultMessage        = 0x8001
	guiTrayMessage          = 0x8002
	guiWMClose              = 0x0010
	guiWMDestroy            = 0x0002
	guiWMCommand            = 0x0111
	guiWMTimer              = 0x0113
	guiWMSize               = 0x0005
	guiWMGetMinMaxInfo      = 0x0024
	guiWMLButtonUp          = 0x0202
	guiWMLButtonDoubleClick = 0x0203
	guiWMRButtonUp          = 0x0205
)

var (
	guiUser32                = windows.NewLazySystemDLL("user32.dll")
	guiKernel32              = windows.NewLazySystemDLL("kernel32.dll")
	guiGDI32                 = windows.NewLazySystemDLL("gdi32.dll")
	guiShell32               = windows.NewLazySystemDLL("shell32.dll")
	guiRegisterClass         = guiUser32.NewProc("RegisterClassExW")
	guiCreateWindow          = guiUser32.NewProc("CreateWindowExW")
	guiDefWindowProc         = guiUser32.NewProc("DefWindowProcW")
	guiDestroyWindow         = guiUser32.NewProc("DestroyWindow")
	guiShowWindow            = guiUser32.NewProc("ShowWindow")
	guiUpdateWindow          = guiUser32.NewProc("UpdateWindow")
	guiGetMessage            = guiUser32.NewProc("GetMessageW")
	guiTranslateMessage      = guiUser32.NewProc("TranslateMessage")
	guiDispatchMessage       = guiUser32.NewProc("DispatchMessageW")
	guiIsDialogMessage       = guiUser32.NewProc("IsDialogMessageW")
	guiPostMessage           = guiUser32.NewProc("PostMessageW")
	guiPostQuitMessage       = guiUser32.NewProc("PostQuitMessage")
	guiSendMessage           = guiUser32.NewProc("SendMessageW")
	guiSetWindowText         = guiUser32.NewProc("SetWindowTextW")
	guiGetWindowText         = guiUser32.NewProc("GetWindowTextW")
	guiGetWindowTextLength   = guiUser32.NewProc("GetWindowTextLengthW")
	guiEnableWindow          = guiUser32.NewProc("EnableWindow")
	guiMoveWindow            = guiUser32.NewProc("MoveWindow")
	guiGetClientRect         = guiUser32.NewProc("GetClientRect")
	guiSetTimer              = guiUser32.NewProc("SetTimer")
	guiKillTimer             = guiUser32.NewProc("KillTimer")
	guiLoadIcon              = guiUser32.NewProc("LoadIconW")
	guiLoadCursor            = guiUser32.NewProc("LoadCursorW")
	guiCreatePopupMenu       = guiUser32.NewProc("CreatePopupMenu")
	guiAppendMenu            = guiUser32.NewProc("AppendMenuW")
	guiDestroyMenu           = guiUser32.NewProc("DestroyMenu")
	guiEnableMenuItem        = guiUser32.NewProc("EnableMenuItem")
	guiGetCursorPos          = guiUser32.NewProc("GetCursorPos")
	guiTrackPopupMenu        = guiUser32.NewProc("TrackPopupMenu")
	guiSetForegroundWindow   = guiUser32.NewProc("SetForegroundWindow")
	guiRegisterWindowMessage = guiUser32.NewProc("RegisterWindowMessageW")
	guiCreateFont            = guiGDI32.NewProc("CreateFontW")
	guiDeleteObject          = guiGDI32.NewProc("DeleteObject")
	guiShellNotifyIcon       = guiShell32.NewProc("Shell_NotifyIconW")
	guiGetModuleHandle       = guiKernel32.NewProc("GetModuleHandleW")
	guiFreeConsole           = guiKernel32.NewProc("FreeConsole")
	guiMoveMemory            = guiKernel32.NewProc("RtlMoveMemory")
	guiGlobalAlloc           = guiKernel32.NewProc("GlobalAlloc")
	guiGlobalLock            = guiKernel32.NewProc("GlobalLock")
	guiGlobalUnlock          = guiKernel32.NewProc("GlobalUnlock")
	guiGlobalFree            = guiKernel32.NewProc("GlobalFree")
	guiOpenClipboard         = guiUser32.NewProc("OpenClipboard")
	guiCloseClipboard        = guiUser32.NewProc("CloseClipboard")
	guiEmptyClipboard        = guiUser32.NewProc("EmptyClipboard")
	guiSetClipboardData      = guiUser32.NewProc("SetClipboardData")
	guiWindows               sync.Map // HWND -> *desktopWindow; owned by the window thread.
	guiRegisterOnce          sync.Once
	guiRegisterError         error
	guiWindowProc            = windows.NewCallback(desktopWindowProc)
)

type guiPoint struct{ X, Y int32 }
type guiRect struct{ Left, Top, Right, Bottom int32 }
type guiMessage struct {
	Window         uintptr
	Message        uint32
	WParam, LParam uintptr
	Time           uint32
	Point          guiPoint
	Private        uint32
}
type guiWindowClass struct {
	Size, Style                        uint32
	WindowProc                         uintptr
	ClassExtra, WindowExtra            int32
	Instance, Icon, Cursor, Background uintptr
	MenuName, ClassName                *uint16
	SmallIcon                          uintptr
}
type guiNotifyIcon struct {
	Size                uint32
	Window              uintptr
	ID, Flags, Callback uint32
	Icon                uintptr
	Tip                 [128]uint16
	State, StateMask    uint32
	Info                [256]uint16
	TimeoutOrVersion    uint32
	InfoTitle           [64]uint16
	InfoFlags           uint32
	GUID                windows.GUID
	BalloonIcon         uintptr
}
type guiRequest struct {
	Action       string
	Form         desktopConfigForm
	EditRevision uint64
}
type guiResult struct {
	Action       string
	Form         desktopConfigForm
	EditRevision uint64
	Err          error
	Snapshot     desktopSnapshot
}
type desktopWindow struct {
	hwnd, font, menu, icon     uintptr
	controls                   map[int]uintptr
	labels                     [2]uintptr
	instance                   uintptr
	taskbarCreated             uint32
	tray                       bool
	busy, settingConfig, dirty bool
	quitting, quitSubmitted    bool
	editRevision               uint64
	settings                   uintptr
	settingsPage               int
	formLabels                 map[int]uintptr
	formLoaded                 bool
	newConfig                  bool
	formLoadError              string
	optionLists                map[int]*guiOptionList
	bootstrapRows              []desktopBootstrapRow
	bootstrapSelected          int
	bootstrapDirty             bool
	ctx                        context.Context
	cancel                     context.CancelFunc
	requests                   chan guiRequest
	results                    chan guiResult
	worker                     sync.WaitGroup
	postMu                     sync.Mutex // Serializes cancellation and native HWND posting.
	backend                    *desktopBackend
	snapshot                   desktopSnapshot
	admission                  desktopAdmissionView
	textCache                  map[uintptr]string
}

func guiUTF16(s string) *uint16 {
	// Display text may originate in diagnostics; embedded NUL must not panic.
	p, _ := windows.UTF16PtrFromString(strings.ReplaceAll(s, "\x00", "�"))
	return p
}
func guiCallError(operation string, err error) error {
	if err == nil || errors.Is(err, windows.ERROR_SUCCESS) {
		return fmt.Errorf("%s failed", operation)
	}
	return fmt.Errorf("%s: %w", operation, err)
}

func runDesktop(options desktopOptions) (err error) {
	// The tray owns its runtime in this process; closing the visible window
	// keeps that runtime alive, while explicit Quit stops and joins it.
	guiFreeConsole.Call()
	defer func() {
		if err != nil {
			windows.MessageBox(0, guiUTF16(err.Error()), guiUTF16("Photon Windows"), windows.MB_OK|windows.MB_ICONERROR)
		}
	}()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	guiUser32.NewProc("SetProcessDPIAware").Call()
	backend, err := newDesktopBackend(options)
	if err != nil {
		return err
	}
	window, err := newDesktopWindow(backend)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, window.dispose()) }()
	window.startWorker()
	window.submit(guiRequest{Action: "load"})
	guiShowWindow.Call(window.hwnd, 5)
	guiUpdateWindow.Call(window.hwnd)
	var message guiMessage
	for {
		result, _, callErr := guiGetMessage.Call(uintptr(unsafe.Pointer(&message)), 0, 0, 0)
		if int32(result) == -1 {
			return guiCallError("GetMessage", callErr)
		}
		if result == 0 {
			return nil
		}
		dialog := window.hwnd
		if window.settings != 0 {
			child, _, _ := guiUser32.NewProc("IsChild").Call(window.settings, message.Window)
			if message.Window == window.settings || child != 0 {
				dialog = window.settings
			}
		}
		handled, _, _ := guiIsDialogMessage.Call(dialog, uintptr(unsafe.Pointer(&message)))
		if handled == 0 {
			guiTranslateMessage.Call(uintptr(unsafe.Pointer(&message)))
			guiDispatchMessage.Call(uintptr(unsafe.Pointer(&message)))
		}
	}
}

func newDesktopWindow(backend *desktopBackend) (_ *desktopWindow, err error) {
	instance, _, callErr := guiGetModuleHandle.Call(0)
	if instance == 0 {
		return nil, guiCallError("GetModuleHandle", callErr)
	}
	icon, _, _ := guiLoadIcon.Call(0, 32512) // Shared IDI_APPLICATION; do not destroy.
	guiRegisterOnce.Do(func() {
		cursor, _, _ := guiLoadCursor.Call(0, 32512)
		for _, name := range []string{"PhotonWindowsDesktop", "PhotonWindowsSettings"} {
			class := guiWindowClass{Style: 8, WindowProc: guiWindowProc, Instance: instance, Icon: icon, SmallIcon: icon, Cursor: cursor, Background: 16, ClassName: guiUTF16(name)}
			class.Size = uint32(unsafe.Sizeof(class))
			atom, _, e := guiRegisterClass.Call(uintptr(unsafe.Pointer(&class)))
			if atom == 0 {
				guiRegisterError = guiCallError("RegisterClassEx", e)
				return
			}
		}
	})
	if guiRegisterError != nil {
		return nil, guiRegisterError
	}
	ctx, cancel := context.WithCancel(context.Background())
	w := &desktopWindow{instance: instance, icon: icon, backend: backend, controls: make(map[int]uintptr), ctx: ctx, cancel: cancel, requests: make(chan guiRequest, 1), results: make(chan guiResult, 1), textCache: make(map[uintptr]string), bootstrapSelected: -1}
	defer func() {
		if err != nil {
			err = errors.Join(err, w.dispose())
		}
	}()
	w.hwnd, _, callErr = guiCreateWindow.Call(0, uintptr(unsafe.Pointer(guiUTF16("PhotonWindowsDesktop"))), uintptr(unsafe.Pointer(guiUTF16("Photon Windows"))), 0x00cf0000|0x02000000, 0x80000000, 0x80000000, 920, 760, 0, 0, instance, 0)
	if w.hwnd == 0 {
		return nil, guiCallError("CreateWindowEx", callErr)
	}
	guiWindows.Store(w.hwnd, w)
	// An owned font is deleted only after all child controls are destroyed.
	height := int32(-16)
	w.font, _, callErr = guiCreateFont.Call(uintptr(height), 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 5, 0, uintptr(unsafe.Pointer(guiUTF16("Microsoft YaHei UI"))))
	if w.font == 0 {
		return nil, guiCallError("CreateFont", callErr)
	}
	static := uint32(0x50000000)
	button := uint32(0x50010000)
	edit := uint32(0x50010000 | 0x0004 | 0x0040 | 0x0080 | 0x1000 | 0x00200000 | 0x00100000)
	specs := []struct {
		id             int
		class, text    string
		style, exStyle uint32
	}{
		{guiStatusID, "STATIC", "连接：读取中…", static, 0},
		{guiRuntimeID, "STATIC", "运行状态：读取中…", static, 0},
		{guiGatewayID, "STATIC", "活动网关：—", static, 0},
		{guiStartID, "BUTTON", "启动连接", button, 0},
		{guiStopID, "BUTTON", "停止连接", button, 0},
		{guiRestartID, "BUTTON", "重新连接", button, 0},
		{guiAdmissionID, "STATIC", "入网：读取中…", static, 0},
		{guiJoinRequestID, "EDIT", "", 0x50010000 | 0x0080 | 0x0800, 0x200},
		{guiCopyRequestID, "BUTTON", "复制入网请求", button, 0},
		{guiRoutesID, "EDIT", "尚无实时路由", edit | 0x0800, 0x200},
		{guiConfigSummaryID, "STATIC", "设置正在读取…", static, 0},
		{guiSettingsID, "BUTTON", "打开设置", button, 0},
		{guiNoteID, "STATIC", "保存后需重新连接生效；关闭窗口隐藏到托盘，退出 Photon 会停止连接。", static, 0},
	}
	for _, spec := range specs {
		hwnd, _, e := guiCreateWindow.Call(uintptr(spec.exStyle), uintptr(unsafe.Pointer(guiUTF16(spec.class))), uintptr(unsafe.Pointer(guiUTF16(spec.text))), uintptr(spec.style), 0, 0, 0, 0, w.hwnd, uintptr(spec.id), instance, 0)
		if hwnd == 0 {
			return nil, guiCallError("CreateWindowEx "+spec.class, e)
		}
		w.controls[spec.id] = hwnd
		guiSendMessage.Call(hwnd, 0x0030, w.font, 1) // WM_SETFONT
	}
	for i, text := range []string{"实时 Babel 路由（目标 / 来源前缀 / origin / metric）", "配置文件 · " + backend.options.ConfigPath} {
		hwnd, _, e := guiCreateWindow.Call(0, uintptr(unsafe.Pointer(guiUTF16("STATIC"))), uintptr(unsafe.Pointer(guiUTF16(text))), uintptr(static), 0, 0, 0, 0, w.hwnd, 0, instance, 0)
		if hwnd == 0 {
			return nil, guiCallError("CreateWindowEx label", e)
		}
		w.labels[i] = hwnd
		guiSendMessage.Call(hwnd, 0x0030, w.font, 1)
	}
	if err := w.createSettingsWindow(); err != nil {
		return nil, err
	}
	guiSendMessage.Call(w.controls[guiRoutesID], 0x00c5, 1<<20, 0)
	guiSendMessage.Call(w.controls[guiJoinRequestID], 0x00c5, desktopJoinRequestLimit, 0)
	guiShowWindow.Call(w.controls[guiJoinRequestID], 0)
	guiShowWindow.Call(w.controls[guiCopyRequestID], 0)
	guiEnableWindow.Call(w.controls[guiCopyRequestID], 0)
	w.menu, _, callErr = guiCreatePopupMenu.Call()
	if w.menu == 0 {
		return nil, guiCallError("CreatePopupMenu", callErr)
	}
	for _, item := range []struct {
		id   int
		text string
	}{{guiOpenID, "打开 Photon"}, {guiTrayStartID, "启动连接"}, {guiTrayStopID, "停止连接"}, {guiExitID, "停止连接并退出 Photon"}} {
		ok, _, e := guiAppendMenu.Call(w.menu, 0, uintptr(item.id), uintptr(unsafe.Pointer(guiUTF16(item.text))))
		if ok == 0 {
			return nil, guiCallError("AppendMenu", e)
		}
	}
	registered, _, callErr := guiRegisterWindowMessage.Call(uintptr(unsafe.Pointer(guiUTF16("TaskbarCreated"))))
	if registered == 0 {
		return nil, guiCallError("RegisterWindowMessage", callErr)
	}
	w.taskbarCreated = uint32(registered)
	w.updateTray(true)
	timer, _, callErr := guiSetTimer.Call(w.hwnd, 1, 2000, 0)
	if timer == 0 {
		return nil, guiCallError("SetTimer", callErr)
	}
	w.layout()
	return w, nil
}

func (w *desktopWindow) startWorker() {
	w.worker.Add(1)
	go func() {
		defer w.worker.Done()
		for {
			select {
			case <-w.ctx.Done():
				return
			case request := <-w.requests:
				if w.ctx.Err() != nil {
					return
				}
				result := guiResult{Action: request.Action, EditRevision: request.EditRevision}
				switch request.Action {
				case "load":
					result.Form, result.Err = w.backend.LoadForm()
				case "save":
					result.Err = w.backend.SaveForm(request.Form)
				case "refresh":
				case "quit":
					result.Err = w.backend.Close()
				default:
					result.Err = w.backend.Runtime(request.Action)
				}
				if w.ctx.Err() != nil {
					return
				}
				// A quit result is sent only after the owned runtime has joined.
				if request.Action != "quit" {
					result.Snapshot = w.backend.Snapshot(w.ctx)
				}
				w.postMu.Lock()
				if w.ctx.Err() == nil {
					// One request is admitted until the UI consumes its result.
					// Never block the native owner while holding this mutex.
					select {
					case w.results <- result:
						guiPostMessage.Call(w.hwnd, guiResultMessage, 0, 0)
					default:
					}
				}
				w.postMu.Unlock()
			}
		}
	}()
}

func (w *desktopWindow) dispose() error {
	w.postMu.Lock()
	w.cancel()
	w.postMu.Unlock()
	w.worker.Wait()
	// Also cover GetMessage failure or unexpected window destruction. Normal
	// Quit already joined the runtime on the worker before reaching disposal.
	cleanupErr := w.backend.Close()
	if w.settings != 0 {
		guiDestroyWindow.Call(w.settings)
	}
	if w.hwnd != 0 {
		guiKillTimer.Call(w.hwnd, 1)
		if w.tray {
			data := w.notifyData()
			guiShellNotifyIcon.Call(2, uintptr(unsafe.Pointer(&data)))
			w.tray = false
		}
		// DestroyWindow is harmless if WM_DESTROY already removed the handle.
		if _, exists := guiWindows.Load(w.hwnd); exists {
			guiDestroyWindow.Call(w.hwnd)
		}
		guiWindows.Delete(w.hwnd)
	}
	if w.menu != 0 {
		guiDestroyMenu.Call(w.menu)
		w.menu = 0
	}
	if w.font != 0 {
		guiDeleteObject.Call(w.font)
		w.font = 0
	}
	return cleanupErr
}

func desktopWindowProc(hwnd uintptr, message uint32, wp, lp uintptr) uintptr {
	value, exists := guiWindows.Load(hwnd)
	if exists {
		w := value.(*desktopWindow)
		if hwnd == w.settings {
			return w.settingsWindowProc(hwnd, message, wp, lp)
		}
		if message == w.taskbarCreated && w.taskbarCreated != 0 {
			w.tray = false
			w.updateTray(true)
			if !w.tray {
				w.show()
				w.note("系统托盘暂不可用，窗口保持打开。退出 Photon 会停止连接。")
			}
			return 0
		}
		switch message {
		case guiWMSize:
			w.layout()
			return 0
		case guiWMGetMinMaxInfo:
			if lp != 0 {
				minimum := guiPoint{700, 620}
				// LPARAM is native MINMAXINFO storage, not a Go pointer. Its
				// fourth POINT is ptMinTrackSize. Copy only those two LONGs
				// through the native API without reinterpreting its address.
				guiMoveMemory.Call(lp+3*unsafe.Sizeof(minimum), uintptr(unsafe.Pointer(&minimum)), unsafe.Sizeof(minimum))
			}
			return 0
		case guiWMCommand:
			id, notification := int(wp&0xffff), uint16(wp>>16)
			if notification == 0 {
				w.command(id)
			}
			return 0
		case guiWMTimer:
			if wp == 1 {
				// Recover if Windows could not queue the WM_APP notification.
				select {
				case result := <-w.results:
					w.applyResult(result)
				default:
				}
				w.submit(guiRequest{Action: "refresh"})
			}
			return 0
		case guiResultMessage:
			select {
			case result := <-w.results:
				w.applyResult(result)
			default:
			}
			return 0
		case guiTrayMessage:
			switch uint32(lp) {
			case guiWMLButtonUp, guiWMLButtonDoubleClick:
				w.show()
			case guiWMRButtonUp:
				w.popup()
			}
			return 0
		case guiWMClose:
			if w.tray {
				if w.settings != 0 {
					guiShowWindow.Call(w.settings, 0)
				}
				guiShowWindow.Call(hwnd, 0)
			} else {
				w.quit()
			}
			return 0
		case guiWMDestroy:
			w.postMu.Lock()
			w.cancel()
			w.postMu.Unlock()
			w.admission = desktopAdmissionView{}
			guiKillTimer.Call(hwnd, 1)
			if w.tray {
				data := w.notifyData()
				guiShellNotifyIcon.Call(2, uintptr(unsafe.Pointer(&data)))
				w.tray = false
			}
			guiWindows.Delete(hwnd)
			guiPostQuitMessage.Call(0)
			return 0
		}
	}
	result, _, _ := guiDefWindowProc.Call(hwnd, uintptr(message), wp, lp)
	return result
}

func (w *desktopWindow) submit(request guiRequest) {
	if w.busy || w.ctx.Err() != nil || (w.quitting && request.Action != "quit") {
		return
	}
	if request.Action == "load" {
		request.EditRevision = w.editRevision
	}
	select {
	case w.requests <- request:
		w.busy = true
		if request.Action == "stop" || request.Action == "restart" {
			w.admission.Request = ""
			w.setText(w.controls[guiJoinRequestID], "")
			guiEnableWindow.Call(w.controls[guiCopyRequestID], 0)
		}
		if request.Action == "load" {
			w.enableForm(false)
		}
		for _, id := range []int{guiStartID, guiStopID, guiRestartID, guiSaveID, guiReloadID} {
			guiEnableWindow.Call(w.controls[id], 0)
		}
		if request.Action != "refresh" {
			w.note("正在处理…")
		}
	default:
	}
}
func (w *desktopWindow) command(id int) {
	if id == guiSettingsID {
		if !w.quitting {
			w.openSettings()
		}
		return
	}
	if id == guiOpenID {
		w.show()
		return
	}
	if id == guiExitID {
		w.quit()
		return
	}
	if id == guiCopyRequestID {
		if w.quitting || !w.admission.Pending || w.admission.Request == "" {
			return
		}
		if err := guiCopyPublicRequest(w.hwnd, w.admission.Request); err != nil {
			w.note("复制入网请求失败：" + err.Error())
		} else {
			w.note("完整入网请求已复制；请提交给上级管理员授权。")
		}
		return
	}
	if w.busy || w.quitting {
		return
	}
	request := guiRequest{}
	switch id {
	case guiStartID, guiTrayStartID:
		if w.guideNewConfig() {
			return
		}
		request.Action = "start"
	case guiStopID, guiTrayStopID:
		request.Action = "stop"
	case guiRestartID:
		if w.guideNewConfig() {
			return
		}
		request.Action = "restart"
	case guiSaveID:
		if !w.formLoaded {
			w.note("无法保存：" + w.formLoadError + "。请检查上方配置文件路径及访问权限，然后点击“重新读取”重试。")
			return
		}
		if draft := w.unappliedDraft(); draft != "" {
			w.note(draft + "输入尚未添加或更新，请在对应页面应用该条目或清除输入后保存。")
			return
		}
		request.Action = "save"
		form, err := w.collectForm()
		if err != nil {
			w.note(err.Error())
			return
		}
		request.Form, request.EditRevision = form, w.editRevision
	case guiReloadID:
		if w.dirty {
			answer, _ := windows.MessageBox(windows.HWND(w.settings), guiUTF16("重新读取会丢弃尚未保存的设置。继续吗？"), guiUTF16("Photon Windows"), windows.MB_YESNO|windows.MB_ICONQUESTION)
			if answer != 6 {
				return
			}
		}
		request.Action = "load"
	default:
		return
	}
	w.submit(request)
}
func (w *desktopWindow) applyResult(result guiResult) {
	w.busy = false
	if result.Action == "quit" {
		if result.Err != nil {
			w.quitting, w.quitSubmitted = false, false
			w.enableForm(true)
			for _, id := range []int{guiStartID, guiStopID, guiRestartID, guiReloadID, guiSettingsID} {
				guiEnableWindow.Call(w.controls[id], 1)
			}
			if w.formLoaded {
				guiEnableWindow.Call(w.controls[guiSaveID], 1)
			}
			w.show()
			w.note("停止连接失败：" + result.Err.Error() + "。请重试“停止连接并退出 Photon”。")
			return
		}
		// Close succeeded only after the owned runtime joined.
		guiDestroyWindow.Call(w.hwnd)
		return
	}
	if w.quitting {
		w.submitQuit()
		return
	}
	if result.Action == "load" {
		w.enableForm(true)
		w.formLoaded = result.Err == nil
		w.formLoadError = ""
		if result.Err != nil {
			w.formLoadError = result.Err.Error()
			w.newConfig = false
		}
	}
	for _, id := range []int{guiStartID, guiStopID, guiRestartID, guiSaveID, guiReloadID} {
		guiEnableWindow.Call(w.controls[id], 1)
	}
	loadChanged := result.Action == "load" && result.EditRevision != w.editRevision
	if result.Action == "load" && !loadChanged && result.Err == nil {
		w.fillForm(result.Form)
		w.newConfig = result.Form.NewConfig
		w.dirty = false
		w.editRevision++
	}
	if result.Err != nil {
		w.note("操作失败：" + result.Err.Error())
	} else {
		switch result.Action {
		case "save":
			w.newConfig = false
			if result.EditRevision == w.editRevision {
				w.dirty = false
			}
			w.note("配置已保存；点击“重新连接”后生效。")
		case "load":
			if w.newConfig {
				w.showSettingsPage(guiBasicPageID)
				w.openSettings()
				w.note("首次使用：先填写身份、网关与路由，然后保存配置。")
			} else {
				w.note("配置已读取。保存后需重新连接生效；退出 Photon 会停止连接。")
			}
		case "start":
			w.note("连接已启动，正在读取实时状态。")
		case "stop":
			w.note("连接已停止。")
		case "restart":
			w.note("已重新连接，保存的配置已应用。")
		}
	}
	if loadChanged {
		w.note("已保留读取期间的新编辑；如需丢弃编辑，请再次点击“重新读取”。")
	}
	if !w.formLoaded {
		guiEnableWindow.Call(w.controls[guiSaveID], 0)
	}
	w.updateConfigSummary()
	w.render(result.Snapshot)
	if w.settings != 0 && (result.Action == "load" || result.Action == "save") {
		// EnableWindow queues paint for the action buttons. Complete this
		// file operation's parent/child painting together; periodic status
		// refreshes do not invalidate the form or disturb ongoing editing.
		guiUser32.NewProc("RedrawWindow").Call(w.settings, 0, 0, 0x0181) // INVALIDATE | ALLCHILDREN | UPDATENOW
	}
}
func (w *desktopWindow) render(snapshot desktopSnapshot) {
	w.snapshot = snapshot
	wasPending := w.admission.Pending
	var diagnosis gossip.AdmissionDiagnosis
	available := snapshot.RuntimeState == "running" && snapshot.Error == "" && snapshot.Observation != nil && snapshot.Observation.Running
	if snapshot.Observation != nil {
		diagnosis = snapshot.Observation.Admission
	}
	w.admission = desktopAdmissionPresentation(diagnosis, available)
	if snapshot.Error != "" {
		w.admission.Label = "入网：实时状态暂不可用。"
	}
	state := map[string]string{"running": "运行中", "stopped": "已停止", "starting": "正在启动", "stopping": "正在停止", "failed": "启动或运行失败"}[snapshot.RuntimeState]
	if state == "" {
		state = "不可用"
	}
	connection, gateway, routes := "未连接", "—", "尚无实时路由"
	if observation := snapshot.Observation; observation != nil && available {
		if observation.TunnelReady {
			connection = "已连接"
		} else {
			connection = "连接中（隧道尚未就绪）"
		}
		if observation.IKE.Live {
			gateway = observation.IKE.Gateway
		}
		if len(observation.Babel.Routes) > 0 {
			var text strings.Builder
			for _, route := range observation.Babel.Routes {
				source := "任意"
				if route.SourcePrefix.IsValid() {
					source = route.SourcePrefix.String()
				}
				fmt.Fprintf(&text, "%s    来源 %s    origin %s    metric %d\r\n", route.Prefix, source, route.Origin, route.Metric)
			}
			if observation.RoutesTruncated {
				text.WriteString("（路由列表已截断）\r\n")
			}
			routes = text.String()
		}
	}
	if snapshot.Error != "" {
		connection = "状态不可用 · " + snapshot.Error
		gateway = "—"
		routes = "实时状态不可用，已清空上次路由。"
	}
	if w.admission.Pending {
		connection, gateway, routes = "待授权", "—", "入网授权完成前尚无实时路由。"
	} else if w.admission.Adopted && snapshot.Observation != nil && !snapshot.Observation.TunnelReady {
		connection = "已入网，正在连接"
	}
	w.setText(w.controls[guiStatusID], "连接："+connection)
	w.setText(w.controls[guiRuntimeID], "运行状态："+state+" · 当前 Photon 窗口管理连接")
	w.setText(w.controls[guiGatewayID], "活动网关："+gateway)
	w.setText(w.controls[guiRoutesID], routes)
	w.setText(w.controls[guiAdmissionID], w.admission.Label)
	w.setText(w.controls[guiJoinRequestID], w.admission.Request)
	if wasPending != w.admission.Pending {
		showRequest := uintptr(0)
		if w.admission.Pending {
			showRequest = 5
		}
		guiShowWindow.Call(w.controls[guiJoinRequestID], showRequest)
		guiShowWindow.Call(w.controls[guiCopyRequestID], showRequest)
		w.layout()
	}
	canCopy := uintptr(0)
	if w.admission.Request != "" {
		canCopy = 1
	}
	guiEnableWindow.Call(w.controls[guiCopyRequestID], canCopy)
	w.updateTray(false)
}
func (w *desktopWindow) setText(hwnd uintptr, text string) {
	if w.textCache[hwnd] == text {
		return
	}
	w.textCache[hwnd] = text
	guiSetWindowText.Call(hwnd, uintptr(unsafe.Pointer(guiUTF16(text))))
}
func (w *desktopWindow) note(text string) {
	w.setText(w.controls[guiNoteID], text)
	if w.controls[guiSettingsNoteID] != 0 {
		w.setText(w.controls[guiSettingsNoteID], text)
	}
}
func (w *desktopWindow) show() {
	guiShowWindow.Call(w.hwnd, 9)
	guiShowWindow.Call(w.hwnd, 5)
	guiSetForegroundWindow.Call(w.hwnd)
}
func (w *desktopWindow) quit() {
	if w.quitting {
		return
	}
	if w.dirty {
		answer, _ := windows.MessageBox(windows.HWND(w.hwnd), guiUTF16("有尚未保存的设置。停止连接、退出 Photon 并丢弃编辑吗？"), guiUTF16("Photon Windows"), windows.MB_YESNO|windows.MB_ICONQUESTION)
		if answer != 6 {
			return
		}
	}
	w.quitting = true
	// Keep the timer until destruction: it also drains a result when the
	// worker's PostMessage could not enqueue a notification. submit's quitting
	// guard prevents this timer from scheduling any new refresh work.
	w.admission.Request = ""
	w.setText(w.controls[guiJoinRequestID], "")
	guiEnableWindow.Call(w.controls[guiCopyRequestID], 0)
	w.updateTray(false)
	w.enableForm(false)
	for _, id := range []int{guiStartID, guiStopID, guiRestartID, guiSaveID, guiReloadID, guiSettingsID} {
		guiEnableWindow.Call(w.controls[id], 0)
	}
	w.note("正在停止连接并退出 Photon…")
	w.submitQuit()
}
func (w *desktopWindow) submitQuit() {
	if w.busy || w.quitSubmitted || w.ctx.Err() != nil {
		return
	}
	w.submit(guiRequest{Action: "quit"})
	w.quitSubmitted = w.busy
}
func (w *desktopWindow) popup() {
	flags := uintptr(0)
	if w.busy || w.quitting {
		flags = 1
	}
	guiEnableMenuItem.Call(w.menu, guiTrayStartID, flags)
	guiEnableMenuItem.Call(w.menu, guiTrayStopID, flags)
	var position guiPoint
	guiGetCursorPos.Call(uintptr(unsafe.Pointer(&position)))
	guiSetForegroundWindow.Call(w.hwnd)
	command, _, _ := guiTrackPopupMenu.Call(w.menu, 0x0102, uintptr(position.X), uintptr(position.Y), 0, w.hwnd, 0)
	guiPostMessage.Call(w.hwnd, 0, 0, 0)
	if command != 0 {
		w.command(int(command))
	}
}
func (w *desktopWindow) notifyData() guiNotifyIcon {
	data := guiNotifyIcon{Window: w.hwnd, ID: 1, Flags: 1 | 2 | 4, Callback: guiTrayMessage, Icon: w.icon}
	data.Size = uint32(unsafe.Sizeof(data))
	tip := "Photon · 未连接"
	if w.quitting {
		tip = "Photon · 正在停止连接并退出"
	} else if w.snapshot.Error != "" {
		tip = "Photon · 状态不可用"
	} else if w.admission.Pending {
		tip = w.admission.Tooltip
	} else if w.snapshot.RuntimeState == "running" && w.snapshot.Observation != nil && w.snapshot.Observation.Running && w.snapshot.Observation.TunnelReady {
		tip = "Photon · 已连接"
	} else if w.admission.Adopted {
		tip = w.admission.Tooltip
	} else if w.snapshot.RuntimeState == "stopped" {
		tip = "Photon · 连接已停止"
	}
	encoded, _ := windows.UTF16FromString(tip)
	copy(data.Tip[:len(data.Tip)-1], encoded)
	return data
}
func (w *desktopWindow) updateTray(add bool) {
	if !add && !w.tray {
		return
	}
	data := w.notifyData()
	action := uintptr(1)
	if add {
		action = 0
	}
	result, _, _ := guiShellNotifyIcon.Call(action, uintptr(unsafe.Pointer(&data)))
	if add {
		w.tray = result != 0
	}
}
func (w *desktopWindow) layout() {
	var bounds guiRect
	guiGetClientRect.Call(w.hwnd, uintptr(unsafe.Pointer(&bounds)))
	width, height := int(bounds.Right), int(bounds.Bottom)
	if width <= 0 || height <= 0 {
		return
	}
	move := func(hwnd uintptr, x, y, wid, hei int) {
		if hwnd != 0 {
			guiMoveWindow.Call(hwnd, uintptr(x), uintptr(y), uintptr(max(wid, 0)), uintptr(max(hei, 0)), 1)
		}
	}
	for row, id := range []int{guiStatusID, guiRuntimeID, guiGatewayID} {
		move(w.controls[id], 16, 14+row*27, width-32, 24)
	}
	for column, id := range []int{guiStartID, guiStopID, guiRestartID} {
		move(w.controls[id], 16+column*132, 100, 120, 30)
	}
	admissionHeight, routesTop, routesHeight := 26, 175, 130
	if w.admission.Pending {
		admissionHeight, routesTop, routesHeight = 52, 241, 80
	}
	move(w.controls[guiAdmissionID], 16, 141, width-32, admissionHeight)
	move(w.controls[guiJoinRequestID], 16, 199, width-192, 30)
	move(w.controls[guiCopyRequestID], width-164, 199, 148, 30)
	move(w.labels[0], 16, routesTop, width-32, 23)
	move(w.controls[guiRoutesID], 16, routesTop+26, width-32, routesHeight)
	configTop := routesTop + 26 + routesHeight + 38
	move(w.labels[1], 16, configTop-26, width-32, 23)
	move(w.controls[guiConfigSummaryID], 16, configTop, width-32, height-configTop-124)
	move(w.controls[guiSettingsID], 16, height-110, 132, 30)
	move(w.controls[guiNoteID], 16, height-72, width-32, 64)
}

// Clipboard memory is allocated movable, as required by CF_UNICODETEXT. A
// successful SetClipboardData transfers ownership to Windows; every failure
// retains our ownership and frees the handle. Only public join material enters
// this function, never configuration text or state database contents.
func guiCopyPublicRequest(hwnd uintptr, request string) error {
	if request == "" || len(request) > desktopJoinRequestLimit {
		return errors.New("入网请求为空或超过长度上限")
	}
	encoded, err := windows.UTF16FromString(request)
	if err != nil {
		return err
	}
	bytes := uintptr(len(encoded)) * 2
	memory, _, callErr := guiGlobalAlloc.Call(0x0042, bytes) // GMEM_MOVEABLE | GMEM_ZEROINIT
	if memory == 0 {
		return guiCallError("GlobalAlloc", callErr)
	}
	defer func() {
		if memory != 0 {
			guiGlobalFree.Call(memory)
		}
	}()
	address, _, callErr := guiGlobalLock.Call(memory)
	if address == 0 {
		return guiCallError("GlobalLock", callErr)
	}
	guiMoveMemory.Call(address, uintptr(unsafe.Pointer(&encoded[0])), bytes)
	guiGlobalUnlock.Call(memory)
	opened, _, callErr := guiOpenClipboard.Call(hwnd)
	if opened == 0 {
		return guiCallError("OpenClipboard", callErr)
	}
	defer guiCloseClipboard.Call()
	emptied, _, callErr := guiEmptyClipboard.Call()
	if emptied == 0 {
		return guiCallError("EmptyClipboard", callErr)
	}
	copied, _, callErr := guiSetClipboardData.Call(13, memory) // CF_UNICODETEXT
	if copied == 0 {
		return guiCallError("SetClipboardData", callErr)
	}
	memory = 0 // Windows owns the allocation after successful publication.
	return nil
}
