//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	guiStatusID             = 1001
	guiServiceID            = 1002
	guiGatewayID            = 1003
	guiRoutesID             = 1004
	guiConfigID             = 1005
	guiNoteID               = 1006
	guiInstallID            = 1101
	guiStartID              = 1102
	guiStopID               = 1103
	guiRestartID            = 1104
	guiSaveID               = 1105
	guiReloadID             = 1106
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
	Action, Text string
	EditRevision uint64
}
type guiResult struct {
	Action, Text string
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
	editRevision               uint64
	newline                    string
	ctx                        context.Context
	cancel                     context.CancelFunc
	requests                   chan guiRequest
	results                    chan guiResult
	worker                     sync.WaitGroup
	postMu                     sync.Mutex // Serializes cancellation and native HWND posting.
	backend                    *desktopBackend
	snapshot                   desktopSnapshot
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
	// A desktop process uses the same executable as SCM and owns no daemon.
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
	defer window.dispose()
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
		handled, _, _ := guiIsDialogMessage.Call(window.hwnd, uintptr(unsafe.Pointer(&message)))
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
		class := guiWindowClass{Style: 8, WindowProc: guiWindowProc, Instance: instance, Icon: icon, SmallIcon: icon, Cursor: cursor, Background: 16, ClassName: guiUTF16("PhotonWindowsDesktop")}
		class.Size = uint32(unsafe.Sizeof(class))
		atom, _, e := guiRegisterClass.Call(uintptr(unsafe.Pointer(&class)))
		if atom == 0 {
			guiRegisterError = guiCallError("RegisterClassEx", e)
		}
	})
	if guiRegisterError != nil {
		return nil, guiRegisterError
	}
	ctx, cancel := context.WithCancel(context.Background())
	w := &desktopWindow{instance: instance, icon: icon, backend: backend, controls: make(map[int]uintptr), ctx: ctx, cancel: cancel, requests: make(chan guiRequest, 1), results: make(chan guiResult, 1), textCache: make(map[uintptr]string), newline: "\n"}
	defer func() {
		if err != nil {
			w.dispose()
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
		{guiServiceID, "STATIC", "服务：读取中…", static, 0},
		{guiGatewayID, "STATIC", "活动网关：—", static, 0},
		{guiInstallID, "BUTTON", "安装服务", button, 0},
		{guiStartID, "BUTTON", "启动", button, 0},
		{guiStopID, "BUTTON", "停止", button, 0},
		{guiRestartID, "BUTTON", "重启服务", button, 0},
		{guiRoutesID, "EDIT", "尚无实时路由", edit | 0x0800, 0x200},
		{guiConfigID, "EDIT", "", edit, 0x200},
		{guiSaveID, "BUTTON", "保存配置", button, 0},
		{guiReloadID, "BUTTON", "重新读取", button, 0},
		{guiNoteID, "STATIC", "配置保存后需重启服务生效；关闭窗口将隐藏到系统托盘。", static, 0},
	}
	for _, spec := range specs {
		hwnd, _, e := guiCreateWindow.Call(uintptr(spec.exStyle), uintptr(unsafe.Pointer(guiUTF16(spec.class))), uintptr(unsafe.Pointer(guiUTF16(spec.text))), uintptr(spec.style), 0, 0, 0, 0, w.hwnd, uintptr(spec.id), instance, 0)
		if hwnd == 0 {
			return nil, guiCallError("CreateWindowEx "+spec.class, e)
		}
		w.controls[spec.id] = hwnd
		guiSendMessage.Call(hwnd, 0x0030, w.font, 1) // WM_SETFONT
	}
	for i, text := range []string{"实时 Babel 路由（目标 / 来源前缀 / origin / metric）", "基础配置 YAML · " + backend.options.ConfigPath} {
		hwnd, _, e := guiCreateWindow.Call(0, uintptr(unsafe.Pointer(guiUTF16("STATIC"))), uintptr(unsafe.Pointer(guiUTF16(text))), uintptr(static), 0, 0, 0, 0, w.hwnd, 0, instance, 0)
		if hwnd == 0 {
			return nil, guiCallError("CreateWindowEx label", e)
		}
		w.labels[i] = hwnd
		guiSendMessage.Call(hwnd, 0x0030, w.font, 1)
	}
	guiSendMessage.Call(w.controls[guiConfigID], 0x00c5, 1<<20, 0) // EM_SETLIMITTEXT, bounded UTF-16.
	guiSendMessage.Call(w.controls[guiRoutesID], 0x00c5, 1<<20, 0)
	w.menu, _, callErr = guiCreatePopupMenu.Call()
	if w.menu == 0 {
		return nil, guiCallError("CreatePopupMenu", callErr)
	}
	for _, item := range []struct {
		id   int
		text string
	}{{guiOpenID, "打开 Photon"}, {guiTrayStartID, "启动服务"}, {guiTrayStopID, "停止服务"}, {guiExitID, "退出界面（服务继续运行）"}} {
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
					result.Text, result.Err = w.backend.LoadConfigText()
				case "save":
					result.Err = w.backend.SaveConfigText(request.Text)
				case "refresh":
				default:
					result.Err = w.backend.Service(request.Action)
				}
				if w.ctx.Err() != nil {
					return
				}
				// Snapshot IPC honors cancellation; SCM mutations already have
				// their existing bounded wait. No task starts another worker.
				result.Snapshot = w.backend.Snapshot(w.ctx)
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

func (w *desktopWindow) dispose() {
	w.postMu.Lock()
	w.cancel()
	w.postMu.Unlock()
	w.worker.Wait()
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
}

func desktopWindowProc(hwnd uintptr, message uint32, wp, lp uintptr) uintptr {
	value, exists := guiWindows.Load(hwnd)
	if exists {
		w := value.(*desktopWindow)
		if message == w.taskbarCreated && w.taskbarCreated != 0 {
			w.tray = false
			w.updateTray(true)
			if !w.tray {
				w.show()
				w.note("系统托盘暂不可用，窗口保持打开。退出界面不会停止服务。")
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
			if id == guiConfigID && notification == 0x0300 && !w.settingConfig {
				w.dirty = true
				w.editRevision++
			} else if notification == 0 {
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
				guiShowWindow.Call(hwnd, 0)
			} else {
				w.quit()
			}
			return 0
		case guiWMDestroy:
			w.postMu.Lock()
			w.cancel()
			w.postMu.Unlock()
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
	if w.busy || w.ctx.Err() != nil {
		return
	}
	if request.Action == "load" {
		request.EditRevision = w.editRevision
	}
	select {
	case w.requests <- request:
		w.busy = true
		if request.Action == "load" {
			guiEnableWindow.Call(w.controls[guiConfigID], 0)
		}
		for _, id := range []int{guiInstallID, guiStartID, guiStopID, guiRestartID, guiSaveID, guiReloadID} {
			guiEnableWindow.Call(w.controls[id], 0)
		}
		if request.Action != "refresh" {
			w.note("正在处理…")
		}
	default:
	}
}
func (w *desktopWindow) command(id int) {
	if id == guiOpenID {
		w.show()
		return
	}
	if id == guiExitID {
		w.quit()
		return
	}
	if w.busy {
		return
	}
	request := guiRequest{}
	switch id {
	case guiInstallID:
		request.Action = "install"
	case guiStartID, guiTrayStartID:
		request.Action = "start"
	case guiStopID, guiTrayStopID:
		request.Action = "stop"
	case guiRestartID:
		request.Action = "restart"
	case guiSaveID:
		request.Action = "save"
		text, err := w.configText()
		if err != nil {
			w.note(err.Error())
			return
		}
		request.Text, request.EditRevision = text, w.editRevision
	case guiReloadID:
		if w.dirty {
			answer, _ := windows.MessageBox(windows.HWND(w.hwnd), guiUTF16("重新读取会丢弃尚未保存的编辑。继续吗？"), guiUTF16("Photon Windows"), windows.MB_YESNO|windows.MB_ICONQUESTION)
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
func (w *desktopWindow) configText() (string, error) {
	size, _, _ := guiGetWindowTextLength.Call(w.controls[guiConfigID])
	if size > 1<<20 {
		return "", errors.New("配置内容超过 1 MiB 上限")
	}
	buffer := make([]uint16, int(size)+1)
	guiGetWindowText.Call(w.controls[guiConfigID], uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)))
	text := windows.UTF16ToString(buffer)
	if w.newline == "\n" {
		text = strings.ReplaceAll(text, "\r\n", "\n")
	}
	return text, nil
}
func (w *desktopWindow) applyResult(result guiResult) {
	w.busy = false
	if result.Action == "load" {
		guiEnableWindow.Call(w.controls[guiConfigID], 1)
	}
	for _, id := range []int{guiInstallID, guiStartID, guiStopID, guiRestartID, guiSaveID, guiReloadID} {
		guiEnableWindow.Call(w.controls[id], 1)
	}
	loadChanged := result.Action == "load" && result.EditRevision != w.editRevision
	if result.Action == "load" && !loadChanged && (result.Err == nil || errors.Is(result.Err, os.ErrNotExist)) {
		w.newline = "\n"
		if strings.Contains(result.Text, "\r\n") {
			w.newline = "\r\n"
		}
		w.settingConfig = true
		display := strings.ReplaceAll(strings.ReplaceAll(result.Text, "\r\n", "\n"), "\n", "\r\n")
		guiSetWindowText.Call(w.controls[guiConfigID], uintptr(unsafe.Pointer(guiUTF16(display))))
		w.settingConfig = false
		w.dirty = false
		w.editRevision++
	}
	if result.Err != nil {
		if result.Action == "load" && errors.Is(result.Err, os.ErrNotExist) {
			w.note("配置文件尚不存在；编辑有效 YAML 并保存后可安装服务。")
		} else {
			w.note("操作失败：" + result.Err.Error())
		}
	} else {
		switch result.Action {
		case "save":
			if result.EditRevision == w.editRevision {
				w.dirty = false
			}
			w.note("配置已保存；点击“重启服务”后生效。")
		case "load":
			w.note("配置已读取。保存后需重启服务生效；退出界面不会停止服务。")
		case "install":
			w.note("服务已安装。点击“启动”连接。")
		case "start":
			w.note("服务已启动，正在读取实时连接状态。")
		case "stop":
			w.note("服务已停止。")
		case "restart":
			w.note("服务已重启，配置将在新进程中生效。")
		}
	}
	if loadChanged {
		w.note("已保留读取期间的新编辑；如需丢弃编辑，请再次点击“重新读取”。")
	}
	w.render(result.Snapshot)
}
func (w *desktopWindow) render(snapshot desktopSnapshot) {
	w.snapshot = snapshot
	state := map[string]string{"running": "运行中", "stopped": "已停止", "not-installed": "未安装", "start-pending": "正在启动", "stop-pending": "正在停止", "paused": "已暂停", "unknown": "不可用", "transitioning": "状态转换中"}[snapshot.ServiceState]
	if state == "" {
		state = "不可用"
	}
	connection, gateway, routes := "未连接", "—", "尚无实时路由"
	if observation := snapshot.Observation; observation != nil {
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
	w.setText(w.controls[guiStatusID], "连接："+connection)
	w.setText(w.controls[guiServiceID], "服务："+state+" · "+w.backend.options.ServiceName)
	w.setText(w.controls[guiGatewayID], "活动网关："+gateway)
	w.setText(w.controls[guiRoutesID], routes)
	w.updateTray(false)
}
func (w *desktopWindow) setText(hwnd uintptr, text string) {
	if w.textCache[hwnd] == text {
		return
	}
	w.textCache[hwnd] = text
	guiSetWindowText.Call(hwnd, uintptr(unsafe.Pointer(guiUTF16(text))))
}
func (w *desktopWindow) note(text string) { w.setText(w.controls[guiNoteID], text) }
func (w *desktopWindow) show() {
	guiShowWindow.Call(w.hwnd, 9)
	guiShowWindow.Call(w.hwnd, 5)
	guiSetForegroundWindow.Call(w.hwnd)
}
func (w *desktopWindow) quit() {
	if w.dirty {
		answer, _ := windows.MessageBox(windows.HWND(w.hwnd), guiUTF16("有尚未保存的配置编辑。退出界面并丢弃编辑吗？服务将继续运行。"), guiUTF16("Photon Windows"), windows.MB_YESNO|windows.MB_ICONQUESTION)
		if answer != 6 {
			return
		}
	}
	guiDestroyWindow.Call(w.hwnd)
}
func (w *desktopWindow) popup() {
	flags := uintptr(0)
	if w.busy {
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
	if w.snapshot.Error != "" {
		tip = "Photon · 状态不可用"
	} else if w.snapshot.Observation != nil && w.snapshot.Observation.TunnelReady {
		tip = "Photon · 已连接"
	} else if w.snapshot.ServiceState == "stopped" {
		tip = "Photon · 服务已停止"
	} else if w.snapshot.ServiceState == "not-installed" {
		tip = "Photon · 服务未安装"
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
	for row, id := range []int{guiStatusID, guiServiceID, guiGatewayID} {
		move(w.controls[id], 16, 14+row*27, width-32, 24)
	}
	for column, id := range []int{guiInstallID, guiStartID, guiStopID, guiRestartID} {
		move(w.controls[id], 16+column*104, 100, 96, 30)
	}
	move(w.labels[0], 16, 143, width-32, 23)
	move(w.controls[guiRoutesID], 16, 169, width-32, 130)
	move(w.labels[1], 16, 311, width-32, 23)
	move(w.controls[guiConfigID], 16, 337, width-32, height-423)
	move(w.controls[guiSaveID], 16, height-72, 112, 30)
	move(w.controls[guiReloadID], 140, height-72, 112, 30)
	move(w.controls[guiNoteID], 16, height-34, width-32, 27)
}
