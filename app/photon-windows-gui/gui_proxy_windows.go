//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
	"unsafe"

	"github.com/HiggsNet/photon/internal/mihomoproxy"
	"golang.org/x/sys/windows"
)

const (
	guiProxyOpenID        = 1210
	guiProxyResultMessage = 0x8050
	guiProxyTitleID       = 2400 + iota
	guiProxyStatusID
	guiProxyPortLabelID
	guiProxyPortID
	guiProxyToggleID
	guiProxyTemplateID
	guiProxyBrowseID
	guiProxyDefaultID
	guiProxyGroupTitleID
	guiProxyChoiceTitleID
	guiProxyGroupsID
	guiProxyChoicesID
	guiProxySelectID
	guiProxyNoteID
)

type proxyResult struct {
	status mihomoproxy.Status
	action string
	err    error
}

type desktopProxyWindow struct {
	hwnd            uintptr
	core            mihomoproxy.Core
	busy            bool
	results         chan proxyResult
	work            sync.WaitGroup
	watch           sync.WaitGroup
	cancelWatch     context.CancelFunc
	template        string
	defaultTemplate string
	status          mihomoproxy.Status
	groupNames      []string
	choices         []string
}

func (w *desktopWindow) openProxy() {
	if w.quitting {
		return
	}
	if w.proxy == nil {
		if err := w.createProxyWindow(); err != nil {
			windows.MessageBox(windows.HWND(w.hwnd), guiUTF16(err.Error()), guiUTF16("Photon 代理"), windows.MB_ICONERROR)
			return
		}
	}
	w.show()
	guiShowWindow.Call(w.proxy.hwnd, 9)
	guiShowWindow.Call(w.proxy.hwnd, 5)
	guiSetForegroundWindow.Call(w.proxy.hwnd)
	guiSetTimer.Call(w.proxy.hwnd, 1, 2000, 0)
	w.proxySubmit("status", "", 0, "", "")
}

func (w *desktopWindow) createProxyWindow() error {
	hwnd, _, err := guiCreateWindow.Call(0, uintptr(unsafe.Pointer(guiUTF16("PhotonWindowsProxy"))),
		uintptr(unsafe.Pointer(guiUTF16("Photon · 代理管理"))), 0x00cf0000|0x02000000,
		0x80000000, 0x80000000, uintptr(w.guiScale(920)), uintptr(w.guiScale(700)), w.hwnd, 0, w.instance, 0)
	if hwnd == 0 {
		return guiCallError("CreateWindowEx proxy", err)
	}
	path := strings.TrimSuffix(w.backend.options.ConfigPath, filepath.Ext(w.backend.options.ConfigPath)) + ".proxy.yaml"
	w.proxy = &desktopProxyWindow{hwnd: hwnd, results: make(chan proxyResult, 1), template: path, defaultTemplate: path}
	guiWindows.Store(hwnd, w)
	const static, button = 0x50000000, 0x50010000
	for _, spec := range []struct {
		id                 int
		class, label, role string
		style, extended    uintptr
	}{
		{guiProxyTitleID, "STATIC", "代理管理", "title", static, 0},
		{guiProxyStatusID, "STATIC", "代理未启动", "body", static, 0},
		{guiProxyPortLabelID, "STATIC", "本地代理端口", "muted", static, 0},
		{guiProxyPortID, "EDIT", "17890", "edit", button | 0x2000 | 0x80, 0x200},
		{guiProxyToggleID, "BUTTON", "启动代理", "primary", button, 0},
		{guiProxyTemplateID, "STATIC", path, "muted", static | 0x8000, 0},
		{guiProxyBrowseID, "BUTTON", "选用规则模板…", "body", button, 0},
		{guiProxyDefaultID, "BUTTON", "默认模板", "body", button, 0},
		{guiProxyGroupTitleID, "STATIC", "代理组", "section", static, 0},
		{guiProxyChoiceTitleID, "STATIC", "可选出口", "section", static, 0},
		{guiProxyGroupsID, "LISTBOX", "", "edit", button | 0x0001 | 0x0100 | 0x00200000, 0x200},
		{guiProxyChoicesID, "LISTBOX", "", "edit", button | 0x0001 | 0x0100 | 0x00200000, 0x200},
		{guiProxySelectID, "BUTTON", "应用出口", "primary", button, 0},
		{guiProxyNoteID, "EDIT", "仅监听本机 HTTP / SOCKS 端口。请在需要代理的应用中填写上述地址。", "edit", button | 0x0004 | 0x0040 | 0x0800 | 0x00200000, 0x200},
	} {
		child, _, err := guiCreateWindow.Call(spec.extended,
			uintptr(unsafe.Pointer(guiUTF16(spec.class))), uintptr(unsafe.Pointer(guiUTF16(spec.label))),
			spec.style, 0, 0, 0, 0, hwnd, uintptr(spec.id), w.instance, 0)
		if child == 0 {
			guiDestroyWindow.Call(hwnd)
			w.proxy = nil
			return guiCallError("CreateWindowEx proxy control", err)
		}
		w.controls[spec.id] = child
		w.guiStyleControl(child, spec.role)
	}
	guiSendMessage.Call(w.controls[guiProxyPortID], 0xc5, 5, 0)
	w.layoutProxy()
	w.updateProxyControls()
	if err := guiFitInitialWindow(hwnd); err != nil {
		guiDestroyWindow.Call(hwnd)
		w.proxy = nil
		return err
	}
	return nil
}

func (w *desktopWindow) layoutProxy() {
	width, height := w.guiClientSize(w.proxy.hwnd)
	if width <= 0 || height <= 0 {
		return
	}
	groupsWidth := (width - 64) / 3
	choiceX := 40 + groupsWidth
	choicesWidth := width - choiceX - 24
	for _, control := range []struct{ id, x, y, width, height int }{
		{guiProxyTitleID, 24, 22, width - 230, 38},
		{guiProxyToggleID, width - 168, 22, 144, 38},
		{guiProxyStatusID, 24, 76, width - 48, 28},
		{guiProxyPortLabelID, 24, 124, 138, 24},
		{guiProxyPortID, 170, 118, 90, 30},
		{guiProxyTemplateID, 24, 170, width - 338, 30},
		{guiProxyBrowseID, width - 294, 164, 154, 34},
		{guiProxyDefaultID, width - 128, 164, 104, 34},
		{guiProxyGroupTitleID, 24, 222, groupsWidth, 26},
		{guiProxyChoiceTitleID, choiceX, 222, choicesWidth, 26},
		{guiProxyGroupsID, 24, 254, groupsWidth, max(0, height-388)},
		{guiProxyChoicesID, choiceX, 254, choicesWidth, max(0, height-388)},
		{guiProxySelectID, width - 168, height - 124, 144, 34},
		{guiProxyNoteID, 24, height - 78, width - 48, 54},
	} {
		w.guiMove(w.controls[control.id], control.x, control.y, control.width, control.height)
	}
}

func (w *desktopWindow) hideProxy() {
	if w.proxy != nil && w.proxy.hwnd != 0 {
		guiKillTimer.Call(w.proxy.hwnd, 1)
		guiShowWindow.Call(w.proxy.hwnd, 0)
	}
}

func (w *desktopWindow) closeProxy() error {
	p := w.proxy
	if p == nil {
		return nil
	}
	p.work.Wait()
	err := p.stop()
	if p.hwnd != 0 {
		guiDestroyWindow.Call(p.hwnd)
	}
	return err
}

func (p *desktopProxyWindow) stop() error {
	if p.cancelWatch != nil {
		p.cancelWatch()
		p.watch.Wait()
		p.cancelWatch = nil
	}
	return p.core.Stop()
}

func (p *desktopProxyWindow) monitor(ctx context.Context, backend *desktopBackend) {
	ctx, p.cancelWatch = context.WithCancel(ctx)
	p.watch.Add(1)
	go func() {
		defer p.watch.Done()
		tick := time.NewTicker(2 * time.Second)
		defer tick.Stop()
		for ctx.Err() == nil {
			probe, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
			directory, err := backend.proxyDirectory(probe)
			cancel()
			if err != nil {
				directory = nil
			}
			if ctx.Err() != nil {
				return
			}
			if err := p.core.Sync(ctx, directory); err != nil {
				// The core retains failures for display and stops when it
				// cannot confirm that withdrawn routes were removed.
				return
			}
			select {
			case <-ctx.Done():
			case <-tick.C:
			}
		}
	}()
}

func (w *desktopWindow) proxySubmit(action, path string, port uint16, group, choice string) {
	p := w.proxy
	if p.busy || w.quitting || w.ctx.Err() != nil {
		return
	}
	p.busy = true
	w.updateProxyControls()
	ctx := w.ctx
	hwnd := p.hwnd
	p.work.Add(1)
	go func() {
		defer p.work.Done()
		var err error
		switch action {
		case "start":
			// Join any previous watcher before replacing its owned run.
			if err = p.stop(); err == nil {
				var executable string
				executable, err = os.Executable()
				if err == nil {
					executable = filepath.Join(filepath.Dir(executable), "mihomo.exe")
					_, err = os.Stat(executable)
				}
				if errors.Is(err, os.ErrNotExist) {
					err = errors.New("请将 mihomo.exe 放在 Photon GUI 同一目录")
				}
				if err == nil {
					var template mihomoproxy.Template
					template, err = readProxyTemplate(path, path == p.defaultTemplate)
					if err == nil {
						err = p.core.Start(ctx, executable, port, template)
					}
				}
				if err == nil {
					p.monitor(ctx, w.backend)
				}
			}
		case "stop":
			err = p.stop()
		case "select":
			err = p.core.Select(ctx, group, choice)
		}
		status, statusErr := p.core.Status(ctx)
		if err == nil {
			err = statusErr
		}
		select {
		case p.results <- proxyResult{status: status, action: action, err: err}:
			guiPostMessage.Call(hwnd, guiProxyResultMessage, 0, 0)
		case <-ctx.Done():
		}
	}()
}

func (w *desktopWindow) updateProxyControls() {
	p := w.proxy
	for _, id := range []int{guiProxyToggleID, guiProxyPortID, guiProxyBrowseID, guiProxyDefaultID, guiProxySelectID} {
		enabled := !p.busy
		switch id {
		case guiProxyPortID, guiProxyBrowseID, guiProxyDefaultID:
			enabled = enabled && !p.status.Running
		case guiProxySelectID:
			group := w.proxySelectedGroup()
			enabled = enabled && p.status.Running && group != nil && (group.Type == "Selector" || group.Type == "URLTest" || group.Type == "Fallback") &&
				proxyListSelection(w.controls[guiProxyChoicesID], p.choices) != ""
		}
		if enabled {
			guiEnableWindow.Call(w.controls[id], 1)
		} else {
			guiEnableWindow.Call(w.controls[id], 0)
		}
	}
}

func proxyListSelection(hwnd uintptr, rows []string) string {
	index, _, _ := guiSendMessage.Call(hwnd, 0x0188, 0, 0)
	if index < uintptr(len(rows)) {
		return rows[index]
	}
	return ""
}

func proxyReplaceList(hwnd uintptr, rows []string, selection string) {
	guiSendMessage.Call(hwnd, 0x000b, 0, 0)
	guiSendMessage.Call(hwnd, 0x0184, 0, 0)
	for _, value := range rows {
		guiSendMessage.Call(hwnd, 0x0180, 0, uintptr(unsafe.Pointer(guiUTF16(value))))
	}
	guiSendMessage.Call(hwnd, 0x0186, uintptr(slices.Index(rows, selection)), 0)
	guiSendMessage.Call(hwnd, 0x000b, 1, 0)
	guiUser32.NewProc("InvalidateRect").Call(hwnd, 0, 1)
}

func (w *desktopWindow) proxySelectedGroup() *mihomoproxy.Group {
	p := w.proxy
	name := proxyListSelection(w.controls[guiProxyGroupsID], p.groupNames)
	for index := range p.status.Groups {
		if p.status.Groups[index].Name == name {
			return &p.status.Groups[index]
		}
	}
	return nil
}

func (w *desktopWindow) updateProxyChoices(previousGroup string, force bool) {
	p := w.proxy
	group := w.proxySelectedGroup()
	if group == nil {
		if len(p.choices) > 0 {
			proxyReplaceList(w.controls[guiProxyChoicesID], nil, "")
		}
		p.choices = nil
		w.setText(w.controls[guiProxyChoiceTitleID], "可选出口")
		return
	}
	label := "可选出口"
	if group.Selected != "" {
		label += " · 当前：" + group.Selected
	}
	w.setText(w.controls[guiProxyChoiceTitleID], label)
	hwnd := w.controls[guiProxyChoicesID]
	if force || previousGroup != group.Name || !slices.Equal(p.choices, group.Choices) {
		choice := group.Selected
		if !force && previousGroup == group.Name {
			current := proxyListSelection(hwnd, p.choices)
			if slices.Contains(group.Choices, current) {
				choice = current
			}
		}
		proxyReplaceList(hwnd, group.Choices, choice)
		p.choices = group.Choices
	}
}

func (w *desktopWindow) applyProxyResult(result proxyResult) {
	p := w.proxy
	p.busy = false
	p.status = result.status
	status, toggle := "代理未启动", "启动代理"
	if p.status.Running {
		status = fmt.Sprintf("本地代理 127.0.0.1:%d · Photon 出口待就绪", p.status.Port)
		if p.status.PhotonOnline {
			status = fmt.Sprintf("本地代理 127.0.0.1:%d · Photon 出口已加载", p.status.Port)
		}
		toggle = "停止代理"
	}
	w.setText(w.controls[guiProxyStatusID], status)
	w.setText(w.controls[guiProxyToggleID], toggle)
	hwnd := w.controls[guiProxyGroupsID]
	previous := proxyListSelection(hwnd, p.groupNames)
	names := make([]string, 0, len(p.status.Groups))
	for _, group := range p.status.Groups {
		names = append(names, group.Name)
	}
	if !slices.Equal(names, p.groupNames) {
		selected := previous
		if !slices.Contains(names, selected) && len(names) > 0 {
			selected = names[0]
		}
		proxyReplaceList(hwnd, names, selected)
		p.groupNames = names
	}
	w.updateProxyChoices(previous, result.action == "select")
	if result.err != nil {
		w.setText(w.controls[guiProxyNoteID], "代理操作失败："+result.err.Error())
	} else if result.action != "status" {
		w.setText(w.controls[guiProxyNoteID], "仅监听本机 HTTP / SOCKS 端口。请在需要代理的应用中填写上述地址。")
	}
	w.updateProxyControls()
}

func (w *desktopWindow) proxyWindowProc(hwnd uintptr, message uint32, wp, lp uintptr) uintptr {
	switch message {
	case guiWMClose:
		w.hideProxy()
		return 0
	case guiWMDestroy:
		guiWindows.Delete(hwnd)
		w.proxy.hwnd = 0
		return 0
	case guiWMSize:
		w.layoutProxy()
		return 0
	case guiWMTimer:
		if wp == 1 {
			w.consumeProxyResult()
			w.proxySubmit("status", "", 0, "", "")
		}
		return 0
	case guiProxyResultMessage:
		w.consumeProxyResult()
		return 0
	case guiWMCommand:
		w.proxyCommand(int(wp&0xffff), uint16(wp>>16))
		return 0
	}
	result, _, _ := guiDefWindowProc.Call(hwnd, uintptr(message), wp, lp)
	return result
}

func (w *desktopWindow) consumeProxyResult() {
	select {
	case result := <-w.proxy.results:
		w.applyProxyResult(result)
	default:
	}
}

func (w *desktopWindow) proxyCommand(id int, notification uint16) {
	p := w.proxy
	if p.busy || w.quitting {
		return
	}
	switch {
	case id == guiProxyGroupsID && notification == 1:
		w.updateProxyChoices("", true)
		w.updateProxyControls()
	case id == guiProxyChoicesID && notification == 1:
		w.updateProxyControls()
	case id == guiProxyToggleID && notification == 0:
		if p.status.Running {
			w.proxySubmit("stop", "", 0, "", "")
			return
		}
		value, _ := guiControlText(w.controls[guiProxyPortID])
		port, err := strconv.ParseUint(strings.TrimSpace(value), 10, 16)
		if err != nil || port == 0 {
			w.setText(w.controls[guiProxyNoteID], "请输入 1 至 65535 的本机代理端口。")
			return
		}
		w.proxySubmit("start", p.template, uint16(port), "", "")
	case id == guiProxyBrowseID && notification == 0 && !p.status.Running:
		path, err := chooseProxyTemplate(p.hwnd)
		if err != nil {
			w.setText(w.controls[guiProxyNoteID], err.Error())
		} else if path != "" {
			p.template = path
			w.setText(w.controls[guiProxyTemplateID], path)
		}
	case id == guiProxyDefaultID && notification == 0 && !p.status.Running:
		p.template = p.defaultTemplate
		w.setText(w.controls[guiProxyTemplateID], p.template)
	case id == guiProxySelectID && notification == 0, id == guiProxyChoicesID && notification == 2:
		group := w.proxySelectedGroup()
		choice := proxyListSelection(w.controls[guiProxyChoicesID], p.choices)
		if group != nil && choice != "" && (group.Type == "Selector" || group.Type == "URLTest" || group.Type == "Fallback") {
			w.proxySubmit("select", "", 0, group.Name, choice)
		}
	}
}

type proxyOpenFileName struct {
	Size                               uint32
	Owner, Instance                    uintptr
	Filter, CustomFilter               *uint16
	MaxCustomFilter, FilterIndex       uint32
	File                               *uint16
	MaxFile                            uint32
	FileTitle                          *uint16
	MaxFileTitle                       uint32
	InitialDir, Title                  *uint16
	Flags                              uint32
	FileOffset, FileExtension          uint16
	DefaultExtension                   *uint16
	Data, Hook, TemplateName, Reserved uintptr
	ReservedFlags, ExtendedFlags       uint32
}

func chooseProxyTemplate(owner uintptr) (string, error) {
	var name [32768]uint16
	filter := utf16.Encode([]rune("Mihomo YAML\x00*.yaml;*.yml\x00\x00"))
	dialog := proxyOpenFileName{
		Owner: owner, Filter: &filter[0], File: &name[0], MaxFile: uint32(len(name)),
		Title: guiUTF16("选用代理规则模板"),
		Flags: 0x00080000 | 0x1000 | 0x0800 | 0x0008, // Explorer, file/path exist, preserve working directory.
	}
	dialog.Size = uint32(unsafe.Sizeof(dialog))
	common := windows.NewLazySystemDLL("comdlg32.dll")
	if result, _, _ := common.NewProc("GetOpenFileNameW").Call(uintptr(unsafe.Pointer(&dialog))); result == 0 {
		if code, _, _ := common.NewProc("CommDlgExtendedError").Call(); code != 0 {
			return "", fmt.Errorf("无法打开模板选择窗口 (%#x)", code)
		}
		return "", nil
	}
	return windows.UTF16ToString(name[:]), nil
}
