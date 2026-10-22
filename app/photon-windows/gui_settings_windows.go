//go:build windows

package main

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"unsafe"

	"github.com/HiggsNet/photon/pkg/core/zone"
	"golang.org/x/sys/windows"
)

const (
	guiRootFieldID        = 2001
	guiManagedFieldID     = 2002
	guiAllowedFieldID     = 2003
	guiSplitFieldID       = 2004
	guiBootstrapListID    = 2005
	guiBootstrapPeerID    = 2006
	guiBootstrapAddressID = 2007
	guiStateFieldID       = 2011
	guiOverlayFieldID     = 2012
	guiListenFieldID      = 2013
	guiAdapterFieldID     = 2014
	guiMTUFieldID         = 2015
	guiLogFieldID         = 2016
	guiInitialFieldID     = 2017
	guiMaxFieldID         = 2018
	guiSettingsNoteID     = 2019
	guiBasicPageID        = 2101
	guiAdvancedPageID     = 2102
	guiGatewayPageID      = 2103
	guiRoutePageID        = 2104
	guiPageTitleID        = 2201
	guiPageHelpID         = 2202
	guiBootstrapAddID     = 2111
	guiBootstrapUpdateID  = 2112
	guiBootstrapDeleteID  = 2113
	guiBootstrapClearID   = 2114
)

var guiBasicFields = []int{guiRootFieldID, guiManagedFieldID}
var guiGatewayFields = []int{guiAllowedFieldID, guiAllowedInputID, guiAllowedAddID, guiAllowedUpdateID, guiAllowedDeleteID, guiAllowedClearID, guiBootstrapListID, guiBootstrapPeerID, guiBootstrapAddressID, guiBootstrapAddID, guiBootstrapUpdateID, guiBootstrapDeleteID, guiBootstrapClearID}
var guiRouteFields = []int{guiSplitFieldID, guiRouteInputID, guiRouteAddID, guiRouteUpdateID, guiRouteDeleteID, guiRouteClearID}
var guiAdvancedFields = []int{guiStateFieldID, guiOverlayFieldID, guiListenFieldID, guiAdapterFieldID, guiMTUFieldID, guiLogFieldID, guiInitialFieldID, guiMaxFieldID}

func (w *desktopWindow) createSettingsWindow() error {
	hwnd, _, err := guiCreateWindow.Call(0, uintptr(unsafe.Pointer(guiUTF16("PhotonWindowsSettings"))), uintptr(unsafe.Pointer(guiUTF16("Photon Windows 设置"))), 0x00cf0000|0x02000000, 0x80000000, 0x80000000, uintptr(w.guiScale(920)), uintptr(w.guiScale(760)), w.hwnd, 0, w.instance, 0)
	if hwnd == 0 {
		return guiCallError("CreateWindowEx settings", err)
	}
	w.settings = hwnd
	guiWindows.Store(hwnd, w)
	w.formLabels = make(map[int]uintptr)
	w.initializeOptionLists()
	create := func(id int, class, text string, style, ex uintptr) error {
		child, _, e := guiCreateWindow.Call(ex, uintptr(unsafe.Pointer(guiUTF16(class))), uintptr(unsafe.Pointer(guiUTF16(text))), style, 0, 0, 0, 0, hwnd, uintptr(id), w.instance, 0)
		if child == 0 {
			return guiCallError("CreateWindowEx settings "+class, e)
		}
		w.controls[id] = child
		guiSendMessage.Call(child, 0x30, w.font, 1)
		return nil
	}
	button := uintptr(0x50010000)
	for _, spec := range []struct {
		id   int
		text string
	}{{guiBasicPageID, "身份"}, {guiGatewayPageID, "网关与引导"}, {guiRoutePageID, "分流路由"}, {guiAdvancedPageID, "高级"}, {guiAllowedAddID, "添加"}, {guiAllowedUpdateID, "更新"}, {guiAllowedDeleteID, "移除"}, {guiAllowedClearID, "清除输入"}, {guiRouteAddID, "添加"}, {guiRouteUpdateID, "更新"}, {guiRouteDeleteID, "移除"}, {guiRouteClearID, "清除输入"}, {guiBootstrapAddID, "添加节点"}, {guiBootstrapUpdateID, "更新选中"}, {guiBootstrapDeleteID, "移除选中"}, {guiBootstrapClearID, "清除输入"}, {guiSaveID, "保存配置"}, {guiReloadID, "重新读取"}} {
		if err := create(spec.id, "BUTTON", spec.text, button, 0); err != nil {
			return err
		}
	}
	specs := []struct {
		id    int
		label string
	}{
		{guiRootFieldID, "可信根公钥"},
		{guiManagedFieldID, "本机管理域"},
		{guiAllowedFieldID, "网关规则"},
		{guiAllowedInputID, ""},
		{guiSplitFieldID, "经过 Photon 的网段"},
		{guiRouteInputID, "网段地址"},
		{guiBootstrapListID, "引导节点 · 网关身份 / 地址"},
		{guiBootstrapPeerID, "网关身份"}, {guiBootstrapAddressID, "主机地址与端口"},
		{guiStateFieldID, "身份数据库 · 绝对路径"},
		{guiOverlayFieldID, "Overlay ID"}, {guiListenFieldID, "Gossip 监听地址"},
		{guiAdapterFieldID, "虚拟网卡名称"}, {guiMTUFieldID, "MTU"}, {guiLogFieldID, "日志级别"},
		{guiInitialFieldID, "重连初始间隔"}, {guiMaxFieldID, "重连最大间隔"},
	}
	for _, spec := range specs {
		label, _, e := guiCreateWindow.Call(0, uintptr(unsafe.Pointer(guiUTF16("STATIC"))), uintptr(unsafe.Pointer(guiUTF16(spec.label))), 0x50000000, 0, 0, 0, 0, hwnd, 0, w.instance, 0)
		if label == 0 {
			return guiCallError("CreateWindowEx setting label", e)
		}
		w.formLabels[spec.id] = label
		guiSendMessage.Call(label, 0x30, w.font, 1)
		class, style := "EDIT", uintptr(0x50010000|0x0080)
		if spec.id == guiBootstrapListID || spec.id == guiAllowedFieldID || spec.id == guiSplitFieldID {
			class = "LISTBOX"
			style = 0x50010000 | 0x0001 | 0x0080 | 0x0100 | 0x00200000
		}
		if spec.id == guiLogFieldID {
			class = "COMBOBOX"
			style = 0x50010000 | 0x0002 | 0x0040 | 0x00200000
		}
		if err := create(spec.id, class, "", style, 0x200); err != nil {
			return err
		}
		if class == "EDIT" {
			guiSendMessage.Call(w.controls[spec.id], 0xc5, 1<<20, 0)
		}
	}
	for _, level := range []string{"debug", "info", "warn", "error"} {
		guiSendMessage.Call(w.controls[guiLogFieldID], 0x143, 0, uintptr(unsafe.Pointer(guiUTF16(level))))
	}
	guiSendMessage.Call(w.controls[guiLogFieldID], 0x141, 64, 0) // CB_LIMITTEXT for the editable selection.
	tab := int32(120)
	guiSendMessage.Call(w.controls[guiBootstrapListID], 0x192, 1, uintptr(unsafe.Pointer(&tab)))
	for _, id := range []int{guiPageTitleID, guiPageHelpID} {
		if err := create(id, "STATIC", "", 0x50000000, 0); err != nil {
			return err
		}
	}
	if err := create(guiSettingsNoteID, "STATIC", "保存后需重新连接生效；关闭本窗口保留未保存的编辑。", 0x50000000, 0); err != nil {
		return err
	}
	w.styleSettingsControls()
	guiEnableWindow.Call(w.controls[guiSaveID], 0)
	w.showSettingsPage(guiBasicPageID)
	w.layoutSettings()
	return nil
}

func (w *desktopWindow) settingsWindowProc(hwnd uintptr, message uint32, wp, lp uintptr) uintptr {
	switch message {
	case guiWMClose:
		guiShowWindow.Call(hwnd, 0)
		return 0
	case guiWMDestroy:
		guiWindows.Delete(hwnd)
		w.settings = 0
		return 0
	case guiWMSize:
		w.layoutSettings()
		return 0
	case guiWMCommand:
		id, notification := int(wp&0xffff), uint16(wp>>16)
		if id == guiBootstrapListID && notification == 1 {
			w.selectBootstrap()
			return 0
		}
		if list := w.optionLists[id]; list != nil && notification == 1 {
			w.selectOptionList(list)
			return 0
		}
		if !w.settingConfig && ((notification == 0x300 && w.isEditableFormField(id)) || (id == guiLogFieldID && (notification == 1 || notification == 5))) {
			if id == guiBootstrapPeerID || id == guiBootstrapAddressID {
				w.bootstrapDirty = true
			}
			if list := w.optionForInput(id); list != nil {
				list.Dirty = true
			}
			w.markFormDirty()
			return 0
		}
		if notification == 0 {
			switch id {
			case guiBasicPageID, guiAdvancedPageID, guiGatewayPageID, guiRoutePageID:
				w.showSettingsPage(id)
			case guiBootstrapAddID, guiBootstrapUpdateID, guiBootstrapDeleteID, guiBootstrapClearID:
				w.changeBootstrap(id)
			default:
				if list := w.optionForAction(id); list != nil {
					w.changeOptionList(list, id)
				} else {
					w.command(id)
				}
			}
		}
		return 0
	}
	result, _, _ := guiDefWindowProc.Call(hwnd, uintptr(message), wp, lp)
	return result
}
func (w *desktopWindow) isEditableFormField(id int) bool {
	for _, fields := range [][]int{guiBasicFields, guiGatewayFields, guiRouteFields, guiAdvancedFields} {
		for _, field := range fields {
			if field == id && id != guiBootstrapListID && id != guiAllowedFieldID && id != guiSplitFieldID && id < 2100 {
				return true
			}
		}
	}
	return false
}
func (w *desktopWindow) markFormDirty() {
	w.dirty = true
	w.editRevision++
	w.updateConfigSummary()
	w.note("有未保存的设置；保存后重新连接生效。")
}
func (w *desktopWindow) openSettings() {
	guiShowWindow.Call(w.settings, 9)
	guiShowWindow.Call(w.settings, 5)
	guiSetForegroundWindow.Call(w.settings)
}
func (w *desktopWindow) showSettingsPage(page int) {
	w.settingsPage = page
	for _, group := range []struct {
		ids  []int
		show bool
	}{{guiBasicFields, page == guiBasicPageID}, {guiGatewayFields, page == guiGatewayPageID}, {guiRouteFields, page == guiRoutePageID}, {guiAdvancedFields, page == guiAdvancedPageID}} {
		visible := uintptr(0)
		if group.show {
			visible = 5
		}
		for _, id := range group.ids {
			guiShowWindow.Call(w.controls[id], visible)
			if label := w.formLabels[id]; label != 0 {
				guiShowWindow.Call(label, visible)
			}
		}
	}
	title, help := "本机身份", "填写管理员提供的可信根公钥与本机管理域，再设置网关和路由。首次启动连接时会自动生成本机身份。"
	switch page {
	case guiGatewayPageID:
		title, help = "网关与引导", "网关规则支持 *.example. 或 *。首次入网至少添加一个具体引导节点；已有身份数据库可留空。"
	case guiRoutePageID:
		title, help = "分流路由", "仅列表中的网段经过 Photon，其余流量保持原路径。支持 IPv4 与 IPv6；选中条目可编辑或移除。"
	case guiAdvancedPageID:
		title, help = "高级设置", "通常保留默认值即可。数据库路径决定使用哪个本机身份，修改前请确认。保存后需重新连接生效。"
	}
	w.setText(w.controls[guiPageTitleID], title)
	w.setText(w.controls[guiPageHelpID], help)
	for _, id := range []int{guiBasicPageID, guiGatewayPageID, guiRoutePageID, guiAdvancedPageID} {
		kind := "body"
		if id == page {
			kind = "primary"
		}
		w.guiStyleControl(w.controls[id], kind)
	}
	w.layoutSettings()
}
func (w *desktopWindow) enableForm(enabled bool) {
	value := uintptr(0)
	if enabled {
		value = 1
	}
	for _, ids := range [][]int{guiBasicFields, guiGatewayFields, guiRouteFields, guiAdvancedFields, {guiBasicPageID, guiGatewayPageID, guiRoutePageID, guiAdvancedPageID}} {
		for _, id := range ids {
			guiEnableWindow.Call(w.controls[id], value)
		}
	}
}
func guiControlText(hwnd uintptr) (string, error) {
	size, _, _ := guiGetWindowTextLength.Call(hwnd)
	if size > 1<<20 {
		return "", errors.New("设置内容超过长度上限")
	}
	buffer := make([]uint16, int(size)+1)
	guiGetWindowText.Call(hwnd, uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)))
	return windows.UTF16ToString(buffer), nil
}
func (w *desktopWindow) fillForm(form desktopConfigForm) {
	w.settingConfig = true
	defer func() { w.settingConfig = false }()
	values := map[int]string{guiRootFieldID: form.RootPublicKey, guiManagedFieldID: form.ManagedZone, guiStateFieldID: form.StatePath, guiOverlayFieldID: form.OverlayID, guiListenFieldID: form.GossipListen, guiAdapterFieldID: form.AdapterName, guiMTUFieldID: form.MTU, guiLogFieldID: form.LogLevel, guiInitialFieldID: form.InitialBackoff, guiMaxFieldID: form.MaxBackoff}
	for id, text := range values {
		guiSetWindowText.Call(w.controls[id], uintptr(unsafe.Pointer(guiUTF16(text))))
	}
	for id, text := range map[int]string{guiAllowedFieldID: form.AllowedGateways, guiSplitFieldID: form.SplitRoutes} {
		list := w.optionLists[id]
		list.Rows = desktopFormLines(text)
		w.clearOptionInput(list)
		w.refreshOptionList(list)
	}
	w.bootstrapRows = append([]desktopBootstrapRow(nil), form.BootstrapHints...)
	w.clearBootstrapInputs()
	w.refreshBootstrapList()
}
func (w *desktopWindow) collectForm() (desktopConfigForm, error) {
	var form desktopConfigForm
	values := map[int]*string{guiRootFieldID: &form.RootPublicKey, guiManagedFieldID: &form.ManagedZone, guiStateFieldID: &form.StatePath, guiOverlayFieldID: &form.OverlayID, guiListenFieldID: &form.GossipListen, guiAdapterFieldID: &form.AdapterName, guiMTUFieldID: &form.MTU, guiLogFieldID: &form.LogLevel, guiInitialFieldID: &form.InitialBackoff, guiMaxFieldID: &form.MaxBackoff}
	for id, target := range values {
		text, err := guiControlText(w.controls[id])
		if err != nil {
			return desktopConfigForm{}, err
		}
		*target = text
	}
	// A save owns a detached row snapshot while further UI editing continues.
	form.BootstrapHints = append([]desktopBootstrapRow(nil), w.bootstrapRows...)
	form.AllowedGateways = strings.Join(w.optionLists[guiAllowedFieldID].Rows, "\r\n")
	form.SplitRoutes = strings.Join(w.optionLists[guiSplitFieldID].Rows, "\r\n")
	return form, nil
}
func (w *desktopWindow) updateConfigSummary() {
	status := "设置已读取"
	if !w.formLoaded {
		status = "设置读取失败，请打开设置后重新读取"
	}
	if w.newConfig {
		status = "首次使用：请填写设置并保存后启动连接"
	}
	if w.dirty {
		status = "有未保存的设置"
	}
	managed, _ := guiControlText(w.controls[guiManagedFieldID])
	state, _ := guiControlText(w.controls[guiStateFieldID])
	if managed == "" {
		managed = "尚未填写"
	}
	summary := fmt.Sprintf("%s\r\n本机管理域：%s · 引导节点 %d 条\r\n数据库：%s", status, managed, len(w.bootstrapRows), state)
	w.setText(w.controls[guiConfigSummaryID], summary)
}
func (w *desktopWindow) clearBootstrapInputs() {
	wasSetting := w.settingConfig
	w.settingConfig = true
	guiSetWindowText.Call(w.controls[guiBootstrapPeerID], uintptr(unsafe.Pointer(guiUTF16(""))))
	guiSetWindowText.Call(w.controls[guiBootstrapAddressID], uintptr(unsafe.Pointer(guiUTF16(""))))
	w.settingConfig = wasSetting
	w.bootstrapSelected = -1
	w.bootstrapDirty = false
	guiSendMessage.Call(w.controls[guiBootstrapListID], 0x186, ^uintptr(0), 0)
}
func (w *desktopWindow) refreshBootstrapList() {
	guiSendMessage.Call(w.controls[guiBootstrapListID], 0x184, 0, 0)
	for _, row := range w.bootstrapRows {
		guiSendMessage.Call(w.controls[guiBootstrapListID], 0x180, 0, uintptr(unsafe.Pointer(guiUTF16(row.Peer+"\t"+row.Address))))
	}
	selected := uintptr(w.bootstrapSelected)
	guiSendMessage.Call(w.controls[guiBootstrapListID], 0x186, selected, 0)
}
func (w *desktopWindow) selectBootstrap() {
	selected, _, _ := guiSendMessage.Call(w.controls[guiBootstrapListID], 0x188, 0, 0)
	if w.bootstrapDirty {
		guiSendMessage.Call(w.controls[guiBootstrapListID], 0x186, uintptr(w.bootstrapSelected), 0)
		w.note("引导节点输入尚未添加或更新，请先处理后选择其他节点。")
		return
	}
	index := int(int32(selected))
	if index < 0 || index >= len(w.bootstrapRows) {
		return
	}
	w.bootstrapSelected = index
	row := w.bootstrapRows[index]
	w.settingConfig = true
	guiSetWindowText.Call(w.controls[guiBootstrapPeerID], uintptr(unsafe.Pointer(guiUTF16(row.Peer))))
	guiSetWindowText.Call(w.controls[guiBootstrapAddressID], uintptr(unsafe.Pointer(guiUTF16(row.Address))))
	w.settingConfig = false
}
func (w *desktopWindow) changeBootstrap(action int) {
	if action == guiBootstrapClearID {
		w.clearBootstrapInputs()
		return
	}
	if action == guiBootstrapDeleteID {
		if w.bootstrapDirty {
			w.note("引导节点输入尚未添加或更新，请先处理后删除。")
			return
		}
		i := w.bootstrapSelected
		if i < 0 || i >= len(w.bootstrapRows) {
			w.note("请先选中要删除的引导节点。")
			return
		}
		w.bootstrapRows = append(w.bootstrapRows[:i], w.bootstrapRows[i+1:]...)
		w.clearBootstrapInputs()
		w.refreshBootstrapList()
		w.markFormDirty()
		return
	}
	peer, peerErr := guiControlText(w.controls[guiBootstrapPeerID])
	address, addressErr := guiControlText(w.controls[guiBootstrapAddressID])
	peer, address = strings.TrimSpace(peer), strings.TrimSpace(address)
	peerZone := zone.ZonePath(peer)
	if peerErr != nil || addressErr != nil || !peerZone.Valid() || peerZone.IsRoot() || zone.HasPatternMeta(peer) {
		w.note("请输入具体的完整网关身份，例如 gateway.example.；引导节点不能使用通配符。")
		return
	}
	host, port, err := net.SplitHostPort(address)
	number, portErr := strconv.Atoi(port)
	if err != nil || host == "" || portErr != nil || number < 1 || number > 65535 {
		w.note("请输入有效的 host:port 地址；IPv6 地址需放在方括号内。")
		return
	}
	index := -1
	if action == guiBootstrapUpdateID {
		index = w.bootstrapSelected
		if index < 0 || index >= len(w.bootstrapRows) {
			w.note("请先选中要更新的引导节点。")
			return
		}
	}
	for i, row := range w.bootstrapRows {
		if row.Peer == peer && row.Address == address && i != index {
			w.note("该身份和地址组合已存在，请选中后更新。")
			return
		}
	}
	row := desktopBootstrapRow{Peer: peer, Address: address}
	if index < 0 {
		w.bootstrapRows = append(w.bootstrapRows, row)
	} else {
		w.bootstrapRows[index] = row
	}
	w.clearBootstrapInputs()
	w.refreshBootstrapList()
	w.markFormDirty()
}
