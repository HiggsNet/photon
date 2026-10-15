//go:build windows

package main

import (
	"net/netip"
	"strings"
	"unsafe"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

const (
	guiAllowedInputID  = 2021
	guiRouteInputID    = 2022
	guiAllowedAddID    = 2121
	guiAllowedUpdateID = 2122
	guiAllowedDeleteID = 2123
	guiAllowedClearID  = 2124
	guiRouteAddID      = 2131
	guiRouteUpdateID   = 2132
	guiRouteDeleteID   = 2133
	guiRouteClearID    = 2134
)

type guiOptionList struct {
	List, Input, Add, Update, Delete, Clear int
	Name                                    string
	Rows                                    []string
	Selected                                int
	Dirty                                   bool
}

func (w *desktopWindow) initializeOptionLists() {
	w.optionLists = map[int]*guiOptionList{
		guiAllowedFieldID: {List: guiAllowedFieldID, Input: guiAllowedInputID, Add: guiAllowedAddID, Update: guiAllowedUpdateID, Delete: guiAllowedDeleteID, Clear: guiAllowedClearID, Name: "允许网关", Selected: -1},
		guiSplitFieldID:   {List: guiSplitFieldID, Input: guiRouteInputID, Add: guiRouteAddID, Update: guiRouteUpdateID, Delete: guiRouteDeleteID, Clear: guiRouteClearID, Name: "分流路由", Selected: -1},
	}
}
func (w *desktopWindow) optionForInput(id int) *guiOptionList {
	for _, list := range w.optionLists {
		if list.Input == id {
			return list
		}
	}
	return nil
}
func (w *desktopWindow) optionForAction(id int) *guiOptionList {
	for _, list := range w.optionLists {
		if id == list.Add || id == list.Update || id == list.Delete || id == list.Clear {
			return list
		}
	}
	return nil
}
func (w *desktopWindow) clearOptionInput(list *guiOptionList) {
	setting := w.settingConfig
	w.settingConfig = true
	guiSetWindowText.Call(w.controls[list.Input], uintptr(unsafe.Pointer(guiUTF16(""))))
	w.settingConfig = setting
	list.Selected = -1
	list.Dirty = false
	guiSendMessage.Call(w.controls[list.List], 0x186, ^uintptr(0), 0)
}
func (w *desktopWindow) refreshOptionList(list *guiOptionList) {
	guiSendMessage.Call(w.controls[list.List], 0x184, 0, 0)
	for _, value := range list.Rows {
		guiSendMessage.Call(w.controls[list.List], 0x180, 0, uintptr(unsafe.Pointer(guiUTF16(value))))
	}
	guiSendMessage.Call(w.controls[list.List], 0x186, uintptr(list.Selected), 0)
}
func (w *desktopWindow) selectOptionList(list *guiOptionList) {
	if list.Dirty {
		guiSendMessage.Call(w.controls[list.List], 0x186, uintptr(list.Selected), 0)
		w.note(list.Name + "输入尚未应用，请先添加、更新或清除输入。")
		return
	}
	selected, _, _ := guiSendMessage.Call(w.controls[list.List], 0x188, 0, 0)
	index := int(int32(selected))
	if index < 0 || index >= len(list.Rows) {
		return
	}
	list.Selected = index
	w.settingConfig = true
	guiSetWindowText.Call(w.controls[list.Input], uintptr(unsafe.Pointer(guiUTF16(list.Rows[index]))))
	w.settingConfig = false
}
func (w *desktopWindow) changeOptionList(list *guiOptionList, action int) {
	if action == list.Clear {
		w.clearOptionInput(list)
		return
	}
	if action == list.Delete {
		if list.Dirty {
			w.note(list.Name + "输入尚未应用，请先更新或清除输入后删除。")
			return
		}
		i := list.Selected
		if i < 0 || i >= len(list.Rows) {
			w.note("请先选择要删除的" + list.Name + "。")
			return
		}
		list.Rows = append(list.Rows[:i], list.Rows[i+1:]...)
	} else {
		value, err := guiControlText(w.controls[list.Input])
		value = strings.TrimSpace(value)
		if err != nil || value == "" {
			w.note("请先填写" + list.Name + "。")
			return
		}
		if list.List == guiAllowedFieldID {
			valid := zone.ValidatePattern(value) == nil
			if !zone.HasPatternMeta(value) {
				path := zone.ZonePath(value)
				valid = valid && path.Valid() && !path.IsRoot()
			}
			if !valid {
				w.note("请输入具体网关身份或有效通配符，例如 gateway.example.、*.example. 或 *。")
				return
			}
		} else {
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				w.note("请输入有效的 IPv4 或 IPv6 网段，例如 10.0.0.0/24 或 fd00::/64。")
				return
			}
			if prefix.Bits() == 0 {
				w.note("仅支持分流网段，不能添加默认路由（/0）。")
				return
			}
			if prefix != prefix.Masked() {
				w.note("请填写网段的网络地址，例如 " + prefix.Masked().String() + "。")
				return
			}
			value = prefix.String()
		}
		index := -1
		if action == list.Update {
			index = list.Selected
			if index < 0 || index >= len(list.Rows) {
				w.note("请先选择要更新的" + list.Name + "。")
				return
			}
		}
		for i, row := range list.Rows {
			if row == value && i != index {
				w.note("列表中已存在该" + list.Name + "。")
				return
			}
		}
		if index < 0 {
			list.Rows = append(list.Rows, value)
		} else {
			list.Rows[index] = value
		}
	}
	w.clearOptionInput(list)
	w.refreshOptionList(list)
	w.markFormDirty()
}
func (w *desktopWindow) unappliedDraft() string {
	if w.bootstrapDirty {
		return "引导节点"
	}
	for _, id := range []int{guiAllowedFieldID, guiSplitFieldID} {
		if list := w.optionLists[id]; list != nil && list.Dirty {
			return list.Name
		}
	}
	return ""
}
func (w *desktopWindow) guideNewConfig() bool {
	if !w.newConfig {
		return false
	}
	w.openSettings()
	w.note("尚未创建配置：请先填写并保存设置，再安装、启动服务。")
	return true
}
