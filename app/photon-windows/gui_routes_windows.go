//go:build windows

package main

import (
	"fmt"
	"slices"
	"time"

	"github.com/HiggsNet/photon/internal/photonwindows"
	"unsafe"
)

func (w *desktopWindow) syncMainRoutes(snapshot desktopSnapshot, available bool) {
	var keys []routeKey
	var rows []string
	if available {
		var groups map[routeKey][]photonwindows.RouteObservation
		keys, groups = desktopRouteGroups(snapshot.Observation.Babel.Routes)
		for _, key := range keys {
			rows = append(rows, fmt.Sprintf("%s  ·  %d 条路径", key.label(), len(groups[key])))
		}
		if snapshot.Observation.RoutesTruncated {
			rows = append(rows, "路由样本已截断")
		}
	}
	if len(rows) == 0 {
		rows = []string{"尚无实时 Babel 路由"}
	}
	if slices.Equal(rows, w.routeRows) && slices.Equal(keys, w.routeKeys) {
		return
	}
	list := w.controls[guiRoutesID]
	selected, _, _ := guiSendMessage.Call(list, 0x0188, 0, 0) // LB_GETCURSEL
	top, _, _ := guiSendMessage.Call(list, 0x018e, 0, 0)      // LB_GETTOPINDEX
	if selected < uintptr(len(w.routeKeys)) {
		selected = uintptr(slices.Index(keys, w.routeKeys[selected]))
	} else {
		selected = ^uintptr(0)
	}
	if top < uintptr(len(w.routeKeys)) {
		if index := slices.Index(keys, w.routeKeys[top]); index >= 0 {
			top = uintptr(index)
		}
	}
	guiSendMessage.Call(list, 0x000b, 0, 0)
	guiSendMessage.Call(list, 0x0184, 0, 0) // LB_RESETCONTENT
	for _, row := range rows {
		guiSendMessage.Call(list, 0x0180, 0, uintptr(unsafe.Pointer(guiUTF16(row)))) // LB_ADDSTRING
	}
	guiSendMessage.Call(list, 0x0186, selected, 0) // LB_SETCURSEL
	guiSendMessage.Call(list, 0x0197, min(top, uintptr(len(rows)-1)), 0)
	guiSendMessage.Call(list, 0x000b, 1, 0)
	guiUser32.NewProc("RedrawWindow").Call(list, 0, 0, 0x405)
	w.routeRows, w.routeKeys = rows, keys
}

func (w *desktopWindow) openSelectedRoute() {
	selected, _, _ := guiSendMessage.Call(w.controls[guiRoutesID], 0x0188, 0, 0)
	if w.quitting || w.diagnosticsView == nil || selected >= uintptr(len(w.routeKeys)) {
		return
	}
	v := w.diagnosticsView
	v.page, v.route = guiDiagnosticsRoutesID, w.routeKeys[selected]
	if !v.paused || v.sampledAt.IsZero() {
		v.snapshot, v.sampledAt = w.snapshot, time.Now()
	}
	w.layoutDiagnostics()
	w.openDiagnostics()
}
