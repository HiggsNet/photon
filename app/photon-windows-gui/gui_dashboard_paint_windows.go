//go:build windows

package main

import (
	"strings"
	"unsafe"
)

func (w *desktopWindow) guiRoundSurface(dc uintptr, rect guiRect, color string, radius int) {
	guiGDI32.NewProc("SelectObject").Call(dc, w.guiBrush(w.guiColor(color)))
	pen, _, _ := guiGDI32.NewProc("GetStockObject").Call(8)
	guiGDI32.NewProc("SelectObject").Call(dc, pen)
	r := uintptr(guiAtDPI(radius, w.guiDPI(w.hwnd)))
	guiGDI32.NewProc("RoundRect").Call(dc, uintptr(rect.Left), uintptr(rect.Top), uintptr(rect.Right), uintptr(rect.Bottom), r, r)
}

func (w *desktopWindow) drawMainBackground(dc uintptr) {
	saved, _, _ := guiGDI32.NewProc("SaveDC").Call(dc)
	defer guiGDI32.NewProc("RestoreDC").Call(dc, saved)
	width, height := w.guiClientSize(w.hwnd)
	dpi := w.guiDPI(w.hwnd)
	rect := func(x, y, r, b int) guiRect {
		return guiRect{int32(guiAtDPI(x, dpi)), int32(guiAtDPI(y, dpi)), int32(guiAtDPI(r, dpi)), int32(guiAtDPI(b, dpi))}
	}
	sidebar := rect(0, 0, 184, height)
	guiUser32.NewProc("FillRect").Call(dc, uintptr(unsafe.Pointer(&sidebar)), w.guiBrush(w.guiColor("sidebar")))
	if w.mainPage == 0 {
		w.guiRoundSurface(dc, rect(212, 28, width-28, 184), "surface", 24)
	}
}

// Use identical column boundaries for the header and every row. The native
// list retains complete accessible strings, selection, keyboard and scrolling.
func (w *desktopWindow) drawDashboardItem(item guiDrawItem) bool {
	header := item.Window == w.controls[guiNodeHeaderID]
	if !header && item.Window != w.controls[guiNodeListID] {
		return false
	}
	saved, _, _ := guiGDI32.NewProc("SaveDC").Call(item.DC)
	defer guiGDI32.NewProc("RestoreDC").Call(item.DC, saved)
	dpi := w.guiDPI(item.Window)
	fill := "surface"
	if header {
		fill = "background"
	} else if item.State&1 != 0 {
		fill = "selected"
	}
	guiUser32.NewProc("FillRect").Call(item.DC, uintptr(unsafe.Pointer(&item.Rect)), w.guiBrush(w.guiColor(fill)))
	if !header && (item.Item == 0xffffffff || int(item.Item) >= len(w.nodeRows)) {
		return true
	}
	values := []string{"节点名称 ↓", "Gossip", "Tunnel", "健康监测"}
	if !header {
		r := w.nodeRows[item.Item]
		values = []string{r.Peer, r.Gossip, r.Tunnel, r.Health}
	}
	width := item.Rect.Right - item.Rect.Left
	columns := []int32{0, width * 36 / 100, width * 55 / 100, width * 80 / 100, width}
	font := w.appearance.fonts[dpi]["body"]
	if header {
		font = w.appearance.fonts[dpi]["section"]
	}
	guiGDI32.NewProc("SelectObject").Call(item.DC, font)
	guiGDI32.NewProc("SetBkMode").Call(item.DC, 1)
	for i, value := range values {
		color := "body"
		if header || strings.HasPrefix(value, "—") || strings.HasPrefix(value, "…") {
			color = "muted"
		}
		if !header && strings.HasPrefix(value, "✓") {
			color = "success"
		}
		if !header && strings.HasPrefix(value, "!") {
			color = "warning"
		}
		if w.appearance.contrast && item.State&1 != 0 {
			color = "onAccent"
		}
		guiGDI32.NewProc("SetTextColor").Call(item.DC, uintptr(w.guiColor(color)))
		r := guiRect{item.Rect.Left + columns[i] + int32(guiAtDPI(16, dpi)), item.Rect.Top, item.Rect.Left + columns[i+1] - int32(guiAtDPI(8, dpi)), item.Rect.Bottom}
		guiUser32.NewProc("DrawTextW").Call(item.DC, uintptr(unsafe.Pointer(guiUTF16(value))), ^uintptr(0), uintptr(unsafe.Pointer(&r)), 0x8824) // SINGLELINE | VCENTER | END_ELLIPSIS | NOPREFIX
	}
	if !header && item.State&0x10 != 0 {
		guiUser32.NewProc("DrawFocusRect").Call(item.DC, uintptr(unsafe.Pointer(&item.Rect)))
	}
	return true
}
