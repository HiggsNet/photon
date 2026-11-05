//go:build windows

package main

import (
	"fmt"
	"strings"
	"unsafe"
)

type guiDiagnosticsReading struct {
	firstLine  uintptr
	start, end uint32 // EDIT offsets are UTF-16 code units.
	follow     bool
}

type guiDiagnosticsScrollInfo struct {
	size, mask uint32
	min, max   int32
	page       uint32
	pos, track int32
}

func guiReadDiagnosticsPosition(edit uintptr) guiDiagnosticsReading {
	r := guiDiagnosticsReading{}
	r.firstLine, _, _ = guiSendMessage.Call(edit, 0xce, 0, 0)                                           // EM_GETFIRSTVISIBLELINE
	guiSendMessage.Call(edit, 0xb0, uintptr(unsafe.Pointer(&r.start)), uintptr(unsafe.Pointer(&r.end))) // EM_GETSEL supports >64K.
	scroll := guiDiagnosticsScrollInfo{mask: 0x17}                                                      // SIF_ALL
	scroll.size = uint32(unsafe.Sizeof(scroll))
	ok, _, _ := guiUser32.NewProc("GetScrollInfo").Call(edit, 1, uintptr(unsafe.Pointer(&scroll)))
	r.follow = r.start == r.end && (ok == 0 || scroll.pos >= scroll.max-int32(max(scroll.page, 1))+1)
	return r
}

func (r guiDiagnosticsReading) restore(edit uintptr) {
	guiSendMessage.Call(edit, 0xb1, uintptr(r.start), uintptr(r.end))
	first, _, _ := guiSendMessage.Call(edit, 0xce, 0, 0)
	guiSendMessage.Call(edit, 0xb6, 0, r.firstLine-first) // EM_LINESCROLL; signed delta.
}

// Update only this EDIT, without re-laying out or repainting the whole window.
// Each page/node keeps its own reading position. Logs follow new records only
// when already at the bottom and no text is selected.
func (w *desktopWindow) updateDiagnosticsText(text string) {
	v, edit := w.diagnosticsView, w.controls[guiDiagnosticsTextID]
	node := ""
	if v.page == guiDiagnosticsGatewayID {
		node = v.gatewayID
	} else if v.page == guiDiagnosticsPeersID {
		node = v.peerID
	} else if v.page == guiDiagnosticsRoutesID {
		node = v.route.label()
	}
	filter := 0
	if v.page == guiDiagnosticsLogID {
		filter = v.logFilter
	}
	key := fmt.Sprintf("%d/%d/%s", v.page, filter, node)
	if v.reading == nil {
		v.reading = make(map[string]guiDiagnosticsReading)
	}
	if v.textView != "" {
		v.reading[v.textView] = guiReadDiagnosticsPosition(edit)
	}
	if v.textView == key && w.textCache[edit] == text {
		return
	}
	r, visited := v.reading[key]
	if !visited {
		r.follow = true
	}
	guiSendMessage.Call(edit, 0x000b, 0, 0) // WM_SETREDRAW
	previous := w.textCache[edit]
	if v.page == guiDiagnosticsLogID && v.textView == key && previous != "" && strings.HasPrefix(text, previous) {
		length, _, _ := guiGetWindowTextLength.Call(edit)
		guiSendMessage.Call(edit, 0xb1, length, length)                                             // EM_SETSEL
		guiSendMessage.Call(edit, 0xc2, 0, uintptr(unsafe.Pointer(guiUTF16(text[len(previous):])))) // EM_REPLACESEL
		w.textCache[edit] = text
	} else {
		w.setText(edit, text)
	}
	follow := v.page == guiDiagnosticsLogID && r.follow
	if follow {
		length, _, _ := guiGetWindowTextLength.Call(edit)
		guiSendMessage.Call(edit, 0xb1, length, length) // EM_SETSEL
	} else {
		r.restore(edit)
	}
	guiSendMessage.Call(edit, 0x000b, 1, 0)
	if follow {
		// EDIT defers scrolling its caret while redraw is disabled.
		guiSendMessage.Call(edit, 0xb7, 0, 0) // EM_SCROLLCARET
	}
	guiUser32.NewProc("RedrawWindow").Call(edit, 0, 0, 0x405)
	v.textView = key
}
