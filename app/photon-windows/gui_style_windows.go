//go:build windows

package main

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var guiSetWindowTheme = windows.NewLazySystemDLL("uxtheme.dll").NewProc("SetWindowTheme")

// One visual owner per desktop. Each top-level window has its own DPI; fonts
// and brushes remain alive until all windows and their child controls close.
type guiAppearance struct {
	dpi       map[uintptr]uint32
	fonts     map[uint32]map[string]uintptr
	roles     map[uintptr]string
	fontKinds map[uintptr]string
	brushes   map[uint32]uintptr
	contrast  bool
}

func (w *desktopWindow) guiDPI(hwnd uintptr) uint32 {
	if hwnd == 0 {
		hwnd = w.hwnd
	}
	if root, _, _ := guiUser32.NewProc("GetAncestor").Call(hwnd, 2); root != 0 {
		hwnd = root
	}
	if w.appearance != nil {
		if dpi := w.appearance.dpi[hwnd]; dpi != 0 {
			return dpi
		}
	}
	dpi, _, _ := guiUser32.NewProc("GetDpiForWindow").Call(hwnd)
	if dpi == 0 {
		dpi, _, _ = guiUser32.NewProc("GetDpiForSystem").Call()
	}
	if dpi == 0 {
		dpi = 96
	}
	return uint32(dpi)
}

func guiAtDPI(value int, dpi uint32) int        { return (value*int(dpi) + 48) / 96 }
func (w *desktopWindow) guiScale(value int) int { return guiAtDPI(value, w.guiDPI(w.hwnd)) }

func (w *desktopWindow) guiClientSize(hwnd uintptr) (int, int) {
	var rect guiRect
	guiGetClientRect.Call(hwnd, uintptr(unsafe.Pointer(&rect)))
	dpi := int(w.guiDPI(hwnd))
	return int(rect.Right) * 96 / dpi, int(rect.Bottom) * 96 / dpi
}

func (w *desktopWindow) guiMove(hwnd uintptr, x, y, width, height int) {
	if hwnd == 0 {
		return
	}
	dpi := w.guiDPI(hwnd)
	guiMoveWindow.Call(hwnd, uintptr(guiAtDPI(x, dpi)), uintptr(guiAtDPI(y, dpi)), uintptr(guiAtDPI(max(width, 0), dpi)), uintptr(guiAtDPI(max(height, 0), dpi)), 1)
}

func (w *desktopWindow) guiEnsureFonts(dpi uint32) error {
	if w.appearance.fonts[dpi] != nil {
		return nil
	}
	fonts := make(map[string]uintptr)
	for _, spec := range []struct {
		kind, face   string
		size, weight int
	}{
		{"body", "Microsoft YaHei UI", 16, 400},
		{"title", "Microsoft YaHei UI", 26, 600},
		{"section", "Microsoft YaHei UI", 16, 600},
		{"mono", "Consolas", 14, 400},
	} {
		height := int32(-guiAtDPI(spec.size, dpi))
		font, _, err := guiCreateFont.Call(uintptr(height), 0, 0, 0, uintptr(spec.weight), 0, 0, 0, 1, 0, 0, 5, 0, uintptr(unsafe.Pointer(guiUTF16(spec.face))))
		if font == 0 {
			for _, owned := range fonts {
				guiDeleteObject.Call(owned)
			}
			return fmt.Errorf("create %s font: %w", spec.kind, guiCallError("CreateFont", err))
		}
		fonts[spec.kind] = font
	}
	w.appearance.fonts[dpi] = fonts
	return nil
}

func (w *desktopWindow) guiInitStyle() error {
	w.appearance = &guiAppearance{dpi: make(map[uintptr]uint32), fonts: make(map[uint32]map[string]uintptr), roles: make(map[uintptr]string), fontKinds: make(map[uintptr]string), brushes: make(map[uint32]uintptr)}
	w.guiReadContrast()
	dpi := w.guiDPI(w.hwnd)
	w.appearance.dpi[w.hwnd] = dpi
	if err := w.guiEnsureFonts(dpi); err != nil {
		return err
	}
	w.font = w.appearance.fonts[dpi]["body"]
	if dpi != 96 {
		guiUser32.NewProc("SetWindowPos").Call(w.hwnd, 0, 0, 0, uintptr(w.guiScale(920)), uintptr(w.guiScale(760)), 0x16)
	}
	return nil
}

func guiFontKind(role string) string {
	switch role {
	case "title", "section", "mono":
		return role
	}
	return "body"
}

func (w *desktopWindow) guiApplyFont(hwnd uintptr, kind string) {
	if hwnd == 0 || w.appearance == nil {
		return
	}
	w.appearance.fontKinds[hwnd] = guiFontKind(kind)
	dpi := w.guiDPI(hwnd)
	font := w.font
	if w.guiEnsureFonts(dpi) == nil {
		font = w.appearance.fonts[dpi][guiFontKind(kind)]
	}
	guiSendMessage.Call(hwnd, 0x30, font, 1)
}

func (w *desktopWindow) guiStyleControl(hwnd uintptr, kind string) {
	if hwnd == 0 || w.appearance == nil {
		return
	}
	w.appearance.roles[hwnd] = kind
	w.guiApplyFont(hwnd, kind)
	// Keep real BUTTON controls, accessibility, focus and native keyboard
	// behavior. Only the emphasized action uses our small owner-drawn face.
	var class [32]uint16
	guiUser32.NewProc("GetClassNameW").Call(hwnd, uintptr(unsafe.Pointer(&class[0])), uintptr(len(class)))
	if windows.UTF16ToString(class[:]) == "Button" {
		style, _, _ := guiUser32.NewProc("GetWindowLongPtrW").Call(hwnd, ^uintptr(15)) // GWL_STYLE=-16
		style &^= 0xf
		if kind == "primary" {
			style |= 0xb
		} // BS_OWNERDRAW
		guiUser32.NewProc("SetWindowLongPtrW").Call(hwnd, ^uintptr(15), style)
	}
	guiSetWindowTheme.Call(hwnd, uintptr(unsafe.Pointer(guiUTF16("Explorer"))), 0)
	guiUser32.NewProc("InvalidateRect").Call(hwnd, 0, 1)
}

func (w *desktopWindow) guiReadContrast() {
	var value struct {
		Size, Flags uint32
		Scheme      uintptr
	}
	value.Size = uint32(unsafe.Sizeof(value))
	guiUser32.NewProc("SystemParametersInfoW").Call(0x42, uintptr(value.Size), uintptr(unsafe.Pointer(&value)), 0)
	w.appearance.contrast = value.Flags&1 != 0
}

func guiRGB(r, g, b uint32) uint32 { return r | g<<8 | b<<16 }

func (w *desktopWindow) guiColor(role string) uint32 {
	if w.appearance.contrast {
		index := uintptr(8) // COLOR_WINDOWTEXT
		switch role {
		case "background", "surface":
			index = 5
		case "accent":
			index = 13
		case "pressed":
			index = 13
		case "onAccent":
			index = 14
		case "disabled":
			index = 15
		case "disabledText":
			index = 17
		}
		color, _, _ := guiUser32.NewProc("GetSysColor").Call(index)
		return uint32(color)
	}
	switch role {
	case "background":
		return guiRGB(245, 247, 251)
	case "surface", "onAccent":
		return guiRGB(255, 255, 255)
	case "accent":
		return guiRGB(37, 99, 211)
	case "pressed":
		return guiRGB(29, 78, 167)
	case "muted", "disabledText":
		return guiRGB(89, 101, 122)
	case "disabled":
		return guiRGB(225, 230, 239)
	case "success":
		return guiRGB(20, 112, 67)
	default:
		return guiRGB(25, 36, 55)
	}
}

func (w *desktopWindow) guiBrush(color uint32) uintptr {
	if brush := w.appearance.brushes[color]; brush != 0 {
		return brush
	}
	brush, _, _ := guiGDI32.NewProc("CreateSolidBrush").Call(uintptr(color))
	w.appearance.brushes[color] = brush
	return brush
}

type guiDrawItem struct {
	Type, ID, Item, Action, State uint32
	Window, DC                    uintptr
	Rect                          guiRect
	Data                          uintptr
}

func (w *desktopWindow) guiHandleStyleMessage(hwnd uintptr, message uint32, wp, lp uintptr) (uintptr, bool) {
	if w.appearance == nil {
		return 0, false
	}
	switch message {
	case guiWMGetMinMaxInfo:
		if lp != 0 {
			height := 620
			if hwnd == w.settings {
				height = 700
			}
			dpi := w.guiDPI(hwnd)
			minimum := guiPoint{int32(guiAtDPI(700, dpi)), int32(guiAtDPI(height, dpi))}
			guiMoveMemory.Call(lp+3*unsafe.Sizeof(minimum), uintptr(unsafe.Pointer(&minimum)), unsafe.Sizeof(minimum))
		}
		return 0, true
	case 0x2e0: // WM_DPICHANGED; suggested RECT is native memory.
		dpi := uint32(wp & 0xffff)
		if dpi < 48 || dpi > 768 || lp == 0 {
			return 0, true
		}
		var rect guiRect
		guiMoveMemory.Call(uintptr(unsafe.Pointer(&rect)), lp, unsafe.Sizeof(rect))
		if err := w.guiEnsureFonts(dpi); err != nil {
			w.note(err.Error())
			return 0, true
		}
		w.appearance.dpi[hwnd] = dpi
		for child, kind := range w.appearance.fontKinds {
			root, _, _ := guiUser32.NewProc("GetAncestor").Call(child, 2)
			if root == hwnd {
				w.guiApplyFont(child, kind)
			}
		}
		if hwnd == w.hwnd {
			w.font = w.appearance.fonts[dpi]["body"]
		}
		if rect.Right > rect.Left && rect.Bottom > rect.Top {
			guiUser32.NewProc("SetWindowPos").Call(hwnd, 0, uintptr(rect.Left), uintptr(rect.Top), uintptr(rect.Right-rect.Left), uintptr(rect.Bottom-rect.Top), 0x14)
		}
		if hwnd == w.settings {
			w.layoutSettings()
		} else if hwnd == w.diagnostics {
			w.layoutDiagnostics()
		} else {
			w.layout()
		}
		guiUser32.NewProc("RedrawWindow").Call(hwnd, 0, 0, 0x185)
		return 0, true
	case 0x14: // WM_ERASEBKGND
		var rect guiRect
		guiGetClientRect.Call(hwnd, uintptr(unsafe.Pointer(&rect)))
		guiUser32.NewProc("FillRect").Call(wp, uintptr(unsafe.Pointer(&rect)), w.guiBrush(w.guiColor("background")))
		return 1, true
	case 0x133, 0x134, 0x138: // EDIT, LISTBOX, STATIC (including readonly EDIT)
		role := w.appearance.roles[lp]
		background := "background"
		if role == "edit" || role == "mono" {
			background = "surface"
		}
		text := "body"
		if role == "muted" {
			text = "muted"
		}
		if lp == w.controls[guiStatusID] && w.snapshot.Error == "" && w.snapshot.Observation != nil && w.snapshot.Observation.TunnelReady {
			text = "success"
		}
		guiGDI32.NewProc("SetTextColor").Call(wp, uintptr(w.guiColor(text)))
		guiGDI32.NewProc("SetBkColor").Call(wp, uintptr(w.guiColor(background)))
		guiGDI32.NewProc("SetBkMode").Call(wp, 1)
		return w.guiBrush(w.guiColor(background)), true
	case 0x2b: // WM_DRAWITEM
		if lp == 0 {
			return 0, false
		}
		var item guiDrawItem
		guiMoveMemory.Call(uintptr(unsafe.Pointer(&item)), lp, unsafe.Sizeof(item))
		if item.Type != 4 || w.appearance.roles[item.Window] != "primary" {
			return 0, false
		}
		saved, _, _ := guiGDI32.NewProc("SaveDC").Call(item.DC)
		defer guiGDI32.NewProc("RestoreDC").Call(item.DC, saved)
		fill, text := "accent", "onAccent"
		if item.State&1 != 0 {
			fill = "pressed"
		}
		if item.State&4 != 0 {
			fill, text = "disabled", "disabledText"
		}
		if w.appearance.contrast && item.State&4 == 0 {
			fill, text = "accent", "onAccent"
		}
		guiUser32.NewProc("FillRect").Call(item.DC, uintptr(unsafe.Pointer(&item.Rect)), w.guiBrush(w.guiColor("background")))
		guiGDI32.NewProc("SelectObject").Call(item.DC, w.guiBrush(w.guiColor(fill)))
		pen, _, _ := guiGDI32.NewProc("GetStockObject").Call(8) // NULL_PEN
		guiGDI32.NewProc("SelectObject").Call(item.DC, pen)
		radius := uintptr(guiAtDPI(8, w.guiDPI(item.Window)))
		guiGDI32.NewProc("RoundRect").Call(item.DC, uintptr(item.Rect.Left), uintptr(item.Rect.Top), uintptr(item.Rect.Right), uintptr(item.Rect.Bottom), radius, radius)
		font, _, _ := guiSendMessage.Call(item.Window, 0x31, 0, 0)
		guiGDI32.NewProc("SelectObject").Call(item.DC, font)
		guiGDI32.NewProc("SetTextColor").Call(item.DC, uintptr(w.guiColor(text)))
		guiGDI32.NewProc("SetBkMode").Call(item.DC, 1)
		label, _ := guiControlText(item.Window)
		guiUser32.NewProc("DrawTextW").Call(item.DC, uintptr(unsafe.Pointer(guiUTF16(label))), ^uintptr(0), uintptr(unsafe.Pointer(&item.Rect)), 0x8025)
		if item.State&0x10 != 0 {
			focus := guiRect{item.Rect.Left + 4, item.Rect.Top + 4, item.Rect.Right - 4, item.Rect.Bottom - 4}
			guiUser32.NewProc("DrawFocusRect").Call(item.DC, uintptr(unsafe.Pointer(&focus)))
		}
		return 1, true
	case 0x1a, 0x31a: // settings/theme change
		w.guiReadContrast()
		guiUser32.NewProc("RedrawWindow").Call(hwnd, 0, 0, 0x185)
	}
	return 0, false
}

func (w *desktopWindow) guiReleaseStyle() {
	if w.appearance == nil {
		return
	}
	for _, fonts := range w.appearance.fonts {
		for _, font := range fonts {
			guiDeleteObject.Call(font)
		}
	}
	for _, brush := range w.appearance.brushes {
		guiDeleteObject.Call(brush)
	}
	w.appearance, w.font = nil, 0
}
