//go:build windows

package main

import "unsafe"

// These controls retain their native edit/list/button behavior. Styling only
// supplies a visual hierarchy and fonts; no configuration or draft lives here.
func (w *desktopWindow) styleSettingsControls() {
	for _, fields := range [][]int{guiBasicFields, guiGatewayFields, guiRouteFields, guiAdvancedFields} {
		for _, id := range fields {
			kind := "body"
			if id < 2100 {
				kind = "edit"
			}
			w.guiStyleControl(w.controls[id], kind)
			w.guiApplyFont(w.controls[id], "body")
			if label := w.formLabels[id]; label != 0 {
				w.guiStyleControl(label, "body")
				w.guiApplyFont(label, "body")
			}
		}
	}
	for _, id := range []int{guiRootFieldID, guiManagedFieldID, guiAllowedFieldID, guiSplitFieldID, guiBootstrapListID, guiBootstrapPeerID, guiBootstrapAddressID, guiStateFieldID, guiOverlayFieldID, guiListenFieldID, guiInitialFieldID, guiMaxFieldID} {
		w.guiApplyFont(w.controls[id], "mono")
	}
	for _, id := range []int{guiAllowedFieldID, guiSplitFieldID, guiBootstrapListID} {
		w.guiStyleControl(w.formLabels[id], "section")
		w.guiApplyFont(w.formLabels[id], "section")
	}
	for _, id := range []int{guiBasicPageID, guiGatewayPageID, guiRoutePageID, guiAdvancedPageID, guiReloadID} {
		w.guiStyleControl(w.controls[id], "body")
		w.guiApplyFont(w.controls[id], "body")
	}
	w.guiStyleControl(w.controls[guiPageTitleID], "title")
	w.guiApplyFont(w.controls[guiPageTitleID], "title")
	for _, id := range []int{guiPageHelpID, guiSettingsNoteID} {
		w.guiStyleControl(w.controls[id], "muted")
		w.guiApplyFont(w.controls[id], "body")
	}
	w.guiStyleControl(w.controls[guiSaveID], "primary")
	w.guiApplyFont(w.controls[guiSaveID], "body")
	for id, cue := range map[int]string{
		guiRootFieldID:        "管理员提供的 Base64 公钥",
		guiManagedFieldID:     "例如 node.example.",
		guiAllowedInputID:     "例如 *.example. 或 gateway.example.",
		guiRouteInputID:       "例如 10.0.0.0/24 或 fd00::/64",
		guiBootstrapPeerID:    "例如 gateway.example.",
		guiBootstrapAddressID: "host:port 或 [IPv6]:port",
		guiStateFieldID:       `例如 C:\Photon\photon.db`,
		guiOverlayFieldID:     "main", guiListenFieldID: "0.0.0.0:33434",
		guiAdapterFieldID: "Photon Windows", guiMTUFieldID: "1400",
		guiInitialFieldID: "例如 1s", guiMaxFieldID: "例如 1m",
	} {
		guiSendMessage.Call(w.controls[id], 0x1501, 0, uintptr(unsafe.Pointer(guiUTF16(cue)))) // EM_SETCUEBANNER
	}
}

// Coordinates are logical 96-DPI units. Additional height goes to the lists,
// while action rows and the shared footer remain separated at the minimum size.
func (w *desktopWindow) layoutSettings() {
	if w.settings == 0 {
		return
	}
	width, height := w.guiClientSize(w.settings)
	if width <= 0 || height <= 0 {
		return
	}
	move := w.guiMove
	const margin, gap = 24, 16
	content := width - 2*margin
	half := (content - gap) / 2
	field := func(id, x, y, wid, hei int) {
		move(w.formLabels[id], x, y, wid, 22)
		move(w.controls[id], x, y+26, wid, hei)
	}
	for column, id := range []int{guiBasicPageID, guiGatewayPageID, guiRoutePageID, guiAdvancedPageID} {
		move(w.controls[id], margin+column*136, 16, 128, 32)
	}
	move(w.controls[guiPageTitleID], margin, 66, content, 30)
	move(w.controls[guiPageHelpID], margin, 104, content, 44)

	field(guiRootFieldID, margin, 172, content, 34)
	field(guiManagedFieldID, margin, 264, content, 34)

	extra := max(0, height-661)
	rulesHeight := 68 + extra/4
	field(guiAllowedFieldID, margin, 154, content, rulesHeight)
	ruleInputY := 154 + 26 + rulesHeight + 12
	move(w.formLabels[guiAllowedInputID], 0, 0, 0, 0)
	move(w.controls[guiAllowedInputID], margin, ruleInputY, content-326, 32)
	for column, id := range []int{guiAllowedAddID, guiAllowedUpdateID, guiAllowedDeleteID, guiAllowedClearID} {
		move(w.controls[id], width-margin-314+column*80, ruleInputY, 74, 32)
	}
	bootstrapY := ruleInputY + 56
	bootstrapHeight := 80 + extra - extra/4
	field(guiBootstrapListID, margin, bootstrapY, content, bootstrapHeight)
	peerY := bootstrapY + 26 + bootstrapHeight + 12
	field(guiBootstrapPeerID, margin, peerY, half, 32)
	field(guiBootstrapAddressID, margin+half+gap, peerY, half, 32)
	for column, id := range []int{guiBootstrapAddID, guiBootstrapUpdateID, guiBootstrapDeleteID, guiBootstrapClearID} {
		move(w.controls[id], margin+column*128, peerY+70, 116, 32)
	}

	routeListHeight := 226 + extra
	field(guiSplitFieldID, margin, 158, content, routeListHeight)
	field(guiRouteInputID, margin, 158+26+routeListHeight+16, content, 32)
	for column, id := range []int{guiRouteAddID, guiRouteUpdateID, guiRouteDeleteID, guiRouteClearID} {
		move(w.controls[id], margin+column*128, 158+26+routeListHeight+88, 116, 32)
	}

	field(guiStateFieldID, margin, 154, content, 32)
	for row, ids := range [][]int{{guiOverlayFieldID, guiListenFieldID}, {guiAdapterFieldID, guiMTUFieldID}, {guiInitialFieldID, guiMaxFieldID}, {guiLogFieldID}} {
		for column, id := range ids {
			controlHeight := 32
			if id == guiLogFieldID {
				controlHeight = 180
			}
			field(id, margin+column*(half+gap), 232+row*76, half, controlHeight)
		}
	}
	move(w.controls[guiSettingsNoteID], margin, height-98, content, 42)
	move(w.controls[guiReloadID], width-margin-252, height-48, 112, 32)
	move(w.controls[guiSaveID], width-margin-128, height-48, 128, 32)
}
