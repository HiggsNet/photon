package main

import "github.com/HiggsNet/photon/internal/photonwindows/configedit"

type desktopConfigForm = configedit.Form
type desktopBootstrapRow = configedit.BootstrapRow

var (
	defaultDesktopConfigForm = configedit.DefaultForm
	desktopFormLines         = configedit.Lines
	desktopFormText          = configedit.FormText
	desktopFormFromConfig    = configedit.FromConfig
)

func (b *desktopBackend) LoadForm() (desktopConfigForm, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.editor.LoadForm()
}

func (b *desktopBackend) SaveForm(form desktopConfigForm) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.editor.SaveForm(form)
}
