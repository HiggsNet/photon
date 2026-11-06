package configedit

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"path/filepath"
	"testing"
)

func TestSaveFormPreservesMOBIKEWhenClientOmitsIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "photon.yaml")
	editor := New(path)
	form, err := editor.LoadForm()
	if err != nil {
		t.Fatal(err)
	}
	root, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	form.RootPublicKey, form.ManagedZone = base64.StdEncoding.EncodeToString(root), "leaf.catofes."
	form.SplitRoutes = "10.16.0.0/16"
	mobike := true
	form.MOBIKE = &mobike
	if err := editor.SaveForm(form); err != nil {
		t.Fatal(err)
	}
	form, err = editor.LoadForm()
	if err != nil {
		t.Fatal(err)
	}
	form.MOBIKE = nil
	if err := editor.SaveForm(form); err != nil {
		t.Fatal(err)
	}
	saved, err := editor.LoadForm()
	if err != nil || saved.MOBIKE == nil || !*saved.MOBIKE {
		t.Fatalf("saved MOBIKE = %v, %v", saved.MOBIKE, err)
	}
}
