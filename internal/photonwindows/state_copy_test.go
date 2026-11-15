package photonwindows

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCopyStatePreservesIdentityAndRevisionAndRejectsLiveSource(t *testing.T) {
	source, _, root, private := saveCommonState(t, 7)
	config := &Config{ManagedZone: "node-a.catofes.", TrustedRootPublicKey: root, State: StateConfig{Path: source}}
	destination := filepath.Join(t.TempDir(), "copy.db")
	live, err := OpenState(source, config.ManagedZone, root, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := CopyState(config, destination); err == nil {
		t.Fatal("copied a live identity")
	}
	if _, err := os.Stat(destination); !os.IsNotExist(err) {
		t.Fatalf("failed copy published identity: %v", err)
	}
	if err := live.Close(); err != nil {
		t.Fatal(err)
	}
	if err := CopyState(config, destination); err != nil {
		t.Fatal(err)
	}
	copy, err := OpenState(destination, config.ManagedZone, root, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	view, err := copy.ReadView(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if view.Revision != 7 || !view.State.IdentityPrivateKey.Equal(private) {
		t.Fatal("copy changed identity or revision")
	}
	if err := copy.Close(); err != nil {
		t.Fatal(err)
	}
	if err := CopyState(config, destination); err == nil {
		t.Fatal("overwrote an existing identity")
	}
}
