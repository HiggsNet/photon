package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/HiggsNet/photon/internal/photonwindows"
)

func TestFrontendWorkerRejectsConfigChangedDuringElevation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "photon.yaml")
	if err := os.WriteFile(path, []byte("changed configuration"), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	stream := frontendStream{Reader: strings.NewReader(""), Writer: &output}
	if code := runFrontendBackend(context.Background(), path, stream, strings.Repeat("0", 64), io.Discard); code != 1 {
		t.Fatalf("exit code = %d", code)
	}
	if _, err := photonwindows.ReadControlReady(&output); err == nil || !strings.Contains(err.Error(), "configuration changed during elevation") {
		t.Fatalf("startup error = %v", err)
	}
}
