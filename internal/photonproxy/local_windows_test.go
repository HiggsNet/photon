package photonproxy

import (
	"context"
	"crypto/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Microsoft/go-winio"
)

func TestWindowsProxyPrivateStateAndRotation(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "proxy-state")
	if err := prepareV2StateDir(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "state.db")
	if err := os.WriteFile(path, []byte("state"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := prepareV2StateDir(dir); err != nil {
		t.Fatalf("state ACL did not inherit: %v", err)
	}
	if err := requestV2Rotation(dir, v2RotationRequest{ID: "one", TLS: true}); err != nil {
		t.Fatal(err)
	}
	if err := requestV2Rotation(dir, v2RotationRequest{ID: "two", TLS: true}); err == nil {
		t.Fatal("overwrote a pending rotation")
	}
}

func TestWindowsProxyAdminPipe(t *testing.T) {
	path := `\\.\pipe\photon-proxy-test-` + rand.Text()
	listener, err := listenV2AdminSocket(path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})}
	defer server.Close()
	go func() { _ = server.Serve(listener) }()
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return winio.DialPipeContext(ctx, path)
	}}
	defer transport.CloseIdleConnections()
	response, err := (&http.Client{Transport: transport, Timeout: 5 * time.Second}).Get("http://local/v1/admin")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("pipe HTTP status = %s", response.Status)
	}
}
