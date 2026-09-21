package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestRootInitControlGuard(t *testing.T) {
	for _, mode := range []string{"absent", "rejected", "unexpected_success"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "control.sock")
			t.Setenv("PHOTON_CONTROL_SOCKET", path)
			if mode != "absent" {
				listener, err := net.Listen("unix", path)
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				go func() {
					conn, err := listener.Accept()
					if err != nil {
						return
					}
					defer conn.Close()
					_ = conn.SetDeadline(time.Now().Add(time.Second))
					var request controlRequest
					if err := json.NewDecoder(conn).Decode(&request); err != nil {
						return
					}
					response := controlResponse{OK: mode == "unexpected_success"}
					if !response.OK {
						response.Error = "daemon has loaded state"
					}
					_ = json.NewEncoder(conn).Encode(response)
				}()
			}
			// Even --direct must not bypass the running-daemon guard.
			err := checkRootInitViaControl(nil)
			if (err != nil) != (mode != "absent") {
				t.Fatalf("checkRootInitViaControl() = %v for %s", err, mode)
			}
		})
	}
}

func TestControlSocketPathDataDirScope(t *testing.T) {
	t.Setenv("PHOTON_CONTROL_SOCKET", "")
	t.Setenv("PHOTON_CONTROL_SOCKET_SCOPE", "data-dir")

	dataDir := t.TempDir()
	got := controlSocketPath(&appConfig{DataDir: dataDir})
	want := filepath.Join(dataDir, controlSocketName)
	if got != want {
		t.Fatalf("controlSocketPath() = %q, want %q", got, want)
	}
}

func TestControlSocketPathExplicitOverridePrecedesDataDirScope(t *testing.T) {
	t.Setenv("PHOTON_CONTROL_SOCKET", "/tmp/explicit-photon.sock")
	t.Setenv("PHOTON_CONTROL_SOCKET_SCOPE", "data-dir")

	got := controlSocketPath(&appConfig{DataDir: t.TempDir()})
	if got != "/tmp/explicit-photon.sock" {
		t.Fatalf("controlSocketPath() = %q, want explicit override", got)
	}
}

func TestIsControlSocketUnavailable(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "missing", err: &net.OpError{Op: "dial", Net: "unix", Err: os.ErrNotExist}, want: true},
		{name: "refused", err: &net.OpError{Op: "dial", Net: "unix", Err: syscall.ECONNREFUSED}, want: true},
		{name: "permission", err: &net.OpError{Op: "dial", Net: "unix", Err: os.ErrPermission}, want: false},
		{name: "reset", err: &net.OpError{Op: "read", Net: "unix", Err: syscall.ECONNRESET}, want: false},
		{name: "deadline", err: &net.OpError{Op: "read", Net: "unix", Err: os.ErrDeadlineExceeded}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isControlSocketUnavailable(tt.err); got != tt.want {
				t.Fatalf("isControlSocketUnavailable(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}
