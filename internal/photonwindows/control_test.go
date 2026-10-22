package photonwindows

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type controlTestDaemon struct {
	observed    atomic.Int32
	stopped     atomic.Bool
	stopGate    <-chan struct{}
	stopStarted chan struct{}
}

func (d *controlTestDaemon) Observe(context.Context) (Observation, error) {
	d.observed.Add(1)
	return Observation{Running: true, Revision: 7}, nil
}
func (d *controlTestDaemon) Stop(ctx context.Context) error {
	if d.stopStarted != nil {
		close(d.stopStarted)
	}
	if d.stopGate != nil {
		select {
		case <-d.stopGate:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	d.stopped.Store(true)
	return nil
}

func TestControlStrictRequest(t *testing.T) {
	for _, body := range []string{
		`{}`, `null`, `[]`, `{"version":2,"method":"status"}`, `{"version":1,"method":"rebind"}`,
		`{"version":1,"method":"status","config":{}}`, `{"version":1,"version":1,"method":"status"}`,
		`{"version":1,"method":"status","method":"stop"}`, `{"version":1,"method":"status"}{}`,
		`{"version":1.0,"method":"status"}`, `{"version":"1","method":"status"}`,
	} {
		if _, err := decodeControlRequest([]byte(body)); err == nil {
			t.Errorf("accepted %s", body)
		}
	}
	for _, method := range []string{"status", "peers", "routes", "diagnostics", "stop"} {
		got, err := decodeControlRequest([]byte(`{"version":1,"method":"` + method + `"}`))
		if err != nil || got != method {
			t.Fatalf("%s: %q %v", method, got, err)
		}
	}
}
func TestControlFramesBounded(t *testing.T) {
	for _, size := range []uint32{0, controlMaxRequest + 1, ^uint32(0)} {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], size)
		if _, err := readControlFrame(bytes.NewReader(b[:]), controlMaxRequest); err == nil {
			t.Fatal("accepted oversized/zero frame")
		}
	}
	if _, err := readControlFrame(strings.NewReader("\x00\x00\x00\x02x"), controlMaxRequest); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
}
func TestControlExchangeUsesOnlyOwner(t *testing.T) {
	daemon := &controlTestDaemon{}
	for _, method := range []string{"status", "peers", "routes", "diagnostics", "stop"} {
		client, server := net.Pipe()
		deadline := time.Now().Add(time.Second)
		_ = client.SetDeadline(deadline)
		_ = server.SetDeadline(deadline)
		result := make(chan error, 1)
		go func() { defer server.Close(); result <- serveControlRequest(context.Background(), server, daemon) }()
		response, err := exchangeControl(client, method)
		client.Close()
		if err != nil || response.Version != 1 || response.Method != method || !json.Valid(response.Result) {
			t.Fatalf("%s: %+v %v", method, response, err)
		}
		if err := <-result; err != nil {
			t.Fatal(err)
		}
	}
	if daemon.observed.Load() != 4 || !daemon.stopped.Load() {
		t.Fatal("did not call one runtime owner")
	}
}
func TestControlStopWaitsForCleanup(t *testing.T) {
	gate := make(chan struct{})
	daemon := &controlTestDaemon{stopGate: gate}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	_ = client.SetDeadline(time.Now().Add(time.Second))
	_ = server.SetDeadline(time.Now().Add(time.Second))
	go func() { _ = serveControlRequest(context.Background(), server, daemon) }()
	done := make(chan error, 1)
	go func() { _, err := exchangeControl(client, "stop"); done <- err }()
	select {
	case err := <-done:
		t.Fatalf("stop replied before cleanup: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(gate)
	if err := <-done; err != nil || !daemon.stopped.Load() {
		t.Fatal("stop did not await cleanup", err)
	}
}
func TestControlEndpointDoesNotOpenState(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing", "state.db")
	a, err := ControlEndpoint(missing)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ControlEndpoint(filepath.Join(filepath.Dir(missing), ".", "state.db"))
	if err != nil || a != b {
		t.Fatal(a, b, err)
	}
	if !strings.HasPrefix(a, `\\.\pipe\Photon.Control.v1.`) || strings.Contains(a, "state.db") {
		t.Fatal(a)
	}
	if _, err := ControlEndpoint(""); err == nil {
		t.Fatal("empty state accepted")
	}
}
