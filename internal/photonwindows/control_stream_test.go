package photonwindows

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestControlStreamStopsAndReleasesState(t *testing.T) {
	for _, stop := range []bool{false, true} {
		t.Run(map[bool]string{false: "frontend lost", true: "stop acknowledged"}[stop], func(t *testing.T) {
			config := autoJoinConfig(t)
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			_ = client.SetDeadline(time.Now().Add(10 * time.Second))
			_ = server.SetDeadline(time.Now().Add(10 * time.Second))
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			daemon := NewDaemon(config, slog.New(slog.NewTextHandler(io.Discard, nil)))
			go func() { done <- RunControlStream(ctx, daemon, strings.Repeat("0", 64), server) }()
			ready, err := ReadControlReady(client)
			if err != nil || ready.PID != os.Getpid() || ready.StatePath != config.State.Path {
				t.Fatalf("startup: %+v, %v", ready, err)
			}
			response, err := ExchangeControl(client, "status")
			if err != nil {
				t.Fatal(err)
			}
			var observation Observation
			if err := json.Unmarshal(response.Result, &observation); err != nil || !observation.Running || !observation.Admission.Pending || observation.Admission.JoinRequestB64 == "" || observation.Wintun.Configured {
				t.Fatalf("live pending state: %+v, %v", observation, err)
			}
			if stop {
				if _, err := ExchangeControl(client, "stop"); err != nil {
					t.Fatal(err)
				}
			} else {
				_ = client.Close()
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("backend did not join after frontend shutdown")
			}
			state, err := OpenState(config.State.Path, config.ManagedZone, config.TrustedRootPublicKey, 100*time.Millisecond)
			if err != nil {
				t.Fatalf("database still owned: %v", err)
			}
			state.Close()
		})
	}
}

func TestControlReadyPreservesNativeFailureAndRejectsInvalidEnvelope(t *testing.T) {
	var stream bytes.Buffer
	native := syscall.Errno(5)
	if err := WriteControlReady(&stream, ControlReady{}, native); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadControlReady(&stream); !errors.Is(err, native) {
		t.Fatalf("lost native startup error: %v", err)
	}
	for _, body := range []string{
		`{"version":2,"method":"ready","result":{"pid":1}}`,
		`{"version":1,"method":"status","result":{"pid":1}}`,
		`{"version":1,"method":"ready"}`,
		`{"version":1,"method":"ready","result":{"pid":1},"error":{"code":"failed","message":"both"}}`,
		`{"version":1,"method":"ready","result":{"pid":1}}`,
	} {
		stream.Reset()
		if err := writeControlFrame(&stream, []byte(body)); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadControlReady(&stream); err == nil {
			t.Fatalf("accepted invalid startup: %s", body)
		}
	}
}
