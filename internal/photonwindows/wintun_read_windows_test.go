package photonwindows

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

func TestWintunDetachedReadDoesNotWaitForWriter(t *testing.T) {
	device := &wintunDevice{packets: make(chan []byte, 1)}
	device.packets <- []byte{42}

	device.mu.Lock()
	done := make(chan error, 1)
	go func() {
		packet, err := device.Read(context.Background())
		if err == nil && (len(packet) != 1 || packet[0] != 42) {
			err = errors.New("unexpected detached packet")
		}
		done <- err
	}()
	select {
	case err := <-done:
		device.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		device.mu.Unlock()
		<-done
		t.Fatal("detached read waited for the writer lock")
	}

	device.packets <- []byte{43}
	device.closed.Store(true)
	if _, err := device.Read(context.Background()); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("queued packet survived device teardown: %v", err)
	}
}
