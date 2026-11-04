package photonwindows

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func testWintunReadEvents(t *testing.T) *wintunDevice {
	t.Helper()
	event := func(manualReset uint32) windows.Handle {
		t.Helper()
		h, err := windows.CreateEvent(nil, manualReset, 0, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = windows.CloseHandle(h) })
		return h
	}
	return &wintunDevice{
		stop: make(chan struct{}), reader: make(chan struct{}, 1),
		readEvent: event(0), stopEvent: event(1), cancelRead: event(1),
	}
}

func TestWintunReadableDoesNotWaitForWriter(t *testing.T) {
	device := testWintunReadEvents(t)
	device.writeMu.Lock()
	defer device.writeMu.Unlock()
	// The driver can signal between the empty check and WaitReadable. The
	// event must be observed even when the writer owns its direction lock.
	if err := windows.SetEvent(device.readEvent); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err := device.WaitReadable(ctx); err != nil {
		t.Fatalf("driver wake with a concurrent writer: %v", err)
	}
}

func TestWintunReadableResetsCallerCancelEvent(t *testing.T) {
	device := testWintunReadEvents(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if err := device.WaitReadable(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancel a blocked ring wait: %v", err)
	}

	next, stop := context.WithTimeout(t.Context(), time.Second)
	defer stop()
	if err := windows.SetEvent(device.readEvent); err != nil {
		t.Fatal(err)
	}
	if err := device.WaitReadable(next); err != nil {
		t.Fatalf("previous caller's cancellation affected next wait: %v", err)
	}
	// A leftover cancellation event would cause a successful OS wait with
	// the wrong event index instead of respecting the next caller deadline.
	last, stopLast := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer stopLast()
	if err := device.WaitReadable(last); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancel event was left signaled: %v", err)
	}
}

func TestWintunQuiesceWakesReaderWithoutClosingAdapter(t *testing.T) {
	device := testWintunReadEvents(t)
	done := make(chan error, 1)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	go func() { done <- device.WaitReadable(ctx) }()
	device.quiesce()
	select {
	case err := <-done:
		if !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("stopped reader: %v", err)
		}
	case <-ctx.Done():
		<-done
		t.Fatal("quiesce did not wake the reader")
	}
	if _, _, err := device.TryRead(); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("read admitted after quiesce: %v", err)
	}
	if device.closed.Load() {
		t.Fatal("quiesce invalidated IP Helper access before cleanup")
	}
}

func TestWintunReadCancellationWhileWaitingForReaderSlot(t *testing.T) {
	device := testWintunReadEvents(t)
	device.reader <- struct{}{}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if _, err := device.Read(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancel a concurrent read waiting for the reader slot: %v", err)
	}
}
