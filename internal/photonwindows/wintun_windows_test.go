package photonwindows

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"
	"time"
)

// Run on an elevated, disposable Windows VM with the pinned signed DLL beside
// this executable. The adapter receives no address or route, so the test cannot
// divert the host's ordinary traffic.
func TestWintunNativeLifecycle(t *testing.T) {
	if os.Getenv("PHOTON_WINTUN_SMOKE") != "1" {
		t.Skip("requires pinned wintun.dll and an elevated test VM")
	}
	for n := 0; n < 2; n++ {
		ctx, cancel := context.WithCancel(context.Background())
		d, err := openWintun(ctx, fmt.Sprintf("PhotonTest-%d-%d", os.Getpid(), n), nil)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		t.Cleanup(d.Close)
		if d.luid == 0 {
			t.Fatal("missing adapter LUID")
		}
		readCtx, stopRead := context.WithTimeout(context.Background(), 20*time.Millisecond)
		// Windows can emit IPv6 control traffic as soon as the adapter exists,
		// even without our addresses/routes. Drain it under the same bounded
		// caller deadline; the lifecycle contract is cancellation, not silence.
		startupPackets := 0
		for {
			_, err = d.Read(readCtx)
			if err != nil {
				break
			}
			startupPackets++
		}
		stopRead()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("read deadline after %d startup packets: %v", startupPackets, err)
		}
		if err := d.Write(nil); err == nil {
			t.Fatal("accepted empty packet")
		}
		// A well-formed IPv6 packet with No Next Header exercises allocate/send;
		// no configured address means the OS drops it without a route mutation.
		packet := make([]byte, 40)
		packet[0], packet[6], packet[7] = 0x60, 59, 1
		packet[8], packet[9], packet[23] = 0xfe, 0x80, 1
		packet[24], packet[25], packet[39] = 0xfe, 0x80, 2
		if err := d.Write(packet); err != nil {
			t.Fatal(err)
		}
		cancel()
		select {
		case <-d.done:
		case <-time.After(2 * time.Second):
			t.Fatal("cancel did not stop native receive loop")
		}
		d.Close()
		d.Close()
		if _, err := d.Read(context.Background()); !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("read after close: %v", err)
		}
		if err := d.Write(packet); !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("write after close: %v", err)
		}
		t.Logf("adapter generation %d created, ring write accepted, cancel joined, closed", n)
	}
}
