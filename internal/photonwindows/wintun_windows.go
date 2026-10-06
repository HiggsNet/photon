package photonwindows

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
)

// The official 0.14.1 signed amd64 DLL, shipped adjacent to the executable.
// See third_party/wintun/README.md. Never search CWD or PATH for a driver DLL.
const wintunAMD64SHA256 = "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce"

func checkWintunDLL() error {
	if runtime.GOARCH != "amd64" {
		return errors.New("Wintun packaging currently supports windows/amd64 only")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	f, err := os.Open(filepath.Join(filepath.Dir(exe), "wintun.dll"))
	if err != nil {
		return fmt.Errorf("open official adjacent wintun.dll: %w", err)
	}
	defer f.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(f, 1<<20)); err != nil {
		return err
	}
	if fmt.Sprintf("%x", hash.Sum(nil)) != wintunAMD64SHA256 {
		return errors.New("wintun.dll does not match pinned official 0.14.1 amd64 binary")
	}
	return nil
}

// wintunDevice owns a newly created adapter and one ring session. The reader
// copies and releases every borrowed ring packet before handing data to Go.
// Close cancels the wait, joins the reader, then ends the ring and adapter.
// IP Helper configuration and packet authorization belong to the caller.
type wintunDevice struct {
	adapter    *wintun.Adapter
	session    wintun.Session
	luid       uint64
	cancel     context.CancelFunc
	done       chan struct{}
	packets    chan []byte
	mu         sync.Mutex // serializes writes with ring teardown
	closed     bool
	err        error
	unregister func()
}

func openWintun(ctx context.Context, name string, guid *windows.GUID) (*wintunDevice, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := checkWintunDLL(); err != nil {
		return nil, err
	}
	if guid == nil {
		generated, err := windows.GenerateGUID()
		if err != nil {
			return nil, err
		}
		guid = &generated
	}
	unregister := registerOwnedAdapter(*guid)
	// Create, never attach to another service's existing adapter/session.
	a, err := wintun.CreateAdapter(name, "Photon", guid)
	if err != nil {
		unregister()
		return nil, err
	}
	session, err := a.StartSession(1 << 20)
	if err != nil {
		a.Close()
		unregister()
		return nil, err
	}
	stopEvent, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		session.End()
		a.Close()
		unregister()
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	d := &wintunDevice{adapter: a, session: session, luid: a.LUID(), cancel: cancel,
		done: make(chan struct{}), packets: make(chan []byte, 64), unregister: unregister}
	go d.receive(ctx, stopEvent)
	return d, nil
}

func (d *wintunDevice) receive(ctx context.Context, stopEvent windows.Handle) {
	wakeDone := make(chan struct{})
	stopWake := context.AfterFunc(ctx, func() {
		defer close(wakeDone)
		_ = windows.SetEvent(stopEvent)
	})
	defer func() {
		if !stopWake() {
			<-wakeDone // do not close a handle while the callback still uses it
		}
		d.cancel()
		d.mu.Lock()
		d.closed = true
		d.session.End()
		_ = d.adapter.Close() // upstream wraps a void API; its return is undefined
		d.unregister()
		d.mu.Unlock()
		_ = windows.CloseHandle(stopEvent)
		close(d.packets)
		close(d.done)
	}()
	for ctx.Err() == nil {
		packet, err := d.session.ReceivePacket()
		if err == nil {
			copyPacket := append([]byte(nil), packet...)
			d.session.ReleaseReceivePacket(packet)
			select {
			case d.packets <- copyPacket:
			default: // bounded ingress: drop under load, never pin ring memory
			}
			continue
		}
		if errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
			_, err = windows.WaitForMultipleObjects([]windows.Handle{stopEvent, d.session.ReadWaitEvent()}, false, windows.INFINITE)
			if err == nil {
				continue
			}
		}
		d.mu.Lock()
		d.err = err
		d.mu.Unlock()
		return
	}
}

func (d *wintunDevice) Read(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case packet, ok := <-d.packets:
		d.mu.Lock()
		defer d.mu.Unlock()
		if !ok || d.closed {
			return nil, errors.Join(io.ErrClosedPipe, d.err)
		}
		return packet, nil
	}
}

// Write copies a complete IP packet into the driver. Allocate failure owns no
// buffer; every successful allocation is sent exactly once under the lock.
func (d *wintunDevice) Write(packet []byte) error {
	if len(packet) == 0 || len(packet) > wintun.PacketSizeMax {
		return errors.New("invalid Wintun packet size")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return io.ErrClosedPipe
	}
	buffer, err := d.session.AllocateSendPacket(len(packet))
	if err != nil {
		return err
	}
	copy(buffer, packet)
	d.session.SendPacket(buffer)
	return nil
}

func (d *wintunDevice) Close() {
	d.cancel()
	<-d.done
}
