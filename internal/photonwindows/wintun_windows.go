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
	"sync/atomic"

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

// wintunDevice owns one adapter and ring session. The caller reads directly
// from Wintun and receives a detached copy, so no Go queue drains the ring.
// Each direction has its own gate. Teardown wakes readers and joins both
// directions before releasing the rings and read wait handles.
type wintunDevice struct {
	adapter    *wintun.Adapter
	session    wintun.Session
	luid       uint64
	cancel     context.CancelFunc
	stop       chan struct{}
	done       chan struct{}
	stopOnce   sync.Once
	closeOnce  sync.Once
	mu         sync.Mutex // serializes IP Helper with adapter destruction
	closed     atomic.Bool
	stopped    atomic.Bool
	writeMu    sync.Mutex
	reader     chan struct{} // serialization token, never holds packet data
	readEvent  windows.Handle
	stopEvent  windows.Handle
	cancelRead windows.Handle
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
	// Create, never attach to another service's existing adapter/session. The
	// DLL's convenience naming path can rename a foreign NIC on collision, so
	// create under an unpredictable temporary alias and rename only our GUID.
	a, err := createWintunWithOwnedName(name, guid)
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
	cancelRead, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		_ = windows.CloseHandle(stopEvent)
		session.End()
		a.Close()
		unregister()
		return nil, err
	}
	lifetime, cancel := context.WithCancel(ctx)
	d := &wintunDevice{
		adapter: a, session: session, luid: a.LUID(), cancel: cancel,
		stop: make(chan struct{}), done: make(chan struct{}), reader: make(chan struct{}, 1),
		readEvent: session.ReadWaitEvent(), stopEvent: stopEvent, cancelRead: cancelRead,
		unregister: unregister,
	}
	context.AfterFunc(lifetime, d.Close)
	return d, nil
}

func (d *wintunDevice) acquireReader(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if d.stopped.Load() {
		return io.ErrClosedPipe
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-d.stop:
		return io.ErrClosedPipe
	case d.reader <- struct{}{}:
		if !d.stopped.Load() {
			return nil
		}
		<-d.reader
		return io.ErrClosedPipe
	}
}

func (d *wintunDevice) releaseReader() {
	<-d.reader
}

// readRing is called while the reader owns the session lifetime. Copy before
// releasing the borrowed Wintun memory, including when Close races this read.
func (d *wintunDevice) readRing() ([]byte, bool, error) {
	if d.stopped.Load() {
		return nil, false, io.ErrClosedPipe
	}
	packet, err := d.session.ReceivePacket()
	if errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, errors.Join(io.ErrClosedPipe, err)
	}
	detached := append([]byte(nil), packet...)
	d.session.ReleaseReceivePacket(packet)
	if d.stopped.Load() {
		return nil, false, io.ErrClosedPipe
	}
	return detached, true, nil
}

// TryRead pulls an immediately available packet. A nil error with ok=false
// means the caller can retry later; the session's only reader may wait.
func (d *wintunDevice) TryRead() ([]byte, bool, error) {
	if d.stopped.Load() {
		return nil, false, io.ErrClosedPipe
	}
	select {
	case d.reader <- struct{}{}:
		defer d.releaseReader()
		return d.readRing()
	default:
		return nil, false, nil
	}
}

func (d *wintunDevice) Read(ctx context.Context) ([]byte, error) {
	if err := d.acquireReader(ctx); err != nil {
		return nil, err
	}
	defer d.releaseReader()
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if packet, ok, err := d.readRing(); ok || err != nil {
			return packet, err
		}
		if err := d.waitReadable(ctx); err != nil {
			return nil, err
		}
	}
}

// WaitReadable waits on the driver readiness hint without consuming a packet.
// The sole reader calls it after TryRead reports an empty ring and retries
// TryRead on wake, since the auto-reset driver event can also be stale.
func (d *wintunDevice) WaitReadable(ctx context.Context) error {
	if err := d.acquireReader(ctx); err != nil {
		return err
	}
	defer d.releaseReader()
	return d.waitReadable(ctx)
}

func (d *wintunDevice) waitReadable(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if d.stopped.Load() {
		return io.ErrClosedPipe
	}
	handles := [...]windows.Handle{d.stopEvent, d.readEvent, d.cancelRead}
	count := 2
	var stopWake func() bool
	var wakeDone chan struct{}
	if ctx.Done() != nil {
		count = 3
		wakeDone = make(chan struct{})
		stopWake = context.AfterFunc(ctx, func() {
			_ = windows.SetEvent(d.cancelRead)
			close(wakeDone)
		})
	}
	status, err := windows.WaitForMultipleObjects(handles[:count], false, windows.INFINITE)
	// Only this reader can use the reusable event. If its callback ran,
	// join it before resetting the event or releasing the lifetime lock.
	if stopWake != nil && !stopWake() {
		<-wakeDone
		if resetErr := windows.ResetEvent(d.cancelRead); err == nil {
			err = resetErr
		}
	}
	if d.stopped.Load() {
		return io.ErrClosedPipe
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if err != nil {
		return err
	}
	if status != windows.WAIT_OBJECT_0+1 {
		return fmt.Errorf("unexpected Wintun read wait status %#x", status)
	}
	return nil
}

// Write copies a complete IP packet into the driver. Allocate failure owns no
// buffer; every successful allocation is sent exactly once under the lock.
func (d *wintunDevice) Write(packet []byte) error {
	if len(packet) == 0 || len(packet) > wintun.PacketSizeMax {
		return errors.New("invalid Wintun packet size")
	}
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	if d.stopped.Load() {
		return io.ErrClosedPipe
	}
	buffer, err := d.session.AllocateSendPacket(len(packet))
	if errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
		return errPacketDeviceFull
	}
	if err != nil {
		return err
	}
	copy(buffer, packet)
	d.session.SendPacket(buffer)
	return nil
}

// quiesce rejects new I/O and wakes waiters while leaving the adapter intact
// for configuredPacketDevice's IP Helper cleanup.
func (d *wintunDevice) quiesce() {
	d.stopOnce.Do(func() {
		d.stopped.Store(true)
		close(d.stop)
		_ = windows.SetEvent(d.stopEvent)
	})
}

func (d *wintunDevice) Close() {
	d.closeOnce.Do(func() {
		d.quiesce()
		d.cancel()
		d.mu.Lock()
		defer d.mu.Unlock()
		d.closed.Store(true)
		d.reader <- struct{}{}
		defer d.releaseReader()
		d.writeMu.Lock()
		defer d.writeMu.Unlock()
		d.session.End()
		_ = d.adapter.Close() // upstream wraps a void API; its return is undefined
		d.unregister()
		_ = windows.CloseHandle(d.stopEvent)
		_ = windows.CloseHandle(d.cancelRead)
		close(d.done)
	})
}
