//go:build windows

package photonwindows

import (
	"context"
	"errors"
	"fmt"
	"io"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const controlPipeSDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)"

var errControlPrivileges = errors.New("control endpoint requires LocalSystem or an enabled Administrators token")

// ControlServer reserves exactly one instance for its entire lifetime. Reusing
// the same handle closes the gap in which a different process could steal the
// name between clients. Excess clients wait only within their own deadline.
type ControlServer struct {
	handle          windows.Handle
	ctx             context.Context
	cancel          context.CancelFunc
	mu              sync.Mutex
	started, closed bool
	done            chan struct{}
	ready           chan struct{}
}

func ListenControl(statePath string) (*ControlServer, error) {
	if err := controlPrivilegedToken(windows.GetCurrentProcessToken()); err != nil {
		return nil, err
	}
	endpoint, err := ControlEndpoint(statePath)
	if err != nil {
		return nil, err
	}
	name, err := windows.UTF16PtrFromString(endpoint)
	if err != nil {
		return nil, err
	}
	sd, err := windows.SecurityDescriptorFromString(controlPipeSDDL)
	if err != nil {
		return nil, err
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	handle, err := windows.CreateNamedPipe(name, windows.PIPE_ACCESS_DUPLEX|windows.FILE_FLAG_OVERLAPPED|windows.FILE_FLAG_FIRST_PIPE_INSTANCE,
		windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS,
		1, 4096, 4096, 0, &sa)
	runtime.KeepAlive(sd)
	if err != nil {
		return nil, fmt.Errorf("reserve local control endpoint: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &ControlServer{handle: handle, ctx: ctx, cancel: cancel, done: make(chan struct{}), ready: make(chan struct{})}, nil
}

func (s *ControlServer) Serve(ctx context.Context, daemon ControlDaemon) error {
	s.mu.Lock()
	if s.started || s.closed {
		s.mu.Unlock()
		return errors.New("control server already started or closed")
	}
	s.started = true
	close(s.ready)
	s.mu.Unlock()
	defer close(s.done)
	defer windows.CloseHandle(s.handle)
	stop := context.AfterFunc(ctx, s.cancel)
	defer stop()
	for s.ctx.Err() == nil {
		_, err := controlPipeOperation(s.ctx, s.handle, func(o *windows.Overlapped, n *uint32) error {
			err := windows.ConnectNamedPipe(s.handle, o)
			if errors.Is(err, windows.ERROR_PIPE_CONNECTED) {
				return nil
			}
			return err
		})
		if err != nil {
			if s.ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept control client: %w", err)
		}
		// Once accepted, finish or time out this one request even when Run exits.
		// Close waits for this drain, so Stop's cleanup result reaches its caller.
		requestCtx, cancel := context.WithTimeout(context.Background(), controlTimeout)
		_ = serveControlRequest(requestCtx, &controlPipeStream{ctx: requestCtx, handle: s.handle}, daemon)
		cancel()
		if err := windows.DisconnectNamedPipe(s.handle); err != nil && !errors.Is(err, windows.ERROR_PIPE_NOT_CONNECTED) {
			return err
		}
	}
	return nil
}

func (s *ControlServer) Close() error {
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		s.cancel()
		if !s.started {
			_ = windows.CloseHandle(s.handle)
			close(s.done)
		}
	}
	s.mu.Unlock()
	<-s.done
	return nil
}

// RunControlled makes the pipe reservation precede all runtime resources.
// Daemon remains the only state, transport, and device owner.
func RunControlled(ctx context.Context, daemon *Daemon, statePath string) error {
	server, err := ListenControl(statePath)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		err := server.Serve(ctx, daemon)
		if err != nil {
			cancel()
		}
		result <- err
	}()
	<-server.ready
	runErr := daemon.Run(ctx)
	_ = server.Close()
	return errors.Join(runErr, <-result)
}

func CallControl(ctx context.Context, statePath, method string) (ControlResponse, error) {
	var empty ControlResponse
	if !controlMethod(method) {
		return empty, errors.New("unsupported control method")
	}
	endpoint, err := ControlEndpoint(statePath)
	if err != nil {
		return empty, err
	}
	name, err := windows.UTF16PtrFromString(endpoint)
	if err != nil {
		return empty, err
	}
	ctx, cancel := context.WithTimeout(ctx, controlTimeout)
	defer cancel()
	var handle windows.Handle
	for {
		if err := ctx.Err(); err != nil {
			return empty, err
		}
		handle, err = windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING,
			windows.FILE_FLAG_OVERLAPPED|windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
		if err == nil {
			break
		}
		if !errors.Is(err, windows.ERROR_PIPE_BUSY) && !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			return empty, err
		}
		timer := time.NewTimer(20 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return empty, ctx.Err()
		case <-timer.C:
		}
	}
	defer windows.CloseHandle(handle)
	if err := controlVerifyServer(handle); err != nil {
		return empty, err
	}
	return exchangeControl(&controlPipeStream{ctx: ctx, handle: handle}, method)
}

// The DACL protects the real server, not a name squatted before startup. Check
// the connected server's process token before transmitting even a stop request.
// Identification SQOS above prevents a fake server impersonating this client.
func controlVerifyServer(handle windows.Handle) error {
	var pid uint32
	if err := windows.GetNamedPipeServerProcessId(handle, &pid); err != nil {
		return err
	}
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return fmt.Errorf("verify control server process: %w", err)
	}
	defer windows.CloseHandle(process)
	var token windows.Token
	if err := windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token); err != nil {
		return err
	}
	defer token.Close()
	return controlPrivilegedToken(token)
}

func controlPrivilegedToken(token windows.Token) error {
	user, err := token.GetTokenUser()
	if err != nil {
		return err
	}
	if user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		return nil
	}
	groups, err := token.GetTokenGroups()
	if err != nil {
		return err
	}
	for _, group := range groups.AllGroups() {
		if group.Sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) && group.Attributes&windows.SE_GROUP_ENABLED != 0 && group.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY == 0 {
			return nil
		}
	}
	return errControlPrivileges
}

type controlPipeStream struct {
	ctx    context.Context
	handle windows.Handle
}

func (s *controlPipeStream) Read(p []byte) (int, error) {
	n, err := controlPipeOperation(s.ctx, s.handle, func(o *windows.Overlapped, n *uint32) error { return windows.ReadFile(s.handle, p, n, o) })
	runtime.KeepAlive(p)
	if err == nil && n == 0 {
		err = io.EOF
	}
	return int(n), err
}
func (s *controlPipeStream) Write(p []byte) (int, error) {
	n, err := controlPipeOperation(s.ctx, s.handle, func(o *windows.Overlapped, n *uint32) error { return windows.WriteFile(s.handle, p, n, o) })
	runtime.KeepAlive(p)
	return int(n), err
}

// Cancellation must drain the OVERLAPPED before its buffers/event leave scope.
// Never close a handle with pending operations or use a blocking pipe flush.
func controlPipeOperation(ctx context.Context, handle windows.Handle, start func(*windows.Overlapped, *uint32) error) (uint32, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(event)
	overlap := windows.Overlapped{HEvent: event}
	var transferred uint32
	err = start(&overlap, &transferred)
	if !errors.Is(err, windows.ERROR_IO_PENDING) {
		return transferred, err
	}
	for {
		if err := ctx.Err(); err != nil {
			_ = windows.CancelIoEx(handle, &overlap)
			_ = windows.GetOverlappedResult(handle, &overlap, &transferred, true)
			return transferred, err
		}
		status, err := windows.WaitForSingleObject(event, 25)
		if err != nil {
			_ = windows.CancelIoEx(handle, &overlap)
			_ = windows.GetOverlappedResult(handle, &overlap, &transferred, true)
			return transferred, err
		}
		if status == windows.WAIT_OBJECT_0 {
			err := windows.GetOverlappedResult(handle, &overlap, &transferred, false)
			return transferred, err
		}
	}
}
