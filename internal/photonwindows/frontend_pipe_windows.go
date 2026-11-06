//go:build windows

package photonwindows

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const frontendPipePrefix = `\\.\pipe\Photon.Frontend.v1.`

func FrontendNeedsElevation() bool {
	return controlPrivilegedToken(windows.GetCurrentProcessToken()) != nil
}

func ListenFrontendPipe() (windows.Handle, string, error) {
	name := frontendPipePrefix + rand.Text()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return 0, "", err
	}
	// An administrator may supply credentials for a different account at UAC.
	dacl := "D:P(A;;GA;;;BA)(A;;GA;;;" + user.User.Sid.String() + ")"
	sd, err := windows.SecurityDescriptorFromString(dacl)
	if err != nil {
		return 0, "", err
	}
	attrs := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	handle, err := windows.CreateNamedPipe(windows.StringToUTF16Ptr(name),
		windows.PIPE_ACCESS_DUPLEX|windows.FILE_FLAG_FIRST_PIPE_INSTANCE|windows.FILE_FLAG_OVERLAPPED,
		windows.PIPE_TYPE_BYTE|windows.PIPE_REJECT_REMOTE_CLIENTS, 1, 4096, 4096, 0, &attrs)
	runtime.KeepAlive(sd)
	return handle, name, err
}

func AcceptFrontendWorker(ctx context.Context, pipe windows.Handle, workerPID uint32) error {
	_, err := controlPipeOperation(ctx, pipe, func(o *windows.Overlapped, _ *uint32) error {
		err := windows.ConnectNamedPipe(pipe, o)
		if errors.Is(err, windows.ERROR_PIPE_CONNECTED) {
			return nil
		}
		return err
	})
	if err != nil {
		return err
	}
	var actual uint32
	if err := windows.GetNamedPipeClientProcessId(pipe, &actual); err != nil {
		return err
	}
	if actual != workerPID {
		return errors.New("Photon elevation pipe client is not the launched worker")
	}
	return nil
}

func OpenFrontendPipe(name string, frontendPID uint32) (windows.Handle, error) {
	suffix, valid := strings.CutPrefix(name, frontendPipePrefix)
	if !valid || len(suffix) != 26 || strings.Trim(suffix, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") != "" {
		return 0, errors.New("invalid Photon elevation pipe name")
	}
	pipe, err := windows.CreateFile(windows.StringToUTF16Ptr(name),
		windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OVERLAPPED|windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
	if err != nil {
		return 0, err
	}
	var actual uint32
	if err := windows.GetNamedPipeServerProcessId(pipe, &actual); err != nil || actual != frontendPID {
		_ = windows.CloseHandle(pipe)
		return 0, errors.Join(errors.New("Photon elevation pipe server is not the requesting process"), err)
	}
	return pipe, nil
}

// The caller keeps the handle until the stream has stopped using it.
func FrontendPipeStream(ctx context.Context, handle windows.Handle) io.ReadWriteCloser {
	ctx, cancel := context.WithCancel(ctx)
	return &frontendPipeStream{controlPipeStream: controlPipeStream{ctx: ctx, handle: handle}, cancel: cancel}
}

type frontendPipeStream struct {
	controlPipeStream
	cancel context.CancelFunc
}

func (s *frontendPipeStream) Read(p []byte) (int, error) {
	n, err := s.controlPipeStream.Read(p)
	if errors.Is(err, windows.ERROR_BROKEN_PIPE) || errors.Is(err, windows.ERROR_NO_DATA) {
		return n, io.EOF
	}
	return n, err
}

func (s *frontendPipeStream) Close() error {
	s.cancel()
	return nil
}

func VerifyFrontendProcess(pid uint32, executable string) (windows.Handle, error) {
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, pid)
	if err != nil {
		return 0, err
	}
	path := make([]uint16, 32768)
	size := uint32(len(path))
	if err := windows.QueryFullProcessImageName(process, 0, &path[0], &size); err != nil {
		_ = windows.CloseHandle(process)
		return 0, fmt.Errorf("verify Photon elevation requester: %w", err)
	}
	if !strings.EqualFold(windows.UTF16ToString(path[:size]), executable) {
		_ = windows.CloseHandle(process)
		return 0, errors.New("Photon elevation requester must be this executable")
	}
	return process, nil
}
