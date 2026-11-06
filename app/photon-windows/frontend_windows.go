//go:build windows

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"time"
	"unsafe"

	"github.com/HiggsNet/photon/internal/photonwindows"
	"golang.org/x/sys/windows"
)

func runElevatedFrontend(ctx context.Context, path string, stream io.ReadWriteCloser, stderr io.Writer) int {
	if !photonwindows.FrontendNeedsElevation() {
		return runFrontendBackend(ctx, path, stream, "", stderr)
	}
	if err := bridgeFrontend(ctx, path, stream); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func bridgeFrontend(ctx context.Context, path string, stream io.ReadWriteCloser) error {
	fail := func(err error) error {
		_ = photonwindows.WriteControlReady(stream, photonwindows.ControlReady{}, err)
		return err
	}
	if !filepath.IsAbs(path) {
		return fail(errors.New("Photon configuration path must be absolute"))
	}
	data, err := readFrontendConfig(path)
	if err != nil {
		return fail(err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(data))
	executable, err := os.Executable()
	if err != nil {
		return fail(err)
	}
	handle, name, err := photonwindows.ListenFrontendPipe()
	if err != nil {
		return fail(err)
	}
	defer windows.CloseHandle(handle)
	worker, err := launchFrontendWorker(executable, []string{
		"frontend-worker", strconv.Itoa(os.Getpid()), name, digest, path,
	})
	if err != nil {
		return fail(err)
	}
	defer windows.CloseHandle(worker)
	defer func() {
		_ = windows.DisconnectNamedPipe(handle)
		_, _ = windows.WaitForSingleObject(worker, windows.INFINITE)
	}()
	pid, err := windows.GetProcessId(worker)
	if err != nil {
		return fail(err)
	}
	start, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := photonwindows.AcceptFrontendWorker(start, handle, pid); err != nil {
		return fail(err)
	}
	startup := photonwindows.FrontendPipeStream(start, handle)
	ready, err := photonwindows.ReadControlReady(startup)
	_ = startup.Close()
	if err != nil {
		return fail(err)
	}
	if ready.PID != int(pid) || ready.ConfigSHA256 != digest {
		return fail(errors.New("Photon elevated backend identity mismatch"))
	}
	ready.PID = os.Getpid()
	if err := photonwindows.WriteControlReady(stream, ready, nil); err != nil {
		return err
	}
	pipe := photonwindows.FrontendPipeStream(ctx, handle)
	out := make(chan error, 1)
	in := make(chan error, 1)
	go func() {
		_, err := io.Copy(stream, pipe)
		out <- err
	}()
	go func() {
		_, err := io.Copy(pipe, stream)
		in <- err
	}()
	select {
	case err := <-out:
		_ = pipe.Close()
		return err
	case err := <-in:
		_ = pipe.Close()
		<-out
		return err
	case <-ctx.Done():
		_ = pipe.Close()
		<-out
		return ctx.Err()
	}
}

func runFrontendWorker(ctx context.Context, args []string, stderr io.Writer) int {
	if len(args) != 4 || photonwindows.FrontendNeedsElevation() {
		return 2
	}
	pid, err := strconv.ParseUint(args[0], 10, 32)
	digest, hexErr := hex.DecodeString(args[2])
	if err != nil || pid == 0 || hexErr != nil || len(digest) != sha256.Size || !filepath.IsAbs(args[3]) {
		return 2
	}
	executable, err := os.Executable()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	parent, err := photonwindows.VerifyFrontendProcess(uint32(pid), executable)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer windows.CloseHandle(parent)
	handle, err := photonwindows.OpenFrontendPipe(args[1], uint32(pid))
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer windows.CloseHandle(handle)
	return runFrontendBackend(ctx, args[3], photonwindows.FrontendPipeStream(ctx, handle), args[2], stderr)
}

type shellExecuteInfo struct {
	size, mask            uint32
	window                windows.Handle
	verb, file, args, dir *uint16
	show                  int32
	instance, list        windows.Handle
	class                 *uint16
	classKey              windows.Handle
	hotkey                uint32
	icon, process         windows.Handle
}

func launchFrontendWorker(executable string, args []string) (windows.Handle, error) {
	const mask = 0x40 | 0x100 | 0x400 // NOCLOSEPROCESS | NOASYNC | FLAG_NO_UI
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ole := windows.NewLazySystemDLL("ole32.dll")
	hresult, _, _ := ole.NewProc("CoInitializeEx").Call(0, 0x2|0x4)
	if int32(hresult) >= 0 {
		defer ole.NewProc("CoUninitialize").Call()
	}
	info := shellExecuteInfo{
		size: uint32(unsafe.Sizeof(shellExecuteInfo{})), mask: mask,
		verb: windows.StringToUTF16Ptr("runas"), file: windows.StringToUTF16Ptr(executable),
		args: windows.StringToUTF16Ptr(windows.ComposeCommandLine(args)),
		dir:  windows.StringToUTF16Ptr(filepath.Dir(executable)), show: windows.SW_HIDE,
	}
	proc := windows.NewLazySystemDLL("shell32.dll").NewProc("ShellExecuteExW")
	ok, _, err := proc.Call(uintptr(unsafe.Pointer(&info)))
	if ok == 0 {
		return 0, fmt.Errorf("start elevated Photon backend: %w", err)
	}
	if info.process == 0 {
		return 0, errors.New("Windows did not return the Photon worker handle")
	}
	return info.process, nil
}
