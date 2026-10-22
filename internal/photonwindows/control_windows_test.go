//go:build windows

package photonwindows

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func controlRestrictedToken(t *testing.T) windows.Token {
	t.Helper()
	var original windows.Token
	// CreateRestrictedToken preserves the input handle's granted access. Its
	// child-process use requires TOKEN_ASSIGN_PRIMARY as well as QUERY/DUPLICATE.
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY|windows.TOKEN_ASSIGN_PRIMARY|windows.TOKEN_ADJUST_DEFAULT, &original); err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	admin, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	disabled := windows.SIDAndAttributes{Sid: admin}
	var restricted windows.Token
	proc := windows.NewLazySystemDLL("advapi32.dll").NewProc("CreateRestrictedToken")
	result, _, callErr := proc.Call(uintptr(original), 1, 1, uintptr(unsafe.Pointer(&disabled)), 0, 0, 0, 0, uintptr(unsafe.Pointer(&restricted)))
	if result == 0 {
		t.Fatal(callErr)
	}
	t.Cleanup(func() { restricted.Close() })
	// The elevated SSH token's default DACL can grant only Administrators.
	// Once that group is disabled, a new process cannot access loader-created
	// objects and exits with 0xc0000142. Change only this test token's defaults.
	user, err := restricted.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetTokenInformation(restricted, windows.TokenDefaultDacl, (*byte)(unsafe.Pointer(&acl)), uint32(unsafe.Sizeof(acl))); err != nil {
		t.Fatal(err)
	}
	runtime.KeepAlive(sd)
	return restricted
}

func controlNative(t *testing.T) (string, *ControlServer) {
	t.Helper()
	if err := controlPrivilegedToken(windows.GetCurrentProcessToken()); err != nil {
		t.Skip("requires elevated Windows native test", err)
	}
	path := filepath.Join(t.TempDir(), "state.db")
	server, err := ListenControl(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	return path, server
}
func startControlNative(t *testing.T, s *ControlServer, d ControlDaemon) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- s.Serve(context.Background(), d) }()
	<-s.ready
	t.Cleanup(func() {
		_ = s.Close()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
}
func openControlNative(t *testing.T, path string) windows.Handle {
	t.Helper()
	endpoint, err := ControlEndpoint(path)
	if err != nil {
		t.Fatal(err)
	}
	name, _ := windows.UTF16PtrFromString(endpoint)
	h, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED|windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { windows.CloseHandle(h) })
	return h
}
func TestControlNativeACLAndExclusiveOwner(t *testing.T) {
	path, s := controlNative(t)
	if second, err := ListenControl(path); err == nil {
		second.Close()
		t.Fatal("second runtime stole control endpoint")
	}
	sd, err := windows.GetSecurityInfo(s.handle, windows.SE_KERNEL_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	flags, _, err := sd.Control()
	if err != nil || flags&windows.SE_DACL_PROTECTED == 0 {
		t.Fatal("DACL not protected", flags, err)
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil || acl.AceCount != 2 {
		t.Fatal("unexpected DACL", err)
	}
	seen := map[string]bool{}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			t.Fatal(err)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || (!sid.IsWellKnown(windows.WinLocalSystemSid) && !sid.IsWellKnown(windows.WinBuiltinAdministratorsSid)) {
			t.Fatal("unexpected allowed principal", sid)
		}
		seen[sid.String()] = true
	}
	if len(seen) != 2 {
		t.Fatal("expected SYSTEM and Administrators")
	}
	// Execute an actual access check by opening under a token with the admin
	// group disabled, rather than inferring denial from the SDDL string alone.
	restricted := controlRestrictedToken(t)
	if err := controlPrivilegedToken(restricted); err == nil {
		t.Fatal("restricted server token was trusted")
	}
	var impersonation windows.Token
	if err := windows.DuplicateTokenEx(restricted, windows.TOKEN_QUERY|windows.TOKEN_IMPERSONATE, nil, windows.SecurityImpersonation, windows.TokenImpersonation, &impersonation); err != nil {
		t.Fatal(err)
	}
	defer impersonation.Close()
	endpoint, _ := ControlEndpoint(path)
	name, _ := windows.UTF16PtrFromString(endpoint)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := windows.SetThreadToken(nil, impersonation); err != nil {
		t.Fatal(err)
	}
	h, openErr := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED, 0)
	revertErr := windows.RevertToSelf()
	if openErr == nil {
		windows.CloseHandle(h)
		t.Fatal("non-admin token opened protected pipe")
	}
	if !errors.Is(openErr, windows.ERROR_ACCESS_DENIED) || revertErr != nil {
		t.Fatal(openErr, revertErr)
	}
	t.Log("protected SYSTEM/Administrators DACL, native restricted-token denial and exclusive pipe ownership verified")
}
func TestControlNativeRoundTripAndDrain(t *testing.T) {
	path, s := controlNative(t)
	gate := make(chan struct{})
	d := &controlTestDaemon{stopGate: gate, stopStarted: make(chan struct{})}
	startControlNative(t, s, d)
	response, err := CallControl(context.Background(), path, "status")
	if err != nil || response.Method != "status" {
		t.Fatal(response, err)
	}
	done := make(chan error, 1)
	go func() { _, err := CallControl(context.Background(), path, "stop"); done <- err }()
	select {
	case <-d.stopStarted:
	case <-time.After(time.Second):
		t.Fatal("stop was not accepted")
	}
	closed := make(chan struct{})
	go func() { s.Close(); close(closed) }()
	close(gate)
	if err := <-done; err != nil || !d.stopped.Load() {
		t.Fatal("stop cleanup reply lost", err)
	}
	select {
	case <-closed:
	case <-time.After(controlTimeout + time.Second):
		t.Fatal("control close did not join")
	}
}
func TestControlNativeIdleAcceptCancellation(t *testing.T) {
	_, s := controlNative(t)
	startControlNative(t, s, &controlTestDaemon{})
	time.Sleep(25 * time.Millisecond)
	start := time.Now()
	s.Close()
	if time.Since(start) > time.Second {
		t.Fatal("idle overlapped accept was not canceled promptly")
	}
}
func TestControlNativeSlowAndOversizedClients(t *testing.T) {
	path, s := controlNative(t)
	d := &controlTestDaemon{}
	startControlNative(t, s, d)
	h := openControlNative(t, path)
	// A partial header must time out. A second client has a shorter bounded
	// deadline and cannot allocate an additional server instance or goroutine.
	stream := &controlPipeStream{ctx: context.Background(), handle: h}
	if _, err := stream.Write([]byte{0}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := CallControl(ctx, path, "status"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("unbounded concurrent client", err)
	}
	started := time.Now()
	s.Close()
	if time.Since(started) > controlTimeout+time.Second {
		t.Fatal("partial frame did not time out/join")
	}
	if d.observed.Load() != 0 {
		t.Fatal("partial request reached daemon")
	}
	// A separately reserved server rejects the huge size before allocation.
	path2, s2 := controlNative(t)
	startControlNative(t, s2, d)
	h2 := openControlNative(t, path2)
	bounded, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	stream2 := &controlPipeStream{ctx: bounded, handle: h2}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], ^uint32(0))
	if _, err := stream2.Write(header[:]); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	if _, err := stream2.Read(b[:]); err == nil {
		t.Fatal("oversized frame accepted")
	}
	if d.observed.Load() != 0 {
		t.Fatal("oversized request reached daemon")
	}
}

// A lower-privilege process can reserve an unused pipe name with a permissive
// DACL. The client must reject that process, even though CreateFile succeeds.
func TestControlNativeRejectsFakeServer(t *testing.T) {
	if err := controlPrivilegedToken(windows.GetCurrentProcessToken()); err != nil {
		t.Skip("requires elevated Windows", err)
	}
	path := filepath.Join(t.TempDir(), "fake.db")
	endpoint, _ := ControlEndpoint(path)
	token := controlRestrictedToken(t)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// SSH uploads may inherit administrator-only execution permissions. Give
	// only this disposable helper copy an explicit current-user read/execute
	// ACE, so the restricted process can actually reach the spoofing test.
	// Use the shared Windows temp root: an SSH user's profile ancestors can
	// themselves be administrator-only even after granting the file RX.
	helperDir, err := os.MkdirTemp(filepath.Join(os.Getenv("SystemRoot"), "Temp"), "photon-control-helper-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(helperDir); err != nil {
			t.Error(err)
		}
	})
	helper := filepath.Join(helperDir, "control-helper.exe")
	source, err := os.Open(executable)
	if err != nil {
		t.Fatal(err)
	}
	target, err := os.Create(helper)
	if err != nil {
		source.Close()
		t.Fatal(err)
	}
	_, copyErr := io.Copy(target, source)
	source.Close()
	closeErr := target.Close()
	if copyErr != nil || closeErr != nil {
		t.Fatal(copyErr, closeErr)
	}
	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGX;;;" + user.User.Sid.String() + ")")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{helperDir, helper} {
		if err := windows.SetNamedSecurityInfo(name, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, helper, "-test.run=^TestControlNativeFakeServerHelper$", "-test.count=1")
	cmd.Dir = helperDir
	cmd.Env = append(os.Environ(), "PHOTON_CONTROL_FAKE_PIPE="+endpoint)
	cmd.SysProcAttr = &syscall.SysProcAttr{Token: syscall.Token(token), CreationFlags: windows.CREATE_NO_WINDOW}
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	line, err := bufio.NewReader(output).ReadString('\n')
	if err != nil || line != "fake-ready\n" {
		t.Fatal("fake pipe setup", line, err, cmd.Wait())
	}
	if server, err := ListenControl(path); err == nil {
		server.Close()
		t.Fatal("squatted endpoint replaced")
	}
	if _, err := CallControl(ctx, path, "stop"); !errors.Is(err, errControlPrivileges) {
		t.Fatal("expected connected server privilege rejection, not an unrelated transport failure", err)
	}
	t.Log("client rejected a connected lower-privilege server process; startup also refused squatted endpoint")
}

func TestControlNativeFakeServerHelper(t *testing.T) {
	endpoint := os.Getenv("PHOTON_CONTROL_FAKE_PIPE")
	if endpoint == "" {
		t.Skip("subprocess helper")
	}
	if err := controlPrivilegedToken(windows.GetCurrentProcessToken()); err == nil {
		t.Fatal("helper unexpectedly privileged")
	}
	name, err := windows.UTF16PtrFromString(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;GA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	h, err := windows.CreateNamedPipe(name, windows.PIPE_ACCESS_DUPLEX|windows.FILE_FLAG_FIRST_PIPE_INSTANCE|windows.FILE_FLAG_OVERLAPPED, windows.PIPE_TYPE_BYTE|windows.PIPE_REJECT_REMOTE_CLIENTS, 1, 4096, 4096, 0, &sa)
	runtime.KeepAlive(sd)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	fmt.Println("fake-ready")
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	_, err = controlPipeOperation(ctx, h, func(o *windows.Overlapped, _ *uint32) error {
		err := windows.ConnectNamedPipe(h, o)
		if errors.Is(err, windows.ERROR_PIPE_CONNECTED) {
			return nil
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	if n, _ := (&controlPipeStream{ctx: ctx, handle: h}).Read(b[:]); n != 0 {
		t.Fatal("fake server received control request before authentication")
	}
}
