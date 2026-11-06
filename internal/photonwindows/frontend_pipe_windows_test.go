//go:build windows

package photonwindows

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestFrontendPipeRestrictedFrontend(t *testing.T) {
	if broker := os.Getenv("PHOTON_TEST_FRONTEND_WORKER_PID"); broker != "" {
		pid, err := strconv.ParseUint(broker, 10, 32)
		if err != nil || !FrontendNeedsElevation() {
			t.Fatal("expected a restricted frontend", err)
		}
		handle, name, err := ListenFrontendPipe()
		if err != nil {
			t.Fatal(err)
		}
		defer windows.CloseHandle(handle)
		fmt.Println(name)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := AcceptFrontendWorker(ctx, handle, uint32(pid)); err != nil {
			t.Fatal(err)
		}
		stream := FrontendPipeStream(ctx, handle)
		defer stream.Close()
		if _, err := io.WriteString(stream, "ping"); err != nil {
			t.Fatal(err)
		}
		message := make([]byte, 4)
		if _, err := io.ReadFull(stream, message); err != nil || string(message) != "pong" {
			t.Fatalf("reply = %q, %v", message, err)
		}
		return
	}

	if FrontendNeedsElevation() {
		t.Skip("requires an elevated native test runner")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	token := controlRestrictedToken(t)
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestFrontendPipeRestrictedFrontend$")
	cmd.SysProcAttr = &syscall.SysProcAttr{Token: syscall.Token(token), CreationFlags: windows.CREATE_NO_WINDOW}
	cmd.Env = append(os.Environ(), "PHOTON_TEST_FRONTEND_WORKER_PID="+strconv.Itoa(os.Getpid()))
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	lines := bufio.NewReader(out)
	name, err := lines.ReadString('\n')
	if err != nil {
		t.Fatalf("restricted frontend did not create a pipe: %v", err)
	}
	parent, err := VerifyFrontendProcess(uint32(cmd.Process.Pid), exe)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(parent)
	handle, err := OpenFrontendPipe(strings.TrimSpace(name), uint32(cmd.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(handle)
	stream := FrontendPipeStream(ctx, handle)
	defer stream.Close()
	message := make([]byte, 4)
	if _, err := io.ReadFull(stream, message); err != nil || string(message) != "ping" {
		t.Fatalf("request = %q, %v", message, err)
	}
	if _, err := io.WriteString(stream, "pong"); err != nil {
		t.Fatal(err)
	}
	if remainder, err := io.ReadAll(lines); err != nil {
		t.Fatal(err)
	} else if err := cmd.Wait(); err != nil {
		t.Fatalf("restricted frontend: %v: %s", err, remainder)
	}
}

func TestFrontendPipeRejectsWrongProcess(t *testing.T) {
	t.Run("wrong server", func(t *testing.T) {
		server, name, err := ListenFrontendPipe()
		if err != nil {
			t.Fatal(err)
		}
		defer windows.CloseHandle(server)
		if handle, err := OpenFrontendPipe(name, uint32(os.Getpid())+1); err == nil {
			_ = windows.CloseHandle(handle)
			t.Fatal("accepted unexpected server")
		}
	})
	t.Run("wrong client", func(t *testing.T) {
		server, name, err := ListenFrontendPipe()
		if err != nil {
			t.Fatal(err)
		}
		defer windows.CloseHandle(server)
		client, err := OpenFrontendPipe(name, uint32(os.Getpid()))
		if err != nil {
			t.Fatal(err)
		}
		defer windows.CloseHandle(client)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := AcceptFrontendWorker(ctx, server, uint32(os.Getpid())+1); err == nil {
			t.Fatal("accepted unexpected client")
		}
	})
}
