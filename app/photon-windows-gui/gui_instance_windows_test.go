//go:build windows

package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const desktopInstanceHelperEnv = "PHOTON_DESKTOP_INSTANCE_TEST_HELPER"

type desktopInstanceClaimResult struct {
	First  bool   `json:"first"`
	Handle uint64 `json:"handle"`
	Error  string `json:"error,omitempty"`
}

// Every contender remains alive until instructed to exit. A first claimant
// therefore cannot accidentally release the object before its peers claim it.
func TestDesktopInstanceClaimSubprocess(t *testing.T) {
	if os.Getenv(desktopInstanceHelperEnv) != "1" {
		return
	}
	name := os.Getenv("PHOTON_DESKTOP_INSTANCE_TEST_NAME")
	if !strings.HasPrefix(name, `Local\PhotonWindowsDesktopTest-`) {
		t.Fatal("helper requires its own isolated test object")
	}
	input := bufio.NewScanner(os.Stdin)
	fmt.Fprintln(os.Stdout, "ready")
	if !input.Scan() || input.Text() != "claim" {
		t.Fatal("claim barrier not received")
	}
	handle, first, err := claimDesktopInstance(name)
	if handle != 0 {
		defer windows.CloseHandle(handle)
	}
	result := desktopInstanceClaimResult{First: first, Handle: uint64(handle)}
	if err != nil {
		result.Error = err.Error()
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		t.Fatal(err)
	}
	if !input.Scan() || input.Text() != "exit" {
		t.Fatal("normal exit command not received")
	}
}

type desktopInstanceChild struct {
	cmd   *exec.Cmd
	input io.WriteCloser
	lines <-chan string
	done  <-chan error
}

func desktopInstanceTestName(t *testing.T) string {
	t.Helper()
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	return `Local\PhotonWindowsDesktopTest-` + hex.EncodeToString(nonce[:])
}

func startDesktopInstanceChild(t *testing.T, name string) *desktopInstanceChild {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestDesktopInstanceClaimSubprocess$")
	cmd.Env = append(os.Environ(), desktopInstanceHelperEnv+"=1", "PHOTON_DESKTOP_INSTANCE_TEST_NAME="+name)
	cmd.Stderr = os.Stderr
	input, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		input.Close()
		cancel()
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		input.Close()
		cancel()
		t.Fatal(err)
	}
	lines := make(chan string, 8)
	go func() {
		defer close(lines)
		scanner := bufio.NewScanner(output)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
	}()
	done := make(chan error, 1)
	joined := make(chan struct{})
	go func() {
		done <- cmd.Wait()
		close(joined)
	}()
	child := &desktopInstanceChild{cmd: cmd, input: input, lines: lines, done: done}
	t.Cleanup(func() {
		input.Close()
		cancel()
		// Process.Kill uses the retained handle of this exact child. No
		// process lookup, executable-name match or unrelated PID is involved.
		_ = cmd.Process.Kill()
		select {
		case <-joined:
		case <-time.After(10 * time.Second):
			t.Error("helper cleanup did not join its owned process")
		}
	})
	if line := child.readLine(t); line != "ready" {
		t.Fatalf("helper startup response %q", line)
	}
	return child
}

func (child *desktopInstanceChild) readLine(t *testing.T) string {
	t.Helper()
	select {
	case line, ok := <-child.lines:
		if !ok {
			t.Fatal("helper exited before its protocol response")
		}
		return line
	case <-time.After(10 * time.Second):
		t.Fatal("helper protocol response timed out")
		return ""
	}
}

func (child *desktopInstanceChild) send(t *testing.T, command string) {
	t.Helper()
	if _, err := fmt.Fprintln(child.input, command); err != nil {
		t.Fatal(err)
	}
}

func (child *desktopInstanceChild) claimResult(t *testing.T) desktopInstanceClaimResult {
	t.Helper()
	var result desktopInstanceClaimResult
	if err := json.Unmarshal([]byte(child.readLine(t)), &result); err != nil {
		t.Fatal(err)
	}
	if result.Error != "" || result.First != (result.Handle != 0) {
		t.Fatalf("invalid claim result: %+v", result)
	}
	return result
}

func (child *desktopInstanceChild) wait(t *testing.T, killed bool) {
	t.Helper()
	select {
	case err := <-child.done:
		if killed {
			if _, ok := err.(*exec.ExitError); !ok {
				t.Fatalf("killed helper did not report a nonzero native exit: %v", err)
			}
		} else if err != nil {
			t.Fatalf("normal helper exit: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("helper exit was not joined")
	}
}

func assertDesktopInstanceCanBeClaimed(t *testing.T, name string) {
	t.Helper()
	handle, first, err := claimDesktopInstance(name)
	if err != nil || !first || handle == 0 {
		if handle != 0 {
			windows.CloseHandle(handle)
		}
		t.Fatalf("released instance could not be claimed: handle=%v first=%t error=%v", handle, first, err)
	}
	if err := windows.CloseHandle(handle); err != nil {
		t.Fatal(err)
	}
}

func TestDesktopInstanceConcurrentProcessesHaveOneClaimant(t *testing.T) {
	name := desktopInstanceTestName(t)
	children := make([]*desktopInstanceChild, 8)
	for index := range children {
		children[index] = startDesktopInstanceChild(t, name)
	}
	// All children have started and reached the same stdin barrier before any
	// can claim. Keep the winner alive while collecting every other result.
	for _, child := range children {
		child.send(t, "claim")
	}
	owners := 0
	for _, child := range children {
		if child.claimResult(t).First {
			owners++
		}
	}
	if owners != 1 {
		t.Fatalf("concurrent claimants=%d, want exactly one", owners)
	}
	for _, child := range children {
		child.send(t, "exit")
	}
	for _, child := range children {
		child.wait(t, false)
	}
	assertDesktopInstanceCanBeClaimed(t, name)
}

func TestDesktopInstanceProcessExitReleasesClaim(t *testing.T) {
	for _, killed := range []bool{false, true} {
		t.Run(fmt.Sprintf("killed=%t", killed), func(t *testing.T) {
			name := desktopInstanceTestName(t)
			child := startDesktopInstanceChild(t, name)
			child.send(t, "claim")
			if !child.claimResult(t).First {
				t.Fatal("isolated child did not own its new instance")
			}
			if killed {
				if err := child.cmd.Process.Kill(); err != nil {
					t.Fatal(err)
				}
			} else {
				child.send(t, "exit")
			}
			child.wait(t, killed)
			assertDesktopInstanceCanBeClaimed(t, name)
		})
	}
}

func TestDesktopInstanceDuplicateClosesHandlesAndPreservesOwner(t *testing.T) {
	name := desktopInstanceTestName(t)
	owner := startDesktopInstanceChild(t, name)
	owner.send(t, "claim")
	if !owner.claimResult(t).First {
		t.Fatal("isolated owner did not claim its instance")
	}
	duplicate := func() {
		t.Helper()
		handle, first, err := claimDesktopInstance(name)
		if handle != 0 {
			windows.CloseHandle(handle)
		}
		if err != nil || first || handle != 0 {
			t.Fatalf("duplicate changed owner or exposed a handle: handle=%v first=%t error=%v", handle, first, err)
		}
	}
	for range 32 {
		duplicate()
	}
	before := desktopInstanceHandleCount(t)
	for range 2048 {
		duplicate()
	}
	after := desktopInstanceHandleCount(t)
	// Go may lazily create a few runtime thread handles; a leaked handle on
	// every already-exists branch would add 2048, not this small fixed margin.
	if after > before+4 {
		t.Fatalf("duplicate claims leaked process handles: before=%d after=%d", before, after)
	}
	duplicate()
	owner.send(t, "exit")
	owner.wait(t, false)
	// A leaked duplicate handle would also keep the object alive here.
	assertDesktopInstanceCanBeClaimed(t, name)
}

func desktopInstanceHandleCount(t *testing.T) uint32 {
	t.Helper()
	var count uint32
	proc := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetProcessHandleCount")
	result, _, err := proc.Call(uintptr(windows.CurrentProcess()), uintptr(unsafe.Pointer(&count)))
	if result == 0 {
		t.Fatalf("GetProcessHandleCount: %v", err)
	}
	return count
}
