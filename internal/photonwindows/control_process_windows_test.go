//go:build windows

package photonwindows

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestControlNativeExpectedServiceProcess(t *testing.T) {
	path, server := controlNative(t)
	daemon := &controlTestDaemon{}
	startControlNative(t, server, daemon)
	if _, err := CallControlForProcess(context.Background(), path, "stop", 0); err == nil {
		t.Fatal("zero SCM PID accepted")
	}
	if _, err := CallControlForProcess(context.Background(), path, "stop", uint32(os.Getpid())+1); err == nil || !strings.Contains(err.Error(), "does not match SCM process") {
		t.Fatalf("foreign privileged server accepted: %v", err)
	}
	if daemon.stopped.Load() {
		t.Fatal("stop request transmitted to wrong process")
	}
	response, err := CallControlForProcess(context.Background(), path, "status", uint32(os.Getpid()))
	if err != nil || response.Method != "status" {
		t.Fatal(response, err)
	}
}
