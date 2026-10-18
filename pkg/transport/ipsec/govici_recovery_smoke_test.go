package ipsec

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// This exercises the real VICI protocol with an isolated charon, including a
// socket absent at startup and a later daemon restart. It never loads keys or
// connections and never uses the system charon socket.
func TestReconnectingGoviciClientDelayedCharonRecoverySmoke(t *testing.T) {
	if os.Getenv("PHOTON_IPSEC_XFRM_SMOKE") != "1" {
		t.Skip("set PHOTON_IPSEC_XFRM_SMOKE=1 to run the root/system VICI recovery smoke")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	ns := fmt.Sprintf("photon-vici-%d", time.Now().UnixNano())
	socket := filepath.Join("/tmp", ns+".vici")
	runIP(t, ctx, "netns", "add", ns)
	t.Cleanup(func() {
		_ = exec.Command("ip", "netns", "delete", ns).Run()
		_ = os.Remove(socket)
	})
	runIP(t, ctx, "netns", "exec", ns, "ip", "link", "set", "lo", "up")
	conf, err := writeStrongSwanConf(socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(conf) })
	piddir := t.TempDir()
	logFile, err := os.CreateTemp("", "photon-vici-recovery-*.log")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = logFile.Close()
		_ = os.Remove(logFile.Name())
	})
	defer func() {
		if t.Failed() {
			_ = logFile.Sync()
			if data, err := os.ReadFile(logFile.Name()); err == nil {
				t.Logf("isolated charon log:\n%s", data)
			}
		}
	}()

	client, err := NewReconnectingGoviciClient(socket)
	if err != nil {
		t.Fatalf("construct before charon starts: %v", err)
	}
	defer client.Close()
	driver := &StrongSwanDriver{VICI: client}
	if _, err := driver.ListSAs(ctx); !errors.Is(err, syscall.ENOENT) {
		t.Fatalf("ListSAs before startup = %v, want missing socket", err)
	}
	t.Logf("same wrapper reports missing socket before startup: %s", socket)

	var charon *exec.Cmd
	t.Cleanup(func() {
		if charon != nil {
			_ = charon.Process.Kill()
			_ = charon.Wait()
		}
	})
	waitReady := func(phase string) {
		t.Helper()
		for {
			sas, err := driver.ListSAs(ctx)
			if err == nil {
				if len(sas) != 0 {
					t.Fatalf("%s: isolated charon unexpectedly has SAs: %+v", phase, sas)
				}
				version, versionErr := client.Call(ctx, "version", nil)
				if versionErr == nil {
					actual := stringValue(version["version"])
					if actual == "" || stringValue(version["daemon"]) != "charon" {
						t.Fatalf("%s: invalid real charon version response: %+v", phase, version)
					}
					if expected := os.Getenv("PHOTON_STRONGSWAN_VERSION"); expected != "" && actual != expected {
						t.Fatalf("%s: charon version = %q, want %q", phase, actual, expected)
					}
					t.Logf("%s: same wrapper ListSAs succeeded with zero SAs; real version=%+v", phase, version)
					assertCharonPrivateRunMount(t, charon, piddir)
					return
				}
				err = versionErr
			}
			select {
			case <-ctx.Done():
				t.Fatalf("%s: real charon did not become ready: %v (last ListSAs error: %v)", phase, ctx.Err(), err)
			case <-time.After(100 * time.Millisecond):
			}
		}
	}

	charon = startCharonInNetNS(ctx, t, ns, piddir, conf, logFile)
	waitReady("delayed startup")
	if err := charon.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("stop isolated charon: %v", err)
	}
	stopped := make(chan error, 1)
	go func() { stopped <- charon.Wait() }()
	select {
	case err := <-stopped:
		charon = nil
		if err != nil {
			t.Fatalf("wait for isolated charon to stop: %v", err)
		}
	case <-time.After(5 * time.Second):
		_ = charon.Process.Kill()
		<-stopped
		charon = nil
		t.Fatal("isolated charon did not stop after SIGTERM")
	}
	if _, err := driver.ListSAs(ctx); err == nil {
		t.Fatal("ListSAs concealed stopped charon as a successful empty list")
	} else {
		t.Logf("same wrapper reports stopped charon: %v", err)
	}
	charon = startCharonInNetNS(ctx, t, ns, piddir, conf, logFile)
	waitReady("restart recovery")
}

func assertCharonPrivateRunMount(t *testing.T, charon *exec.Cmd, piddir string) {
	t.Helper()
	parentNS, err := os.Readlink("/proc/self/ns/mnt")
	if err != nil {
		t.Fatal(err)
	}
	childNS, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/mnt", charon.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	if parentNS == childNS {
		t.Fatal("test charon shares its mount namespace with the parent")
	}
	runPath, err := filepath.EvalSymlinks("/run")
	if err != nil {
		t.Fatal(err)
	}
	privateDir, err := os.Stat(piddir)
	if err != nil {
		t.Fatal(err)
	}
	childRun, err := os.Stat(filepath.Join(fmt.Sprintf("/proc/%d/root", charon.Process.Pid), runPath))
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(privateDir, childRun) {
		t.Fatalf("charon /run does not point to its private piddir %s", piddir)
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/mountinfo", charon.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	var bindMount string
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 7 || fields[4] != runPath {
			continue
		}
		for _, field := range fields[6:] {
			if field == "-" {
				break
			}
			if strings.HasPrefix(field, "shared:") || strings.HasPrefix(field, "master:") || strings.HasPrefix(field, "propagate_from:") {
				t.Fatalf("charon /run bind mount is not private: %s", line)
			}
		}
		bindMount = line
	}
	if bindMount == "" {
		t.Fatalf("charon has no private /run bind mount at %s", runPath)
	}
	t.Logf("charon private mount namespace parent=%s child=%s; /run bind mount: %s", parentNS, childNS, bindMount)
}
