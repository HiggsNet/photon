//go:build windows

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

func TestDesktopWindowsMissingConfigErrorsAreRecognized(t *testing.T) {
	dir := t.TempDir()
	for _, path := range []string{filepath.Join(dir, "config.yaml"), filepath.Join(dir, "missing-parent", "config.yaml")} {
		file, err := desktopOpenConfig(path)
		if file != nil {
			file.Close()
			t.Fatal("missing file opened")
		}
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("native missing error for %q not recognized: %v", path, err)
		}
	}
}

func TestDesktopWindowsInvalidPathCannotBecomeNewForm(t *testing.T) {
	dir := t.TempDir()
	// '?' is forbidden in a Win32 file name. Check the actual native error
	// before testing that LoadForm must not treat it as a missing config.
	path := filepath.Join(dir, "config?.yaml")
	file, openErr := desktopOpenConfig(path)
	if file != nil {
		file.Close()
		t.Fatal("invalid native config path opened")
	}
	if !errors.Is(openErr, windows.ERROR_INVALID_NAME) || errors.Is(openErr, os.ErrNotExist) {
		t.Fatalf("fixture did not produce a non-missing native error: %v", openErr)
	}
	b, err := newDesktopBackend(desktopOptions{ConfigPath: path})
	if err != nil {
		t.Fatal(err)
	}
	form, loadErr := b.LoadForm()
	if !errors.Is(loadErr, windows.ERROR_INVALID_NAME) || form.NewConfig || form.StatePath != "" {
		t.Fatalf("invalid config path replaced by defaults: %+v, %v", form, loadErr)
	}
	valid := defaultDesktopConfigForm(filepath.Join(dir, "valid.yaml"))
	completeFirstRunForm(&valid)
	if err := b.SaveForm(valid); err == nil || !strings.Contains(err.Error(), "did not load successfully") {
		t.Fatal("failed load allowed saving without successful reload")
	}
	if files, err := os.ReadDir(dir); err != nil || len(files) != 0 {
		t.Fatalf("failed load/save created files: %v, %v", files, err)
	}
}

func TestDesktopWindowsPreservesConfigDACL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	text := desktopTestConfig(filepath.Join(dir, "state.db"))
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	before, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := newDesktopBackend(desktopOptions{ConfigPath: path})
	if _, err := b.LoadConfigText(); err != nil {
		t.Fatal(err)
	}
	if err := b.SaveConfigText(text + "# saved\n"); err != nil {
		t.Fatal(err)
	}
	after, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if before.String() != after.String() {
		t.Fatalf("DACL changed: before %s after %s", before.String(), after.String())
	}
}

func TestDesktopWindowsServiceOwnership(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	name := "PhotonDesktopOwnershipTest"
	base := mgr.Config{ServiceType: windows.SERVICE_WIN32_OWN_PROCESS, ServiceStartName: "LocalSystem", BinaryPathName: windows.ComposeCommandLine([]string{exe, "run", "--service", "--name", name, "--config", path})}
	if err := validateOwnedService(base, name, path); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*mgr.Config){
		func(c *mgr.Config) { c.ServiceStartName = `NT AUTHORITY\LocalService` },
		func(c *mgr.Config) { c.ServiceType = windows.SERVICE_WIN32_SHARE_PROCESS },
		func(c *mgr.Config) { c.BinaryPathName = strings.Replace(c.BinaryPathName, "--service", "--console", 1) },
		func(c *mgr.Config) { c.BinaryPathName += " --extra" },
		func(c *mgr.Config) {
			c.BinaryPathName = windows.ComposeCommandLine([]string{`C:\foreign.exe`, "run", "--service", "--name", name, "--config", path})
		},
	} {
		c := base
		mutate(&c)
		if err := validateOwnedService(c, name, path); err == nil {
			t.Fatalf("foreign service accepted: %+v", c)
		}
	}
	if err := validateOwnedService(base, name, path+".other"); err == nil {
		t.Fatal("different config accepted")
	}
}

func TestDesktopWindowsAtomicSaveFailurePreservesOriginal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	text := desktopTestConfig(filepath.Join(dir, "state.db"))
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	b, _ := newDesktopBackend(desktopOptions{ConfigPath: path})
	if _, err := b.LoadConfigText(); err != nil {
		t.Fatal(err)
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	// Hold an ordinary reader that denies delete sharing: ReplaceFile must fail
	// without ever truncating the existing file, then recover after release.
	handle, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.SaveConfigText(text + "# edited\n"); err == nil {
		windows.CloseHandle(handle)
		t.Fatal("locked replacement succeeded")
	}
	if err := windows.CloseHandle(handle); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); string(got) != text {
		t.Fatal("failed atomic save damaged original")
	}
	if err := b.SaveConfigText(text + "# retry\n"); err != nil {
		t.Fatal(err)
	}
}

func TestDesktopWindowsInactiveHasNoStaleObservation(t *testing.T) {
	b, err := newDesktopBackend(desktopOptions{ConfigPath: filepath.Join(t.TempDir(), "config.yaml")})
	if err != nil {
		t.Fatal(err)
	}
	out := b.Snapshot(context.Background())
	if out.RuntimeState != "stopped" || out.Observation != nil || out.Error != "" {
		t.Fatalf("absent snapshot: %+v", out)
	}
}
