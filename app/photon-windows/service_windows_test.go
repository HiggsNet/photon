//go:build windows

package main

import (
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
