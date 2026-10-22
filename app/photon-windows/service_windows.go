//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/HiggsNet/photon/internal/photonwindows"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func manageService(action, name, config string) error {
	manager, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect SCM (administrator required): %w", err)
	}
	defer manager.Disconnect()
	if action == "install" {
		executable, err := os.Executable()
		if err != nil {
			return err
		}
		executable, err = filepath.Abs(executable)
		if err != nil {
			return err
		}
		// CreateService escapes each argument using Windows command-line rules.
		service, err := manager.CreateService(name, executable, mgr.Config{
			DisplayName: name, Description: "Photon Windows leaf networking daemon",
			StartType: mgr.StartManual, ErrorControl: mgr.ErrorNormal, ServiceStartName: "LocalSystem",
		}, "run", "--service", "--name", name, "--config", config)
		if err != nil {
			return err
		}
		if err := photonwindows.InstallEventSource(name); err != nil {
			return errors.Join(err, service.Delete(), service.Close())
		}
		return service.Close()
	}
	service, err := manager.OpenService(name)
	if err != nil {
		return err
	}
	defer service.Close()
	installed, err := service.Config()
	if err != nil {
		return err
	}
	if err := validateOwnedService(installed, name, config); err != nil {
		return err
	}
	status, err := service.Query()
	if err != nil {
		return err
	}
	switch action {
	case "start":
		if status.State == svc.Running {
			return nil
		}
		if status.State != svc.Stopped {
			return fmt.Errorf("service is in transition (%d)", status.State)
		}
		if err := service.Start(); err != nil {
			return err
		}
		return waitServiceState(service, svc.Running, 30*time.Second)
	case "stop":
		if status.State == svc.Stopped {
			if status.Win32ExitCode != 0 || status.ServiceSpecificExitCode != 0 {
				return fmt.Errorf("service is stopped with failure: Win32=%d service=%d", status.Win32ExitCode, status.ServiceSpecificExitCode)
			}
			return nil
		}
		if _, err := service.Control(svc.Stop); err != nil {
			return err
		}
		return waitServiceState(service, svc.Stopped, 15*time.Second)
	case "remove":
		if status.State != svc.Stopped {
			return fmt.Errorf("stop service before removal (state %d)", status.State)
		}
		if err := service.Delete(); err != nil {
			return err
		}
		return photonwindows.RemoveEventSource(name)
	}
	return fmt.Errorf("unsupported service action %q", action)
}

// Both CLI mutations and desktop observations use the installed SCM command as
// the owner boundary; a matching service name alone never grants ownership.
func validateOwnedService(installed mgr.Config, name, config string) error {
	argv, err := windows.DecomposeCommandLine(installed.BinaryPathName)
	if err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	if installed.ServiceType != windows.SERVICE_WIN32_OWN_PROCESS || !strings.EqualFold(installed.ServiceStartName, "LocalSystem") {
		return fmt.Errorf("service %q is not an owned LocalSystem process", name)
	}
	if len(argv) != 7 || !strings.EqualFold(filepath.Clean(argv[0]), filepath.Clean(executable)) || argv[1] != "run" || argv[2] != "--service" || argv[3] != "--name" || argv[4] != name || argv[5] != "--config" || !filepath.IsAbs(argv[6]) {
		return fmt.Errorf("service %q is not owned by this Photon Windows executable", name)
	}
	if config != "" && !strings.EqualFold(filepath.Clean(config), filepath.Clean(argv[6])) {
		return fmt.Errorf("service %q uses a different config", name)
	}
	return nil
}

func waitServiceState(service *mgr.Service, desired svc.State, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		status, err := service.Query()
		if err != nil {
			return err
		}
		if status.State == svc.Stopped && (status.Win32ExitCode != 0 || status.ServiceSpecificExitCode != 0) {
			return fmt.Errorf("service failed: Win32=%d service=%d", status.Win32ExitCode, status.ServiceSpecificExitCode)
		}
		if status.State == desired {
			return nil
		}
		if status.State == svc.Stopped {
			return fmt.Errorf("service stopped before reaching state %d", desired)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for service state %d (current %d)", desired, status.State)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
