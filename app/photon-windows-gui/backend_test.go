package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

var desktopBackendBuild struct {
	sync.Once
	dir, path string
	err       error
}

func desktopTestBackend(t *testing.T) string {
	t.Helper()
	if path := os.Getenv("PHOTON_WINDOWS_TEST_BACKEND"); path != "" {
		absolute, err := filepath.Abs(path)
		if err != nil {
			t.Fatal(err)
		}
		return absolute
	}
	desktopBackendBuild.Do(func() {
		desktopBackendBuild.dir, desktopBackendBuild.err = os.MkdirTemp("", "photon-gui-backend-test-*")
		if desktopBackendBuild.err != nil {
			return
		}
		name := "photon-windows"
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		desktopBackendBuild.path = filepath.Join(desktopBackendBuild.dir, name)
		goTool := filepath.Join(runtime.GOROOT(), "bin", "go")
		if runtime.GOOS == "windows" {
			goTool += ".exe"
		}
		command := exec.Command(goTool, "build", "-o", desktopBackendBuild.path, "../photon-windows")
		output, err := command.CombinedOutput()
		if err != nil {
			desktopBackendBuild.err = &backendBuildError{err: err, output: string(output)}
		}
	})
	if desktopBackendBuild.err != nil {
		t.Fatal(desktopBackendBuild.err)
	}
	return desktopBackendBuild.path
}

type backendBuildError struct {
	err    error
	output string
}

func (e *backendBuildError) Error() string { return e.err.Error() + ": " + e.output }

func TestMain(m *testing.M) {
	code := m.Run()
	if desktopBackendBuild.dir != "" {
		_ = os.RemoveAll(desktopBackendBuild.dir)
	}
	os.Exit(code)
}
