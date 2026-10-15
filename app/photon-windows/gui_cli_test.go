package main

import (
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

func TestDesktopOptionsDoNotRequireAnExistingConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-created.yaml")
	options, err := parseDesktopOptions([]string{"--config", path, "--name", "Photon-GUI-Test"}, io.Discard)
	if err != nil || options.ConfigPath != path || options.ServiceName != "Photon-GUI-Test" {
		t.Fatalf("options=%+v err=%v", options, err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("parsing created or accessed configuration: %v", err)
	}
	for _, args := range [][]string{{"--name", ""}, {"--name", "bad/name"}, {"extra"}, {"--unknown"}} {
		if _, err := parseDesktopOptions(args, io.Discard); err == nil {
			t.Fatalf("accepted invalid desktop arguments: %v", args)
		}
	}
}

func TestDesktopDefaultOnlyAppliesToWindowsMain(t *testing.T) {
	want := []string(nil)
	if runtime.GOOS == "windows" {
		want = []string{"gui"}
	}
	if got := defaultCommandArgs(nil); !reflect.DeepEqual(got, want) {
		t.Fatalf("default arguments=%v, want %v", got, want)
	}
	args := []string{"status", "--config", "config.yaml"}
	if got := defaultCommandArgs(args); !reflect.DeepEqual(got, args) {
		t.Fatalf("changed explicit CLI invocation: %v", got)
	}
	options, err := parseDesktopOptions(nil, io.Discard)
	if err != nil || !filepath.IsAbs(options.ConfigPath) || filepath.Base(options.ConfigPath) != "config.yaml" {
		t.Fatalf("default config options=%+v err=%v", options, err)
	}
}
