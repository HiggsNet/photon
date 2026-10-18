//go:build linux

package photonopenwrt

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestCommandOutputLimitsAreExact(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
		want int
	}{
		{"nft", []string{"-j", "list", "ruleset"}, 8 << 20},
		{"ubus", []string{"call", "network.interface", "dump"}, 8 << 20},
		{"ubus", []string{"call", "other", "dump"}, 32 << 10},
		{"nft", []string{"-j", "list", "ruleset", "extra"}, 32 << 10},
		{"logread", []string{"-l", "80"}, 32 << 10},
		{"preflight", nil, 32 << 10},
	} {
		if got := commandOutputLimit(test.name, test.args); got != test.want {
			t.Fatalf("%s %v: %d want %d", test.name, test.args, got, test.want)
		}
	}
}

func TestCommandStructuredOutputIsCompleteOrExplicitError(t *testing.T) {
	dir := t.TempDir()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// Only test-owned executable names are intercepted. Caller arguments remain
	// literal argv, and no command or payload from an external request is used.
	for _, name := range []string{"nft", "ubus", "diagnostic"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\nexec \"$PHOTON_COMMAND_TEST_EXE\" -test.run=^TestCommandOutputHelper$ -- \"$@\"\n"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PHOTON_COMMAND_TEST_EXE", exe)
	t.Setenv("PHOTON_COMMAND_TEST_HELPER", "1")
	for _, name := range []string{"nft", "ubus"} {
		args := []string{"-j", "list", "ruleset"}
		if name == "ubus" {
			args = []string{"call", "network.interface", "dump"}
		}
		for _, size := range []int{48 << 10, structuredCommandOutputLimit} {
			t.Setenv("PHOTON_COMMAND_TEST_SIZE", strconv.Itoa(size))
			data, err := runCommand(context.Background(), name, args...)
			if size == structuredCommandOutputLimit {
				if !errors.Is(err, errStructuredOutputTruncated) || len(data) != 0 {
					t.Fatalf("%s excess output not explicit: %d %v", name, len(data), err)
				}
			} else if err != nil || !json.Valid(data) || len(data) <= diagnosticCommandOutputLimit {
				t.Fatalf("%s valid large JSON truncated: len=%d err=%v", name, len(data), err)
			}
		}
	}
	t.Setenv("PHOTON_COMMAND_TEST_SIZE", strconv.Itoa(48<<10))
	data, err := runCommand(context.Background(), "diagnostic")
	if err != nil || len(data) != diagnosticCommandOutputLimit {
		t.Fatalf("diagnostic cap changed: %d %v", len(data), err)
	}
}

func TestCommandOutputHelper(t *testing.T) {
	if os.Getenv("PHOTON_COMMAND_TEST_HELPER") != "1" {
		return
	}
	size, err := strconv.Atoi(os.Getenv("PHOTON_COMMAND_TEST_SIZE"))
	if err != nil {
		os.Exit(2)
	}
	data := append([]byte(`{"data":"`), bytes.Repeat([]byte{'x'}, size)...)
	data = append(data, []byte(`"}`)...)
	if _, err := os.Stdout.Write(data); err != nil {
		os.Exit(3)
	}
	os.Exit(0)
}
