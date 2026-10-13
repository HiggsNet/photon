//go:build windows && photon_profile

package main

import (
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFixtureCPUProfileBoundedAndFlushed(t *testing.T) {
	for _, stop := range []bool{false, true} {
		prefix := filepath.Join(t.TempDir(), "profile")
		if stop {
			if err := os.WriteFile(prefix+".stop", nil, 0600); err != nil {
				t.Fatal(err)
			}
		}
		before := time.Now()
		if err := captureFixtureCPU(prefix, 100*time.Millisecond); err != nil {
			t.Fatal(err)
		}
		if time.Since(before) > 3*time.Second {
			t.Fatal("unbounded profile shutdown")
		}
		done, err := os.ReadFile(prefix + ".done")
		if err != nil {
			t.Fatal(err)
		}
		want := "limit\n"
		if stop {
			want = "stopped\n"
		}
		if string(done) != want {
			t.Fatalf("done %q", done)
		}
		file, err := os.Open(prefix + ".pprof")
		if err != nil {
			t.Fatal(err)
		}
		reader, err := gzip.NewReader(file)
		if err != nil {
			file.Close()
			t.Fatal(err)
		}
		data, err := io.ReadAll(reader)
		reader.Close()
		file.Close()
		if err != nil || len(data) == 0 {
			t.Fatalf("ack preceded complete compressed profile: %v", err)
		}
	}
}
func TestFixtureCPUProfileDoesNotOverwrite(t *testing.T) {
	prefix := filepath.Join(t.TempDir(), "profile")
	if err := os.WriteFile(prefix+".pprof", []byte("existing"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := captureFixtureCPU(prefix, time.Millisecond); err == nil {
		t.Fatal("overwrote existing profile")
	}
	raw, _ := os.ReadFile(prefix + ".pprof")
	if string(raw) != "existing" {
		t.Fatal("changed existing profile")
	}
}
