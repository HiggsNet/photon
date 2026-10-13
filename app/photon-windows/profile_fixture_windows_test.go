//go:build windows && photon_profile

package main

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/photonwindows"
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
		drops, err := os.Open(prefix + ".packet-drops.json")
		if err != nil {
			t.Fatal(err)
		}
		var report fixturePacketDropReport
		err = json.NewDecoder(drops).Decode(&report)
		drops.Close()
		if err != nil || report.SchemaVersion != 1 {
			t.Fatalf("ack preceded complete packet-drop JSON: %+v %v", report, err)
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

func TestFixtureCPUProfileDoesNotOverwritePacketDrops(t *testing.T) {
	prefix := filepath.Join(t.TempDir(), "profile")
	path := prefix + ".packet-drops.json"
	if err := os.WriteFile(path, []byte("existing"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := captureFixtureCPU(prefix, time.Millisecond); err == nil {
		t.Fatal("overwrote existing packet-drop artifact")
	}
	raw, _ := os.ReadFile(path)
	if string(raw) != "existing" {
		t.Fatal("changed existing packet-drop artifact")
	}
	for _, suffix := range []string{".started", ".done"} {
		if _, err := os.Stat(prefix + suffix); !os.IsNotExist(err) {
			t.Fatalf("acknowledged rejected artifact: %s %v", suffix, err)
		}
	}
}

func TestFixturePacketDropDeltaRejectsCounterRegression(t *testing.T) {
	baseline := photonwindows.FixturePacketDrops{RawIngress: 5, LeafIngress: 8, ESPIngress: 13}
	end := photonwindows.FixturePacketDrops{RawIngress: 7, LeafIngress: 11, ESPIngress: 17}
	got, err := fixturePacketDropDelta(baseline, end)
	if want := (fixturePacketDropReport{SchemaVersion: 1, RawIngress: 2, LeafIngress: 3, ESPIngress: 4}); err != nil || got != want {
		t.Fatalf("delta %+v %v", got, err)
	}
	for _, changed := range []photonwindows.FixturePacketDrops{
		{RawIngress: 4, LeafIngress: 8, ESPIngress: 13},
		{RawIngress: 5, LeafIngress: 7, ESPIngress: 13},
		{RawIngress: 5, LeafIngress: 8, ESPIngress: 12},
	} {
		if _, err := fixturePacketDropDelta(baseline, changed); err == nil {
			t.Fatal("accepted counter regression")
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

func TestFixturePacketTimingMarker(t *testing.T) {
	directory := t.TempDir()
	if mode, err := readFixturePacketTimingMode(directory); mode != "" || err != nil {
		t.Fatalf("absent marker: %q %v", mode, err)
	}
	path := filepath.Join(directory, "fixture-packet-timing-profile")
	for _, value := range []string{"on:f1-w64-IPv4\n", "on:f4-w64-IPv4\n", "off:f1-w64-IPv4\n", "off:f4-w64-IPv4\n"} {
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
		mode, err := readFixturePacketTimingMode(directory)
		if err != nil || (mode != "on" && mode != "off") {
			t.Fatalf("valid marker %q: %q %v", value, mode, err)
		}
	}
	for _, value := range []string{"", "on:f4-w1024-IPv4\n", "on:f4-w64-IPv6\n", "ON:f4-w64-IPv4\n", "on:f4-w64-IPv4\r\n", "off:f4-w64-IPv4\nextra", "arbitrary request exceeding the bounded marker size"} {
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := readFixturePacketTimingMode(directory); err == nil {
			t.Fatalf("accepted malformed marker %q", value)
		}
		prefix := filepath.Join(directory, "profile")
		if err := captureFixtureCPU(prefix, time.Millisecond); err == nil {
			t.Fatal("started malformed capture")
		}
		if _, err := os.Stat(prefix + ".pprof"); !os.IsNotExist(err) {
			t.Fatalf("malformed marker opened artifact: %v", err)
		}
	}
}

func TestFixturePacketTimingCaptureAndExclusiveArtifact(t *testing.T) {
	for _, mode := range []string{"off", "on"} {
		t.Run(mode, func(t *testing.T) {
			directory := t.TempDir()
			marker := filepath.Join(directory, "fixture-packet-timing-profile")
			if err := os.WriteFile(marker, []byte(mode+":f4-w64-IPv4\n"), 0600); err != nil {
				t.Fatal(err)
			}
			prefix := filepath.Join(directory, "profile")
			if err := captureFixtureCPU(prefix, time.Millisecond); err != nil {
				t.Fatal(err)
			}
			file, err := os.Open(prefix + ".packet-timing.json")
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			var report photonwindows.FixturePacketTiming
			if err := json.NewDecoder(file).Decode(&report); err != nil {
				t.Fatal(err)
			}
			if report.SchemaVersion != 1 || report.Enabled != (mode == "on") {
				t.Fatalf("wrong timing mode/schema: %+v", report)
			}
			if _, err := os.Stat(prefix + ".done"); err != nil {
				t.Fatal("complete timing artifact was not acknowledged", err)
			}
		})
	}
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "fixture-packet-timing-profile"), []byte("on:f4-w64-IPv4\n"), 0600); err != nil {
		t.Fatal(err)
	}
	prefix := filepath.Join(directory, "profile")
	path := prefix + ".packet-timing.json"
	if err := os.WriteFile(path, []byte("existing"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := captureFixtureCPU(prefix, time.Millisecond); err == nil {
		t.Fatal("overwrote existing timing artifact")
	}
	if raw, _ := os.ReadFile(path); string(raw) != "existing" {
		t.Fatal("changed existing timing artifact")
	}
	for _, suffix := range []string{".started", ".done"} {
		if _, err := os.Stat(prefix + suffix); !os.IsNotExist(err) {
			t.Fatalf("acknowledged rejected timing artifact: %s %v", suffix, err)
		}
	}
}
