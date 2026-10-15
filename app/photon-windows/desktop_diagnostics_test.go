package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/HiggsNet/photon/internal/photonwindows"
)

func desktopLogFixture(t *testing.T) (*desktopBackend, string) {
	t.Helper()
	dir := t.TempDir()
	path, statePath := filepath.Join(dir, "config.yaml"), filepath.Join(dir, "identity.db")
	if err := os.WriteFile(path, []byte(desktopTestConfig(statePath)), 0600); err != nil {
		t.Fatal(err)
	}
	b, err := newDesktopBackend(desktopOptions{ConfigPath: path})
	if err != nil {
		t.Fatal(err)
	}
	return b, statePath + ".log"
}

func TestDesktopLogTailMissingDoesNotReadOrCreatePrivateState(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "portable.yaml")
	b, err := newDesktopBackend(desktopOptions{ConfigPath: path})
	if err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(dir, "portable.db")
	private := []byte("PRIVATE_DATABASE_SENTINEL: not a log and not a valid database")
	if err := os.WriteFile(statePath, private, 0600); err != nil {
		t.Fatal(err)
	}
	tail, err := b.LogTail()
	if err != nil || !tail.Missing || tail.Path != statePath+".log" || tail.Text != "" || tail.Truncated {
		t.Fatalf("missing log: %+v, %v", tail, err)
	}
	if data, err := os.ReadFile(statePath); err != nil || !bytes.Equal(data, private) {
		t.Fatal("log viewer read/changed a private database as log data")
	}
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 1 || files[0].Name() != "portable.db" {
		t.Fatalf("read-only viewer created files: %v, %v", files, err)
	}
}

func TestDesktopLogTailRejectsInvalidConfigurationAndNonregularFiles(t *testing.T) {
	t.Run("invalid config is not missing log", func(t *testing.T) {
		b, path := desktopLogFixture(t)
		if err := os.WriteFile(path, []byte("must not be read through defaults"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(b.options.ConfigPath, []byte("invalid: ["), 0600); err != nil {
			t.Fatal(err)
		}
		if tail, err := b.LogTail(); err == nil || tail.Missing || tail.Text != "" {
			t.Fatalf("invalid config became empty/default log: %+v, %v", tail, err)
		}
	})
	t.Run("directory", func(t *testing.T) {
		b, path := desktopLogFixture(t)
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
		if tail, err := b.LogTail(); err == nil || tail.Missing || tail.Text != "" {
			t.Fatalf("nonregular log accepted: %+v, %v", tail, err)
		}
	})
	t.Run("link to private state", func(t *testing.T) {
		b, path := desktopLogFixture(t)
		target := strings.TrimSuffix(path, ".log")
		if err := os.WriteFile(target, []byte("private key material must never enter the log viewer"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, path); err != nil {
			t.Skipf("symlink creation unavailable: %v", err)
		}
		if tail, err := b.LogTail(); err == nil || tail.Missing || tail.Text != "" {
			t.Fatalf("linked log exposed private state: %+v, %v", tail, err)
		}
	})
}

func TestDesktopLogTailByteBoundPreservesUTF8Suffix(t *testing.T) {
	b, path := desktopLogFixture(t)
	suffix := "最后的日志🙂\n"
	data := strings.Repeat("中🙂", desktopLogMaxBytes/7+8) + suffix
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	tail, err := b.LogTail()
	if err != nil || !tail.Truncated || tail.Missing || len(tail.Text) > desktopLogMaxBytes || !utf8.ValidString(tail.Text) || !strings.HasSuffix(tail.Text, suffix) || strings.Contains(tail.Text, "?") {
		t.Fatalf("bounded UTF-8 suffix: bytes=%d, truncated=%t, valid=%t, err=%v", len(tail.Text), tail.Truncated, utf8.ValidString(tail.Text), err)
	}
}

func TestDesktopLogTailKeepsLatestThousandLines(t *testing.T) {
	for _, trailingNewline := range []bool{false, true} {
		t.Run(fmt.Sprint(trailingNewline), func(t *testing.T) {
			b, path := desktopLogFixture(t)
			var data strings.Builder
			for i := 0; i < 1205; i++ {
				fmt.Fprintf(&data, "line-%04d 中文🙂", i)
				if i != 1204 || trailingNewline {
					data.WriteString("\r\n")
				}
			}
			if err := os.WriteFile(path, []byte(data.String()), 0600); err != nil {
				t.Fatal(err)
			}
			tail, err := b.LogTail()
			lines := strings.Split(strings.TrimSuffix(tail.Text, "\r\n"), "\n")
			if err != nil || !tail.Truncated || len(lines) != 1000 || !strings.HasPrefix(tail.Text, "line-0205 ") || !strings.Contains(lines[999], "line-1204 ") {
				t.Fatalf("line clipping: count=%d, first=%q, err=%v", len(lines), lines[0], err)
			}
		})
	}
}

func TestDesktopLogTailUsesRunPathAfterEditsAndStop(t *testing.T) {
	b, firstPath := desktopLogFixture(t)
	form, err := b.LoadForm()
	if err != nil {
		t.Fatal(err)
	}
	for path, text := range map[string]string{firstPath: "first run log", filepath.Join(filepath.Dir(firstPath), "next.db.log"): "next run log"} {
		if err := os.WriteFile(path, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	// Log selection depends on the immutable run path, not its readiness or
	// the editable form. Production lifecycle/lock tests exercise the real run.
	run := &desktopRun{statePath: strings.TrimSuffix(firstPath, ".log"), done: make(chan struct{})}
	b.run = run
	form.StatePath = filepath.Join(filepath.Dir(firstPath), "next.db")
	if err := b.SaveForm(form); err != nil {
		t.Fatal(err)
	}
	for _, stopped := range []bool{false, true} {
		if stopped {
			close(run.done)
		}
		if tail, err := b.LogTail(); err != nil || tail.Path != firstPath || tail.Text != "first run log" {
			t.Fatalf("stopped=%t: saved config retargeted old run log: %+v, %v", stopped, tail, err)
		}
	}
	b.run = &desktopRun{statePath: form.StatePath}
	if tail, err := b.LogTail(); err != nil || tail.Text != "next run log" || tail.Path != form.StatePath+".log" {
		t.Fatalf("new run did not select its own log: %+v, %v", tail, err)
	}
}

func TestDesktopLogTailRotationAndExistingLoggerRedaction(t *testing.T) {
	b, path := desktopLogFixture(t)
	config, err := desktopParseConfig(desktopTestConfig(strings.TrimSuffix(path, ".log")))
	if err != nil {
		t.Fatal(err)
	}
	logger, closer, err := photonwindows.NewRuntimeLogger(config, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	logger.Info("safe runtime event", "private_key", "PRIVATE_LOG_SENTINEL", "packet", []byte("RAW_PACKET_SENTINEL"))
	if err := closer.Close(); err != nil {
		t.Fatal(err)
	}
	tail, err := b.LogTail()
	if err != nil || tail.Truncated || tail.Missing || strings.Contains(tail.Text, "PRIVATE_LOG_SENTINEL") || strings.Contains(tail.Text, "RAW_PACKET_SENTINEL") || !strings.Contains(tail.Text, "[redacted]") {
		t.Fatalf("existing production logger redaction was not preserved: %+v, %v", tail, err)
	}
	opened, err := desktopOpenConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatalf("rotation denied by read handle: %v", err)
	}
	if err := os.WriteFile(path, []byte("new current log\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if tail, err := b.LogTail(); err != nil || tail.Text != "new current log\n" {
		t.Fatalf("rotation retained the previous file: %+v, %v", tail, err)
	}
}

func TestDesktopPeerAndDiagnosticFormattingUsesOnlyAvailableDTO(t *testing.T) {
	when := time.Date(2026, 10, 16, 10, 0, 0, 0, time.FixedZone("offset", 8*60*60))
	observation := &photonwindows.Observation{Running: true, ObservedAt: when, PeersTruncated: true, RoutesTruncated: true, Peers: []photonwindows.PeerObservation{{Peer: "failed.example.", PullState: "failed", UpdatedAt: when, PullAttempts: 7, PullSuccesses: 3, PullFailures: 4}}}
	snapshot := desktopSnapshot{RuntimeState: "running", Observation: observation}
	peers := desktopFormatPeers(snapshot)
	for _, want := range []string{"同步失败", `pull_state="failed"`, "2026-10-16 02:00:00 UTC", "尝试 7 · 成功 3 · 失败 4", "节点列表已截断"} {
		if !strings.Contains(peers, want) {
			t.Fatalf("peer details missing %q: %s", want, peers)
		}
	}
	var details struct {
		Available   bool                       `json:"available"`
		Observation *photonwindows.Observation `json:"observation"`
	}
	if err := json.Unmarshal([]byte(desktopFormatDiagnostics(snapshot)), &details); err != nil || !details.Available || details.Observation == nil || details.Observation.Peers[0].PullState != "failed" || !details.Observation.RoutesTruncated {
		t.Fatalf("diagnostic DTO lost failure/truncation: %+v, %v", details, err)
	}
	for _, inactive := range []desktopSnapshot{{RuntimeState: "stopped", Observation: observation}, {RuntimeState: "running", Error: "IPC disconnected", Observation: observation}, {RuntimeState: "failed", Observation: observation}, {RuntimeState: "running", Observation: &photonwindows.Observation{Running: false}}} {
		if got := desktopFormatPeers(inactive); !strings.Contains(got, "不可用") || strings.Contains(got, "failed.example.") {
			t.Fatalf("offline peer formatter retained live data: %s", got)
		}
		encoded := desktopFormatDiagnostics(inactive)
		if !json.Valid([]byte(encoded)) || strings.Contains(encoded, `"observation"`) || strings.Contains(encoded, "failed.example.") || !strings.Contains(encoded, `"available": false`) {
			t.Fatalf("offline diagnostics retained live data: %s", encoded)
		}
	}
}

func TestDesktopPeerFormattingPreservesUnknownAndEmptyStates(t *testing.T) {
	snapshot := desktopSnapshot{RuntimeState: "running", Observation: &photonwindows.Observation{Running: true, Peers: []photonwindows.PeerObservation{{Peer: "unknown.", PullState: "future_state"}, {Peer: "waiting."}}}}
	text := desktopFormatPeers(snapshot)
	if !strings.Contains(text, "未知状态") || !strings.Contains(text, `pull_state="future_state"`) || !strings.Contains(text, "暂无会话状态") || !strings.Contains(text, "尚无时间记录") {
		t.Fatalf("unknown/empty state invented health: %s", text)
	}
}
