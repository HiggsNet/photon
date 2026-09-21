package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

func (l *appLogger) withNow(now func() time.Time) *appLogger {
	if l == nil {
		l = newAppLogger(nil)
	}
	if now != nil {
		l.now = now
	}
	return l
}

func (l *appLogger) withOutput(out io.Writer) *appLogger {
	if l == nil {
		l = newAppLogger(nil)
	}
	if out != nil {
		l.out = out
	}
	return l
}

func (l *appLogger) setLevel(level logLevel) *appLogger {
	if l == nil {
		l = newAppLogger(nil)
	}
	switch level {
	case logLevelDebug, logLevelInfo, logLevelWarn, logLevelError:
	default:
		level = logLevelInfo
	}
	l.level = level
	return l
}

func syncErrorReason(err error) string {
	var pending *syncPendingZonesError
	switch {
	case err == nil:
		return ""
	case errors.As(err, &pending):
		return "pending_zones"
	case errors.Is(err, context.DeadlineExceeded):
		return "context_deadline"
	case isReceiveTimeout(err):
		return "timeout"
	case errors.Is(err, gossip.ErrUnknownPeer):
		return "unknown_peer"
	case errors.Is(err, gossip.ErrMessageTooLarge):
		return "message_too_large"
	case errors.Is(err, gossip.ErrQuotaExceeded):
		return "quota"
	default:
		reason := gossip.RejectReason(err)
		if reason != "invalid_message" {
			return reason
		}
		return "sync_error"
	}
}

func TestAppLoggerWritesStructuredFields(t *testing.T) {
	var buf bytes.Buffer
	logger := &appLogger{
		level: logLevelInfo,
		out:   &buf,
		now:   func() time.Time { return time.Unix(100, 123).UTC() },
	}

	logger.Warn("sync", "round_failed", map[string]any{
		"peer_id": "node-a.catofes.",
		"reason":  "timeout",
		"error":   "sync receive timed out",
	})

	line := buf.String()
	for _, want := range []string{
		"ts=1970-01-01T00:01:40.000000123Z",
		"level=warn",
		"component=sync",
		"event=round_failed",
		"peer_id=node-a.catofes.",
		"reason=timeout",
		`error="sync receive timed out"`,
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("log line %q does not contain %q", line, want)
		}
	}
}

func TestRepeatedLogLimiterSuppressesUntilInterval(t *testing.T) {
	limiter := newRepeatedLogLimiter(time.Minute)
	now := time.Unix(100, 0)

	if suppressed, ok := limiter.Allow("sync|node-a|timeout", now); !ok || suppressed != 0 {
		t.Fatalf("first Allow = %d/%v, want 0/true", suppressed, ok)
	}
	if suppressed, ok := limiter.Allow("sync|node-a|timeout", now.Add(time.Second)); ok || suppressed != 0 {
		t.Fatalf("second Allow = %d/%v, want 0/false", suppressed, ok)
	}
	if suppressed, ok := limiter.Allow("sync|node-a|timeout", now.Add(2*time.Second)); ok || suppressed != 0 {
		t.Fatalf("third Allow = %d/%v, want 0/false", suppressed, ok)
	}
	if suppressed, ok := limiter.Allow("sync|node-a|timeout", now.Add(time.Minute)); !ok || suppressed != 2 {
		t.Fatalf("interval Allow = %d/%v, want 2/true", suppressed, ok)
	}
}

func TestAppLoggerFiltersByLevel(t *testing.T) {
	var buf bytes.Buffer
	logger := (&appLogger{}).setLevel(logLevelWarn).withOutput(&buf).withNow(func() time.Time {
		return time.Unix(100, 0).UTC()
	})

	logger.Info("sync", "round_completed", map[string]any{"peer_id": "node-a.catofes."})
	logger.Warn("sync", "round_failed", map[string]any{"peer_id": "node-a.catofes."})

	line := buf.String()
	if strings.Contains(line, "round_completed") {
		t.Fatalf("warn logger emitted info line: %q", line)
	}
	if !strings.Contains(line, "event=round_failed") {
		t.Fatalf("warn logger did not emit warn line: %q", line)
	}
}

func TestAppLoggerWritesToConfiguredFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "photon.log")
	var stderr bytes.Buffer
	logger := newAppLogger(&appConfig{Log: logConfig{Mode: "stderr+file", File: path}}).withOutput(&stderr).withNow(func() time.Time {
		return time.Unix(100, 0).UTC()
	})

	logger.Warn("gossip", "packet_failed", map[string]any{"peer_id": "node-a.catofes.", "reason": "quota"})

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(log): %v", err)
	}
	line := string(data)
	if !strings.Contains(line, "component=gossip") || !strings.Contains(line, "event=packet_failed") || !strings.Contains(line, "reason=quota") {
		t.Fatalf("file log line = %q, want structured packet failure", line)
	}
	if !strings.Contains(stderr.String(), "event=packet_failed") {
		t.Fatalf("stderr log line = %q, want duplicate console output", stderr.String())
	}
}

func TestSyncErrorReasonPendingZones(t *testing.T) {
	err := &syncPendingZonesError{zones: []zone.ZonePath{"node-b.catofes."}}
	if got := syncErrorReason(err); got != "pending_zones" {
		t.Fatalf("syncErrorReason = %q, want pending_zones", got)
	}
	if !strings.Contains(err.Error(), "sync once timed out with pending zones: node-b.catofes.") {
		t.Fatalf("pending error text = %q", err.Error())
	}
}

func TestAppLoggerReservedFieldsAndEscaping(t *testing.T) {
	var out bytes.Buffer
	logger := (&appLogger{}).withOutput(&out).withNow(func() time.Time { return time.Unix(100, 123) })
	logger.Info("control", "started", map[string]any{
		"ts": "fake", "level": "error", "component": "fake", "event": "fake",
		"time": "fake", "msg": "fake", "nil": nil,
		"message": "first\nsecond", "values": []string{"a b", "c"},
	})
	line := out.String()
	for _, want := range []string{"ts=1970-01-01T00:01:40.000000123Z", "level=info", "component=control", "event=started", `message="first\nsecond"`, `values="[a b c]"`} {
		if !strings.Contains(line, want) {
			t.Errorf("line %q missing %q", line, want)
		}
	}
	if strings.Contains(line, "fake") || strings.Contains(line, "nil=") || strings.Count(line, "\n") != 1 {
		t.Fatalf("invalid structured log: %q", line)
	}
}

func TestAppLoggerConcurrentZeroDefaults(t *testing.T) {
	var out bytes.Buffer
	logger := (&appLogger{}).withOutput(&out)
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			logger.Info("test", "concurrent", map[string]any{"id": id})
		}(i)
	}
	wg.Wait()
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 100 {
		t.Fatalf("got %d lines, want 100", len(lines))
	}
	seen := make(map[int]bool)
	for _, line := range lines {
		_, raw, ok := strings.Cut(line, "event=concurrent id=")
		id, err := strconv.Atoi(raw)
		if !ok || err != nil || seen[id] {
			t.Fatalf("corrupt or repeated line: %q", line)
		}
		seen[id] = true
	}
	if logger.level != "" || logger.mode != "" {
		t.Fatal("logging mutated configuration defaults")
	}
}

func TestAppLoggerReportsFileSinkFailure(t *testing.T) {
	for _, path := range []string{"", t.TempDir(), "/dev/full"} {
		t.Run(path, func(t *testing.T) {
			if path == "/dev/full" {
				if _, err := os.Stat(path); err != nil {
					t.Skip("/dev/full unavailable")
				}
			}
			var out bytes.Buffer
			logger := &appLogger{mode: logModeFile, file: path, out: &out}
			logger.Info("test", "write", nil)
			if !strings.Contains(out.String(), "level=error component=log event=sink_failed error=") {
				t.Fatalf("missing sink failure: %q", out.String())
			}
		})
	}
}
