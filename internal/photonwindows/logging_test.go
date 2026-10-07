package photonwindows

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"crypto/ed25519"
)

type capturedRuntimeEvent struct {
	level   slog.Level
	id      uint32
	message string
}

type logScalarSecret int

func (logScalarSecret) String() string { return "FORMATTER-SECRET" }
func (logScalarSecret) Format(state fmt.State, verb rune) {
	_, _ = state.Write([]byte("FORMATTER-SECRET"))
}

type logKeySecret string

func (logKeySecret) String() string { return "FORMATTER-SECRET" }

func TestRuntimeLoggingErrorsAndCustomScalars(t *testing.T) {
	var text bytes.Buffer
	events := &capturedRuntimeSink{}
	logger := slog.New(&runtimeLogHandler{handlers: []slog.Handler{slog.NewTextHandler(&text, nil)}, event: events})
	logger.Error("runtime_start_failed", "error", fmt.Errorf("open adapter: %w", errors.New("access denied")),
		"scalar", logScalarSecret(7), "string_keys", map[logKeySecret]any{"public": logScalarSecret(9)},
		"other_keys", map[logScalarSecret]any{1: "value"})
	for _, got := range []string{text.String(), events.events[0].message} {
		if strings.Contains(got, "FORMATTER-SECRET") || !strings.Contains(got, "open adapter: access denied") || !strings.Contains(got, "scalar=7") || !strings.Contains(got, "public:9") {
			t.Fatalf("unsafe formatter or missing error context: %s", got)
		}
	}
	logger.Error("runtime_start_failed", "error", fmt.Errorf("load: %w", errors.New(`{"private_key":"FORMATTER-SECRET"}`)))
	if strings.Contains(text.String(), "FORMATTER-SECRET") || strings.Contains(events.events[1].message, "FORMATTER-SECRET") {
		t.Fatal("error handling bypassed text redaction")
	}
}

func TestRuntimeLogRejectsOversizedExistingFiles(t *testing.T) {
	for _, suffix := range []string{"", ".1", ".2", ".3"} {
		t.Run("file"+suffix, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.db.log")
			file, err := os.Create(path + suffix)
			if err != nil {
				t.Fatal(err)
			}
			if err := file.Truncate(logFileLimit + 1); err != nil {
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			if writer, err := openRuntimeLog(path); err == nil {
				writer.Close()
				t.Fatal("oversized existing log accepted")
			}
			stat, err := os.Stat(path + suffix)
			if err != nil || stat.Size() != logFileLimit+1 {
				t.Fatalf("rejected log was changed: %v %v", stat, err)
			}
		})
	}
}

type capturedRuntimeSink struct{ events []capturedRuntimeEvent }

func (s *capturedRuntimeSink) Report(level slog.Level, id uint32, message string) error {
	s.events = append(s.events, capturedRuntimeEvent{level, id, message})
	return nil
}
func (*capturedRuntimeSink) Close() error { return nil }

type opaqueLogSecret struct{ private string }

func (s opaqueLogSecret) String() string { return s.private }

func TestRuntimeLoggingRedactsBeforeEverySink(t *testing.T) {
	var text bytes.Buffer
	events := &capturedRuntimeSink{}
	logger := slog.New(&runtimeLogHandler{handlers: []slog.Handler{slog.NewTextHandler(&text, nil)}, event: events})
	secret := "NEVER-EXPOSE-THIS-KEY"
	logger.With("private_key", secret).WithGroup("details").Warn("leaf_device_failed",
		"nested", map[string]any{"private_key": secret, "raw": []byte(secret), "key": ed25519.PrivateKey(secret)},
		"opaque", opaqueLogSecret{secret}, "zone", "node.catofes.")
	if strings.Contains(text.String(), secret) || len(events.events) != 1 || strings.Contains(events.events[0].message, secret) {
		t.Fatalf("secret exposed: %q %#v", text.String(), events.events)
	}
	if !strings.Contains(text.String(), "[redacted]") || !strings.Contains(text.String(), "node.catofes.") || events.events[0].level != slog.LevelWarn || events.events[0].id != 502 {
		t.Fatalf("lost severity, event identity or public context: %q %#v", text.String(), events.events)
	}
	logger.Info("unknown_event", "error", `invalid {"IdentityPrivateKey":"`+secret+`"}`)
	if strings.Contains(text.String(), secret) || events.events[1].id != 999 {
		t.Fatal("serialized key exposed or dynamic event id created")
	}
}

func TestRuntimeLogFileRotatesBoundedRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db.log")
	file, err := openRuntimeLog(path)
	if err != nil {
		t.Fatal(err)
	}
	file.limit = 64
	for i := 0; i < 12; i++ {
		if _, err := file.Write([]byte(strings.Repeat("x", 32))); err != nil {
			t.Fatal(err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"", ".1", ".2", ".3"} {
		stat, err := os.Stat(path + suffix)
		if err != nil || stat.Size() > 64 {
			t.Fatalf("rotation %s: %v %v", suffix, stat, err)
		}
	}
	if _, err := os.Stat(path + ".4"); !os.IsNotExist(err) {
		t.Fatal("unbounded rotations")
	}
	if _, err := file.Write([]byte("late")); err == nil {
		t.Fatal("write after close accepted")
	}
}

func TestRuntimeLoggerOwnedFileAndConcurrentClose(t *testing.T) {
	config := &Config{State: StateConfig{Path: filepath.Join(t.TempDir(), "state.db")}, Log: LogConfig{Level: "info"}}
	var text bytes.Buffer
	logger, closer, err := NewRuntimeLogger(config, &text, "")
	if err != nil {
		t.Fatal(err)
	}
	logger.Debug("tunnel_packet_rejected", "error", "not recorded")
	logger.Info("gossip_started", "zone", "node.catofes.")
	var joined sync.WaitGroup
	for range 8 {
		joined.Go(func() {
			if err := closer.Close(); err != nil {
				t.Error(err)
			}
		})
	}
	joined.Wait()
	content, err := os.ReadFile(config.State.Path + ".log")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(content, []byte("not recorded")) || !bytes.Contains(content, []byte("event_id=201")) || string(content) != text.String() {
		t.Fatalf("file/console mismatch: %s %q", content, text.String())
	}
}

func TestRuntimeLoggerRejectsNonregularPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	if err := os.Mkdir(path+".log", 0700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := NewRuntimeLogger(&Config{State: StateConfig{Path: path}}, nil, ""); err == nil {
		t.Fatal("directory adopted as owned log")
	}
	var sink bytes.Buffer
	deep := map[string]any{"public": "ok"}
	for range 20 {
		deep = map[string]any{"next": deep}
	}
	logger := slog.New(&runtimeLogHandler{handlers: []slog.Handler{slog.NewTextHandler(&sink, nil)}})
	logger.Log(context.Background(), slog.LevelInfo, "runtime_started", "value", deep)
	if !strings.Contains(sink.String(), "[truncated]") {
		t.Fatal("unbounded reflective traversal")
	}
}
