package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"log/syslog"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type logLevel string

const (
	logLevelDebug logLevel = "debug"
	logLevelInfo  logLevel = "info"
	logLevelWarn  logLevel = "warn"
	logLevelError logLevel = "error"
)

// Configuration is immutable once logging starts.
type appLogger struct {
	mu      sync.Mutex
	buffer  bytes.Buffer
	handler *slog.TextHandler

	level logLevel
	out   io.Writer
	now   func() time.Time
	mode  logMode
	file  string
}

type logMode string

const (
	logModeStderr       logMode = "stderr"
	logModeFile         logMode = "file"
	logModeSyslog       logMode = "syslog"
	logModeStderrFile   logMode = "stderr+file"
	logModeStderrSyslog logMode = "stderr+syslog"
)

func newAppLogger(config *appConfig) *appLogger {
	level := logLevelInfo
	raw := strings.ToLower(strings.TrimSpace(os.Getenv("PHOTON_LOG_LEVEL")))
	if raw == "" && config != nil {
		raw = strings.ToLower(strings.TrimSpace(config.Log.Level))
	}
	switch logLevel(raw) {
	case logLevelDebug, logLevelInfo, logLevelWarn, logLevelError:
		level = logLevel(raw)
	default:
		// Keep unknown values non-fatal so existing configs continue to run.
	}
	mode := logModeStderr
	file := ""
	if config != nil {
		mode = parseLogMode(config.Log.Mode)
		file = strings.TrimSpace(config.Log.File)
	}
	return &appLogger{level: level, out: os.Stderr, now: time.Now, mode: mode, file: file}
}

func parseLogMode(raw string) logMode {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "stderr", "console":
		return logModeStderr
	case "file":
		return logModeFile
	case "syslog":
		return logModeSyslog
	case "stderr+file", "console+file":
		return logModeStderrFile
	case "stderr+syslog", "console+syslog":
		return logModeStderrSyslog
	default:
		return logModeStderr
	}
}

func isValidLogMode(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "stderr", "console", "file", "syslog", "stderr+file", "console+file", "stderr+syslog", "console+syslog":
		return true
	default:
		return false
	}
}

func (level logLevel) slogLevel() slog.Level {
	switch level {
	case logLevelDebug:
		return slog.LevelDebug
	case logLevelWarn:
		return slog.LevelWarn
	case logLevelError:
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func (l *appLogger) debugEnabled() bool {
	if l == nil {
		l = newAppLogger(nil)
	}
	return slog.LevelDebug >= l.level.slogLevel()
}

func (l *appLogger) Debug(component, event string, fields map[string]any) {
	l.write(logLevelDebug, component, event, fields)
}

// logControlFallback logs a structured warning when a CLI command falls back
// to direct state manipulation because the daemon control socket is not
// available. The fallback is still functional, but operating without the
// daemon is abnormal and should be visible at the default log level.
func logControlFallback(operation string) {
	newAppLogger(nil).Warn("control", "fallback", map[string]any{
		"operation": operation,
		"reason":    "daemon control socket unavailable",
	})
}

func (l *appLogger) Info(component, event string, fields map[string]any) {
	l.write(logLevelInfo, component, event, fields)
}

func (l *appLogger) Warn(component, event string, fields map[string]any) {
	l.write(logLevelWarn, component, event, fields)
}

func (l *appLogger) Error(component, event string, fields map[string]any) {
	l.write(logLevelError, component, event, fields)
}

// replaceLogAttr preserves public field names and timestamp precision.
func replaceLogAttr(groups []string, attr slog.Attr) slog.Attr {
	if len(groups) != 0 {
		return attr
	}
	switch attr.Key {
	case slog.TimeKey:
		return slog.String("ts", attr.Value.Time().UTC().Format(time.RFC3339Nano))
	case slog.LevelKey:
		return slog.String("level", strings.ToLower(attr.Value.String()))
	case slog.MessageKey:
		attr.Key = "component"
	}
	return attr
}

func reservedLogKey(key string) bool {
	switch key {
	case "ts", "level", "component", "event", slog.TimeKey, slog.MessageKey:
		return true
	default:
		return false
	}
}

func (l *appLogger) write(level logLevel, component, event string, fields map[string]any) {
	if l == nil {
		l = newAppLogger(nil)
	}
	// Filter before allocating fields or acquiring the output lock.
	if level.slogLevel() < l.level.slogLevel() {
		return
	}
	now := time.Now
	if l.now != nil {
		now = l.now
	}
	record := slog.NewRecord(now(), level.slogLevel(), component, 0)
	record.AddAttrs(slog.String("event", event))
	keys := make([]string, 0, len(fields))
	for key, value := range fields {
		if value != nil && !reservedLogKey(key) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		record.AddAttrs(slog.Any(key, fields[key]))
	}

	// Protect the reusable buffer and outputs, including non-concurrent writers.
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.handler == nil {
		l.handler = slog.NewTextHandler(&l.buffer, &slog.HandlerOptions{ReplaceAttr: replaceLogAttr})
	}
	l.buffer.Reset()
	// bytes.Buffer.Write cannot fail. Handle does not call Enabled; filtered above.
	_ = l.handler.Handle(context.Background(), record)
	line := l.buffer.Bytes()
	out := l.out
	if out == nil {
		out = os.Stderr
	}
	var sinkErr error
	switch l.mode {
	case "", logModeStderr, logModeStderrFile, logModeStderrSyslog:
		_, sinkErr = out.Write(line)
	}
	switch l.mode {
	case logModeFile, logModeStderrFile:
		sinkErr = errors.Join(sinkErr, l.writeFileLine(line))
	case logModeSyslog, logModeStderrSyslog:
		sinkErr = errors.Join(sinkErr, writeSyslogLine(level, strings.TrimSuffix(string(line), "\n")))
	}
	if sinkErr != nil {
		// Report directly to stderr instead of recursing into the failing sink.
		l.buffer.Reset()
		failure := slog.NewRecord(now(), slog.LevelError, "log", 0)
		failure.AddAttrs(slog.String("event", "sink_failed"), slog.Any("error", sinkErr))
		_ = l.handler.Handle(context.Background(), failure)
		_, _ = out.Write(l.buffer.Bytes())
	}
}

func (l *appLogger) writeFileLine(line []byte) error {
	if l.file == "" {
		return errors.New("log file path is empty")
	}
	// Open per entry so external rename-based rotation keeps working.
	file, err := os.OpenFile(l.file, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(line)
	return errors.Join(writeErr, file.Close())
}

func writeSyslogLine(level logLevel, line string) error {
	writer, err := syslog.New(syslog.LOG_DAEMON|syslog.LOG_INFO, "photon")
	if err != nil {
		return err
	}
	defer writer.Close()
	switch level {
	case logLevelDebug:
		return writer.Debug(line)
	case logLevelWarn:
		return writer.Warning(line)
	case logLevelError:
		return writer.Err(line)
	default:
		return writer.Info(line)
	}
}

type repeatedLogLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	entries  map[string]repeatedLogEntry
}

type repeatedLogEntry struct {
	last       time.Time
	suppressed int
}

func newRepeatedLogLimiter(interval time.Duration) *repeatedLogLimiter {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	return &repeatedLogLimiter{interval: interval, entries: make(map[string]repeatedLogEntry)}
}

func (l *repeatedLogLimiter) Allow(key string, now time.Time) (suppressed int, ok bool) {
	if l == nil || key == "" {
		return 0, true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	entry := l.entries[key]
	if entry.last.IsZero() || now.Sub(entry.last) >= l.interval {
		suppressed = entry.suppressed
		l.entries[key] = repeatedLogEntry{last: now}
		return suppressed, true
	}
	entry.suppressed++
	l.entries[key] = entry
	return 0, false
}
