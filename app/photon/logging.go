package main

import (
	"bytes"
	"fmt"
	"io"
	"log/syslog"
	"os"
	"sort"
	"strconv"
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

type appLogger struct {
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

func logLevelRank(level logLevel) int {
	switch level {
	case logLevelDebug:
		return 0
	case logLevelInfo:
		return 1
	case logLevelWarn:
		return 2
	case logLevelError:
		return 3
	default:
		return logLevelRank(logLevelInfo)
	}
}

func (l *appLogger) enabled(level logLevel) bool {
	if l == nil {
		return newAppLogger(nil).enabled(level)
	}
	if l.level == "" {
		l.level = logLevelInfo
	}
	if logLevelRank(level) < logLevelRank(l.level) {
		return false
	}
	if level == logLevelDebug && l.level != logLevelDebug {
		return false
	}
	return true
}

func (l *appLogger) debugEnabled() bool {
	if l == nil {
		return newAppLogger(nil).debugEnabled()
	}
	return l.level == logLevelDebug
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

func (l *appLogger) write(level logLevel, component, event string, fields map[string]any) {
	if l == nil {
		l = newAppLogger(nil)
	}
	if !l.enabled(level) {
		return
	}
	out := l.out
	if out == nil {
		out = os.Stderr
	}
	now := time.Now
	if l.now != nil {
		now = l.now
	}
	base := map[string]any{
		"ts":        now().UTC().Format(time.RFC3339Nano),
		"level":     level,
		"component": component,
		"event":     event,
	}
	for k, v := range fields {
		if v != nil {
			base[k] = v
		}
	}
	line := renderLogLine(base)
	l.writeLine(level, line)
}

func (l *appLogger) writeLine(level logLevel, line []byte) {
	if len(line) == 0 {
		return
	}
	if l.mode == "" {
		l.mode = logModeStderr
	}
	switch l.mode {
	case logModeStderr, logModeStderrFile, logModeStderrSyslog:
		l.writeStderrLine(line)
	}
	switch l.mode {
	case logModeFile, logModeStderrFile:
		l.writeFileLine(line)
	case logModeSyslog, logModeStderrSyslog:
		l.writeSyslogLine(level, line)
	}
}

func (l *appLogger) writeStderrLine(line []byte) {
	out := l.out
	if out == nil {
		out = os.Stderr
	}
	fmt.Fprintln(out, string(line))
}

func (l *appLogger) writeFileLine(line []byte) {
	if l.file == "" {
		l.writeSinkError("log file path is empty")
		return
	}
	file, err := os.OpenFile(l.file, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		l.writeSinkError(err.Error())
		return
	}
	_, _ = file.Write(append(line, '\n'))
	_ = file.Close()
}

func (l *appLogger) writeSyslogLine(level logLevel, line []byte) {
	if err := writeSyslogLine(level, string(line)); err != nil {
		l.writeSinkError(err.Error())
	}
}

func (l *appLogger) writeSinkError(err string) {
	out := l.out
	if out == nil {
		out = os.Stderr
	}
	fmt.Fprintf(out, "ts=%s level=error component=log event=sink_failed error=%s\n", time.Now().UTC().Format(time.RFC3339Nano), quoteLogValue(err))
}

func renderLogLine(base map[string]any) []byte {
	var buf bytes.Buffer
	keys := make([]string, 0, len(base))
	for key := range base {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	preferred := []string{"ts", "level", "component", "event", "peer_id", "message", "reason", "error"}
	written := make(map[string]bool, len(keys))
	first := true
	for _, key := range preferred {
		if _, ok := base[key]; ok {
			first = writeLogField(&buf, first, key, base[key])
			written[key] = true
		}
	}
	for _, key := range keys {
		if written[key] {
			continue
		}
		first = writeLogField(&buf, first, key, base[key])
	}
	return buf.Bytes()
}

func writeLogField(out io.Writer, first bool, key string, value any) bool {
	if !first {
		fmt.Fprint(out, " ")
	}
	fmt.Fprintf(out, "%s=%s", key, quoteLogValue(value))
	return false
}

func quoteLogValue(value any) string {
	switch v := value.(type) {
	case string:
		if v == "" {
			return `""`
		}
		if strings.ContainsAny(v, " \t\n\r\"=") {
			return strconv.Quote(v)
		}
		return v
	case logLevel:
		return string(v)
	case error:
		return quoteLogValue(v.Error())
	case time.Duration:
		return v.String()
	case fmt.Stringer:
		return quoteLogValue(v.String())
	default:
		return fmt.Sprint(v)
	}
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
