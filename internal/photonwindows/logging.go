package photonwindows

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"
)

const logFileLimit = 8 << 20

// Event IDs are fixed and independent of peers, addresses and error text.
// EventCreate's installed message resources cover these IDs (1..1000).
var runtimeEventIDs = map[string]uint32{
	"runtime_started": 101, "runtime_start_failed": 102, "runtime_stopped": 103, "runtime_stop_failed": 104,
	"gossip_started": 201, "gossip_rebound": 202, "gossip_rebind_failed": 203, "gossip_event_failed": 204,
	"gossip_receive_failed": 205, "gossip_sync_failed": 206, "gossip_bootstrap_refresh_failed": 207,
	"gateway_candidates_changed": 301, "gateway_plan_changed": 302,
	"tunnel_authenticated": 401, "tunnel_ready_changed": 402, "tunnel_stopped": 403, "tunnel_packet_rejected": 404, "tunnel_local_identity_unavailable": 405,
	"leaf_unavailable": 501, "leaf_device_failed": 502, "leaf_read_failed": 503, "leaf_packet_failed": 504, "leaf_cleanup_failed": 505,
	"power_resumed": 601,
}

type runtimeEventSink interface {
	Report(slog.Level, uint32, string) error
	Close() error
}

// NewRuntimeLogger owns one bounded file beside the state database.
// Console also writes to its supplied stream; SCM writes to its registered
// Event Log source. Neither sink receives key material or raw packet bytes.
func NewRuntimeLogger(config *Config, console io.Writer, serviceName string) (*slog.Logger, io.Closer, error) {
	if config == nil || config.State.Path == "" {
		return nil, nil, errors.New("runtime logging requires a state path")
	}
	var level slog.Level
	if err := level.UnmarshalText([]byte(config.Log.Level)); err != nil && config.Log.Level != "" {
		return nil, nil, fmt.Errorf("log level: %w", err)
	}
	// The logger is created before Daemon.Run, including on first auto-join.
	// This creates directories only, never an identity or database.
	if err := os.MkdirAll(filepath.Dir(config.State.Path), 0700); err != nil {
		return nil, nil, fmt.Errorf("create runtime log directory: %w", err)
	}
	file, err := openRuntimeLog(config.State.Path + ".log")
	if err != nil {
		return nil, nil, fmt.Errorf("open runtime log: %w", err)
	}
	var event runtimeEventSink
	if serviceName != "" {
		event, err = openRuntimeEventSink(serviceName)
		if err != nil {
			file.Close()
			return nil, nil, fmt.Errorf("open Event Log: %w", err)
		}
	}
	handlers := []slog.Handler{slog.NewTextHandler(file, &slog.HandlerOptions{Level: level})}
	if console != nil {
		handlers = append(handlers, slog.NewTextHandler(console, &slog.HandlerOptions{Level: level}))
	}
	handler := &runtimeLogHandler{handlers: handlers, event: event, level: level}
	return slog.New(handler), &runtimeLogCloser{file: file, event: event}, nil
}

type runtimeLogCloser struct {
	file  *runtimeLogFile
	event runtimeEventSink
	once  sync.Once
	err   error
}

func (c *runtimeLogCloser) Close() error {
	c.once.Do(func() {
		c.err = c.file.Close()
		if c.event != nil {
			c.err = errors.Join(c.err, c.event.Close())
		}
	})
	return c.err
}

type runtimeLogHandler struct {
	handlers []slog.Handler
	event    runtimeEventSink
	level    slog.Level
	attrs    []slog.Attr
	groups   []string
}

func (h *runtimeLogHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
}
func (h *runtimeLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	next := *h
	next.attrs = append(append([]slog.Attr(nil), h.attrs...), attrs...)
	return &next
}
func (h *runtimeLogHandler) WithGroup(group string) slog.Handler {
	next := *h
	next.groups = append(append([]string(nil), h.groups...), group)
	return &next
}
func (h *runtimeLogHandler) Handle(ctx context.Context, record slog.Record) error {
	id := runtimeEventIDs[record.Message]
	if id == 0 {
		id = 999
	}
	safe := slog.NewRecord(record.Time, record.Level, redactLogText(record.Message), record.PC)
	var attrs []slog.Attr
	for _, attr := range h.attrs {
		attrs = append(attrs, sanitizeLogAttr(attr))
	}
	record.Attrs(func(attr slog.Attr) bool { attrs = append(attrs, sanitizeLogAttr(attr)); return true })
	for n := len(h.groups) - 1; n >= 0; n-- {
		attrs = []slog.Attr{{Key: h.groups[n], Value: slog.GroupValue(attrs...)}}
	}
	safe.AddAttrs(slog.Uint64("event_id", uint64(id)))
	safe.AddAttrs(attrs...)
	var result error
	for _, handler := range h.handlers {
		result = errors.Join(result, handler.Handle(ctx, safe))
	}
	if h.event != nil && record.Level >= slog.LevelInfo {
		// Use the same sanitized representation, never the original record.
		var text strings.Builder
		_ = slog.NewTextHandler(&text, nil).Handle(ctx, safe)
		result = errors.Join(result, h.event.Report(record.Level, id, text.String()))
	}
	return result
}

func sensitiveLogKey(key string) bool {
	key = strings.ToLower(strings.ReplaceAll(key, "-", "_"))
	for _, part := range []string{"private", "secret", "password", "payload", "packet", "token", "signature", "key_material"} {
		if strings.Contains(key, part) {
			return true
		}
	}
	return key == "key" || key == "publickey" || key == "public_key"
}

func redactLogText(text string) string {
	lower := strings.ToLower(text)
	if strings.Contains(text, "PRIVATE KEY") || strings.Contains(lower, "private_key") || strings.Contains(lower, "privatekey") {
		return "[redacted]"
	}
	if len(text) > 4096 {
		return text[:4096] + " [truncated]"
	}
	return text
}

func sanitizeLogAttr(attr slog.Attr) slog.Attr {
	attr.Value = attr.Value.Resolve()
	if sensitiveLogKey(attr.Key) {
		return slog.String(attr.Key, "[redacted]")
	}
	switch attr.Value.Kind() {
	case slog.KindString:
		attr.Value = slog.StringValue(redactLogText(attr.Value.String()))
	case slog.KindGroup:
		children := attr.Value.Group()
		clean := make([]slog.Attr, 0, len(children))
		for _, child := range children {
			clean = append(clean, sanitizeLogAttr(child))
		}
		attr.Value = slog.GroupValue(clean...)
	case slog.KindAny:
		budget := 256
		attr.Value = slog.AnyValue(sanitizeLogValue(reflect.ValueOf(attr.Value.Any()), 0, &budget))
	}
	return attr
}

// Public runtime DTOs can contain nested byte/key fields. Bound traversal and
// redact them before any formatter or custom String method can expose bytes.
func sanitizeLogValue(value reflect.Value, depth int, budget *int) any {
	*budget--
	if !value.IsValid() {
		return nil
	}
	if depth > 6 || *budget < 0 {
		return "[truncated]"
	}
	if (value.Kind() == reflect.Interface || value.Kind() == reflect.Pointer) && value.IsNil() {
		return nil
	}
	if value.CanInterface() {
		if err, ok := value.Interface().(error); ok {
			return redactLogText(err.Error())
		}
		switch typed := value.Interface().(type) {
		case netip.Addr:
			return typed.String()
		case netip.Prefix:
			return typed.String()
		case netip.AddrPort:
			return typed.String()
		case time.Time:
			return typed.Format(time.RFC3339Nano)
		}
	}
	if value.Kind() == reflect.Interface || value.Kind() == reflect.Pointer {
		return sanitizeLogValue(value.Elem(), depth+1, budget)
	}
	switch value.Kind() {
	case reflect.Slice, reflect.Array:
		if value.Type().Elem().Kind() == reflect.Uint8 {
			return "[redacted]"
		}
		n := min(value.Len(), 64)
		out := make([]any, 0, n+1)
		for i := 0; i < n; i++ {
			out = append(out, sanitizeLogValue(value.Index(i), depth+1, budget))
		}
		if value.Len() > n {
			out = append(out, "[truncated]")
		}
		return out
	case reflect.Map:
		if value.Type().Key().Kind() != reflect.String {
			return "[opaque]"
		}
		out := make(map[string]any)
		iter := value.MapRange()
		for n := 0; n < 64 && iter.Next(); n++ {
			rawKey := iter.Key().String()
			key := redactLogText(rawKey)
			if sensitiveLogKey(rawKey) {
				out[key] = "[redacted]"
			} else {
				out[key] = sanitizeLogValue(iter.Value(), depth+1, budget)
			}
		}
		return out
	case reflect.Struct:
		out := make(map[string]any)
		for i := 0; i < value.NumField() && i < 64; i++ {
			field := value.Type().Field(i)
			if field.PkgPath != "" {
				continue
			}
			if sensitiveLogKey(field.Name) {
				out[field.Name] = "[redacted]"
			} else {
				out[field.Name] = sanitizeLogValue(value.Field(i), depth+1, budget)
			}
		}
		if len(out) == 0 {
			return "[opaque]"
		}
		return out
	case reflect.String:
		return redactLogText(value.String())
	case reflect.Bool:
		return value.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return value.Int()
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return value.Uint()
	case reflect.Float32, reflect.Float64:
		return value.Float()
	case reflect.Complex64, reflect.Complex128:
		return value.Complex()
	default:
		return "[opaque]"
	}
}

type runtimeLogFile struct {
	mu    sync.Mutex
	path  string
	file  *os.File
	size  int64
	limit int64
}

func openRuntimeLog(path string) (*runtimeLogFile, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	writer := &runtimeLogFile{path: path, limit: logFileLimit}
	// Do not silently adopt oversized or nonregular history and then claim a
	// bounded four-file log. Leave rejected existing files untouched.
	for n := 1; n <= 3; n++ {
		if err := writer.validate(fmt.Sprintf("%s.%d", path, n)); err != nil {
			return nil, err
		}
	}
	if err := writer.open(); err != nil {
		return nil, err
	}
	return writer, nil
}
func (w *runtimeLogFile) validate(path string) error {
	stat, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !stat.Mode().IsRegular() || stat.Size() > w.limit {
		return errors.New("runtime log must be a regular file within the size limit")
	}
	return nil
}
func (w *runtimeLogFile) open() error {
	if err := w.validate(w.path); err != nil {
		return err
	}
	file, err := os.OpenFile(w.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	stat, err := file.Stat()
	if err != nil {
		file.Close()
		return err
	}
	if !stat.Mode().IsRegular() || stat.Size() > w.limit {
		file.Close()
		return errors.New("runtime log must be a regular file within the size limit")
	}
	w.file, w.size = file, stat.Size()
	return nil
}
func (w *runtimeLogFile) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return 0, os.ErrClosed
	}
	if int64(len(data)) > w.limit {
		return 0, errors.New("runtime log record exceeds file limit")
	}
	if w.size+int64(len(data)) > w.limit {
		if err := w.file.Close(); err != nil {
			return 0, err
		}
		w.file = nil
		for n := 3; n >= 1; n-- {
			source := w.path
			if n > 1 {
				source = fmt.Sprintf("%s.%d", w.path, n-1)
			}
			target := fmt.Sprintf("%s.%d", w.path, n)
			if err := os.Remove(target); err != nil && !errors.Is(err, os.ErrNotExist) {
				return 0, err
			}
			if err := os.Rename(source, target); err != nil && !errors.Is(err, os.ErrNotExist) {
				return 0, err
			}
		}
		if err := w.open(); err != nil {
			return 0, err
		}
	}
	n, err := w.file.Write(data)
	w.size += int64(n)
	return n, err
}
func (w *runtimeLogFile) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return nil
	}
	err := w.file.Close()
	w.file = nil
	return err
}
