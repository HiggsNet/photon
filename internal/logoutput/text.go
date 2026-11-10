package logoutput

import (
	"io"
	"log/slog"
	"strings"
	"time"
)

// TextHandler formats the same structured record for any Photon text sink.
func TextHandler(out io.Writer, level slog.Level) *slog.TextHandler {
	return slog.NewTextHandler(out, &slog.HandlerOptions{Level: level, ReplaceAttr: replaceAttr})
}

func replaceAttr(groups []string, attr slog.Attr) slog.Attr {
	if len(groups) != 0 {
		return attr
	}
	switch attr.Key {
	case slog.TimeKey:
		return slog.String("ts", attr.Value.Time().UTC().Format(time.RFC3339Nano))
	case slog.LevelKey:
		return slog.String("level", strings.ToLower(attr.Value.String()))
	case slog.MessageKey:
		if attr.Value.String() == "" {
			return slog.Attr{}
		}
		attr.Key = "event"
	}
	return attr
}
