package text

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
)

type lineWriter struct {
	w   io.Writer
	err error
}

func newLineWriter(w io.Writer) *lineWriter {
	return &lineWriter{w: w}
}

func (l *lineWriter) Printf(format string, args ...any) {
	if l == nil || l.err != nil {
		return
	}
	_, l.err = fmt.Fprintf(l.w, format, args...)
}

func (l *lineWriter) PrintIf(cond bool, format string, args ...any) {
	if cond {
		l.Printf(format, args...)
	}
}

func (l *lineWriter) Linef(format string, args ...any) {
	l.Printf(format+"\n", args...)
}

func (l *lineWriter) LineIf(cond bool, format string, args ...any) {
	if cond {
		l.Linef(format, args...)
	}
}

func (l *lineWriter) Println(args ...any) {
	if l == nil || l.err != nil {
		return
	}
	_, l.err = fmt.Fprintln(l.w, args...)
}

func (l *lineWriter) Blank() {
	l.Println()
}

func (l *lineWriter) Err() error {
	if l == nil {
		return nil
	}
	return l.err
}

func defaultText(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func failureMessage(failure *inspect.FailureView) string {
	if failure == nil {
		return ""
	}
	return failure.Message
}

func failureDisplay(failure *inspect.FailureView) string {
	if failure == nil {
		return "-"
	}
	if failure.Message == "" {
		return "code=" + failure.Code
	}
	return fmt.Sprintf("code=%s message=%s", failure.Code, failure.Message)
}

func WriteJSON(w io.Writer, value any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(value)
}

func formatDuration(d time.Duration) string {
	if d <= 0 {
		return "default"
	}
	return d.String()
}

func shortText(value string, max int) string {
	if value == "" {
		return "-"
	}
	if len(value) <= max {
		return value
	}
	return value[:max] + "..."
}

func escapeTableCell(value string) string {
	return strings.NewReplacer(
		"\t", `\t`,
		"\r", `\r`,
		"\n", `\n`,
	).Replace(value)
}
