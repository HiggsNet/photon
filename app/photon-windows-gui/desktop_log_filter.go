package main

import (
	"strconv"
	"strings"
)

// Filtering changes only the presentation of the existing bounded tail. Parse
// logfmt fields rather than matching an event name inside a quoted error value.
func desktopFilterDiagnosticLog(text string, filter int) string {
	if filter == 3 {
		return text
	}
	var out strings.Builder
	for _, line := range strings.SplitAfter(text, "\n") {
		level, event, component := desktopDiagnosticLogFields(line)
		keep := false
		switch filter {
		case 0:
			for _, prefix := range []string{"runtime_", "gateway_", "tunnel_", "leaf_", "network_", "power_", "gossip_rebind", "gossip_rebound"} {
				keep = keep || strings.HasPrefix(event, prefix)
			}
		case 1:
			keep = strings.EqualFold(level, "warn") || strings.EqualFold(level, "error")
		case 2:
			keep = component == "gossip"
		}
		if keep {
			out.WriteString(line)
		}
	}
	return out.String()
}

func desktopDiagnosticLogFields(line string) (level, event, component string) {
	for line != "" {
		line = strings.TrimLeft(line, " \t\r\n")
		equal := strings.IndexByte(line, '=')
		if equal <= 0 || strings.ContainsAny(line[:equal], " \t\r\n") {
			break
		}
		key, rest := line[:equal], line[equal+1:]
		value := ""
		if strings.HasPrefix(rest, `"`) {
			quoted, err := strconv.QuotedPrefix(rest)
			if err != nil {
				break
			}
			value, err = strconv.Unquote(quoted)
			if err != nil {
				break
			}
			line = rest[len(quoted):]
		} else if end := strings.IndexAny(rest, " \t\r\n"); end >= 0 {
			value, line = rest[:end], rest[end:]
		} else {
			value, line = rest, ""
		}
		if key == "level" && level == "" {
			level = value
		}
		if key == "event" && event == "" {
			event = value
		}
		if key == "component" && component == "" {
			component = value
		}
		if level != "" && event != "" && component != "" {
			break
		}
	}
	return
}
