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
		level, event := desktopDiagnosticLogFields(line)
		keep := false
		switch filter {
		case 0:
			for _, prefix := range []string{"runtime_", "gateway_", "tunnel_", "leaf_", "network_", "power_", "gossip_rebind", "gossip_rebound"} {
				keep = keep || strings.HasPrefix(event, prefix)
			}
		case 1:
			keep = level == "WARN" || level == "ERROR"
		case 2:
			for _, prefix := range []string{"gossip_", "session_", "worker_", "zone_", "packet_", "sending_announce", "announce_hint", "hinted_sync", "ping_summary"} {
				keep = keep || strings.HasPrefix(event, prefix)
			}
		}
		if keep {
			out.WriteString(line)
		}
	}
	return out.String()
}

func desktopDiagnosticLogFields(line string) (level, event string) {
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
		if key == "msg" && event == "" {
			event = value
		}
		if level != "" && event != "" {
			break
		}
	}
	return
}
