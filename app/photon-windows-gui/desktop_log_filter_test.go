package main

import (
	"strings"
	"testing"
)

func TestDiagnosticLogFilterSeparatesConnectionFromGossipNoise(t *testing.T) {
	started := "time=2026-10-16T17:17:04+08:00 level=INFO msg=runtime_started mode=desktop\n"
	rejection := "level=DEBUG msg=tunnel_packet_rejected error=\"IKE_AUTH error notification 24\"\n"
	quota := "level=WARN msg=gossip_event_failed error=\"gossip peer quota exceeded\"\n"
	pong := "level=DEBUG msg=session_state_changed event=pong new_state=completed\n"
	text := started + rejection + quota + pong
	if got := desktopFilterDiagnosticLog(text, 0); got != started+rejection {
		t.Fatalf("connection events buried in Gossip noise: %s", got)
	}
	if got := desktopFilterDiagnosticLog(text, 1); got != quota {
		t.Fatalf("warning filter: %s", got)
	}
	if got := desktopFilterDiagnosticLog(text, 2); got != quota+pong {
		t.Fatalf("Gossip filter: %s", got)
	}
	if got := desktopFilterDiagnosticLog(text, 3); got != text {
		t.Fatal("all-log view changed the source tail")
	}
}

func TestDiagnosticLogFilterUsesActualFieldsAndPreservesUnknownRawRecords(t *testing.T) {
	spoof := "level=INFO error=\"text msg=tunnel_stopped level=ERROR\" msg=session_state_changed\r\n"
	quoted := "level=ERROR msg=\"tunnel_stopped\" error=\"bad \\\"signature\\\"\"\r\n"
	malformed := "level=INFO msg=\"unterminated text\n"
	unknown := "an old free-text record\n"
	if got := desktopFilterDiagnosticLog(spoof+quoted+malformed+unknown, 0); got != quoted {
		t.Fatalf("quoted fields were mistaken for events: %q", got)
	}
	if got := desktopFilterDiagnosticLog(spoof, 1); got != "" {
		t.Fatal("quoted error text forged a warning level")
	}
	if got := desktopFilterDiagnosticLog(malformed+unknown, 3); !strings.Contains(got, unknown) || got != malformed+unknown {
		t.Fatal("all-log view discarded malformed or older records")
	}
}
