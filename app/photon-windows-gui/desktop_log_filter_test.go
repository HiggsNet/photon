package main

import (
	"strings"
	"testing"
)

func TestDiagnosticLogFilterSeparatesConnectionFromGossipNoise(t *testing.T) {
	started := "ts=2026-10-16T17:17:04+08:00 level=info event=runtime_started mode=desktop\n"
	rejection := "level=debug event=tunnel_packet_rejected error=\"IKE_AUTH error notification 24\"\n"
	quota := "level=warn event=packet_failed component=gossip error=\"gossip peer quota exceeded\"\n"
	pong := "level=debug event=session_state_changed component=gossip trigger=pong new_state=completed\n"
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
	spoof := "level=info error=\"text event=tunnel_stopped level=error component=gossip\" event=session_state_changed\r\n"
	quoted := "level=error event=\"tunnel_stopped\" error=\"bad \\\"signature\\\"\"\r\n"
	malformed := "level=info event=\"unterminated text\n"
	unknown := "an old free-text record\n"
	if got := desktopFilterDiagnosticLog(spoof+quoted+malformed+unknown, 0); got != quoted {
		t.Fatalf("quoted fields were mistaken for events: %q", got)
	}
	if got := desktopFilterDiagnosticLog(spoof, 1); got != "" {
		t.Fatal("quoted error text forged a warning level")
	}
	if got := desktopFilterDiagnosticLog(spoof, 2); got != "" {
		t.Fatal("quoted error text forged a component")
	}
	if got := desktopFilterDiagnosticLog(malformed+unknown, 3); !strings.Contains(got, unknown) || got != malformed+unknown {
		t.Fatal("all-log view discarded malformed or older records")
	}
}
