package ipsec

import "testing"

func TestParseSAStatesRecognizesResponderWithoutInitiatorFlag(t *testing.T) {
	states := parseSAStates(map[string]any{"ipsec-responder": map[string]any{
		"uniqueid": "42", "version": "2", "state": "ESTABLISHED",
		"initiator-spi": "0123456789abcdef", "responder-spi": "fedcba9876543210",
	}})
	if len(states) != 1 || !states[0].InitiatorKnown || states[0].Initiator {
		t.Fatalf("responder direction = %+v", states)
	}
}

func TestParseSAStatesFromVICIListSAs(t *testing.T) {
	states := parseSAStates(map[string]any{
		"ipsec-main-ab": map[string]any{
			"uniqueid":    "42",
			"initiator":   "yes",
			"established": "180",
			"local-host":  "198.51.100.10",
			"local-port":  "4500",
			"local-id":    "node-a.catofes.",
			"remote-host": "2001:db8::20",
			"remote-port": "4500",
			"remote-id":   "node-b.catofes.",
			"state":       "ESTABLISHED",
			"child-sas": map[string]any{
				"ipsec-main-ab-child": map[string]any{
					"reqid":        "17",
					"if-id-in":     "0",
					"if-id-out":    "4e",
					"state":        "INSTALLED",
					"install-time": "175",
					"bytes-in":     "4096",
					"packets-in":   "32",
					"use-in":       "45",
				},
			},
		},
	})
	if len(states) != 1 {
		t.Fatalf("states len = %d, want 1: %+v", len(states), states)
	}
	got := states[0]
	if got.Name != "ipsec-main-ab" || got.ChildSA != "ipsec-main-ab-child" {
		t.Fatalf("names = %+v", got)
	}
	if got.LocalIdentity != "node-a.catofes." || got.RemoteIdentity != "node-b.catofes." {
		t.Fatalf("identities = %+v", got)
	}
	if got.LocalEndpoint != "198.51.100.10:4500" || got.RemoteEndpoint != "[2001:db8::20]:4500" || got.Endpoint != got.RemoteEndpoint {
		t.Fatalf("endpoints = %+v", got)
	}
	if got.XFRMIfID != 78 || got.ReqID != 17 || !got.Established {
		t.Fatalf("child fields = %+v", got)
	}
	if got.UniqueID != 42 || !got.InitiatorKnown || !got.Initiator || got.IKEAgeSeconds != 180 || got.ChildAgeSeconds != 175 {
		t.Fatalf("GC fields = %+v", got)
	}
	if !got.InboundKnown || got.InboundBytes != 4096 || got.InboundPackets != 32 || got.InboundIdleSecs != 45 {
		t.Fatalf("inbound activity fields = %+v", got)
	}
}

func TestParseSAStatesDoesNotMarkConnectingIKEEstablished(t *testing.T) {
	states := parseSAStates(map[string]any{
		"ipsec-main-ab": map[string]any{
			"local-host":  "198.51.100.10",
			"local-port":  "4500",
			"remote-host": "198.51.100.20",
			"remote-port": "4500",
			"state":       "CONNECTING",
			"child-sas": map[string]any{
				"ipsec-main-ab-child": map[string]any{
					"reqid":     "17",
					"if-id-out": "4d",
					"state":     "CREATED",
				},
			},
		},
	})
	if len(states) != 1 {
		t.Fatalf("states len = %d, want 1: %+v", len(states), states)
	}
	if states[0].Established {
		t.Fatalf("connecting SA parsed as established: %+v", states[0])
	}
	if states[0].IKEState != "CONNECTING" || states[0].ChildState != "CREATED" {
		t.Fatalf("states = %+v, want raw StrongSwan states preserved", states[0])
	}
}
