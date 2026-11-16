package main

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/HiggsNet/photon/internal/photonwindows"
)

func TestGatewayNodesJoinCurrentFactsWithoutMutatingObservation(t *testing.T) {
	s := debugViewFixture()
	o := s.Observation
	o.Gateway.Candidates = []photonwindows.GatewayCandidateObservation{{Zone: "z.example."}, {Zone: "gateway.catofes."}, {Zone: "a.example.", Rejected: "missing authorization"}}
	o.IKE.Gateway, o.IKE.Live, o.IKE.ChildLive, o.TunnelReady = "gateway.catofes.", true, true, true
	o.IKE.AttemptGateway = "gateway.catofes."
	o.IKE.LastFailure = &photonwindows.IKEFailureObservation{Gateway: "previous.example.", Message: "previous timeout", Historical: true}
	before, _ := json.Marshal(s)
	if got := desktopGatewayNodes(s); !slices.Equal(got, []string{"a.example.", "gateway.catofes.", "previous.example.", "z.example."}) {
		t.Fatalf("unstable, duplicated or missing node identities: %v", got)
	}
	active := desktopFormatGatewayNode(s, "gateway.catofes.")
	if !strings.Contains(active, "状态：业务就绪") || !strings.Contains(active, "CHILD 数据隧道有效：是") || strings.Contains(active, "previous timeout") || strings.Contains(active, "missing authorization") {
		t.Fatalf("active node lost facts or included another node's error:\n%s", active)
	}
	rejected := desktopFormatGatewayNode(s, "a.example.")
	if !strings.Contains(rejected, "状态：不可尝试") || !strings.Contains(rejected, "missing authorization") || strings.Contains(rejected, "CHILD 数据隧道有效：是") || strings.Contains(rejected, "实际业务 IP") {
		t.Fatalf("candidate inherited active gateway state:\n%s", rejected)
	}
	previous := desktopFormatGatewayNode(s, "previous.example.")
	if !strings.Contains(previous, "状态：历史记录") || !strings.Contains(previous, "[最近失败（历史记录）]") || !strings.Contains(previous, "previous timeout") {
		t.Fatalf("historical failure lost attribution:\n%s", previous)
	}
	after, _ := json.Marshal(s)
	if string(before) != string(after) {
		t.Fatal("node views modified the daemon's detached observation")
	}
	for _, state := range []string{"stopped", "starting", "failed"} {
		s.RuntimeState = state
		if len(desktopGatewayNodes(s)) != 0 || strings.Contains(desktopFormatGatewayNode(s, "gateway.catofes."), "gateway.catofes.") {
			t.Fatalf("%s retained live node details", state)
		}
	}
	s.RuntimeState, s.Error = "running", "IPC disconnected"
	if len(desktopGatewayNodes(s)) != 0 || !strings.Contains(desktopFormatGatewayNode(s, "gateway.catofes."), s.Error) {
		t.Fatal("IPC failure retained node facts or hid its cause")
	}
}

func TestGatewayNodeDistinguishesAttemptAuthenticationAndReadiness(t *testing.T) {
	s := debugViewFixture()
	o := s.Observation
	ike := &o.IKE
	ike.AttemptGateway, ike.AttemptRemoteEndpoint = "gateway.catofes.", "192.0.2.4:4500"
	ike.AttemptActive, ike.SendAttempts = true, 3
	ike.LastRejection = &photonwindows.IKEFailureObservation{Gateway: "gateway.catofes.", Event: "packet_rejected", Message: "rejected packet"}
	text := desktopFormatGatewayNode(s, "gateway.catofes.")
	for _, want := range []string{"状态：连接中", "IKE 认证有效：否", "远端端点：192.0.2.4:4500", "交换发送轮数：3", "单个拒包不表示整条隧道失败"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q:\n%s", want, text)
		}
	}
	ike.AttemptActive = false
	if text := desktopFormatGatewayNode(s, "gateway.catofes."); strings.Contains(text, "远端端点：192.0.2.4:4500") || !strings.Contains(text, "状态：待连接") {
		t.Fatal("ended attempt kept its endpoint live or became a connection failure from a rejected packet")
	}
	ike.Gateway, ike.Live = "gateway.catofes.", true
	if desktopGatewayState(o, ike.Gateway) != "已认证" {
		t.Fatal("authentication inferred data tunnel readiness")
	}
	ike.ChildLive = true
	if desktopGatewayState(o, ike.Gateway) != "隧道已建立" {
		t.Fatal("data tunnel inferred business readiness")
	}
	o.TunnelReady = true
	if desktopGatewayState(o, ike.Gateway) != "业务就绪" {
		t.Fatal("explicit readiness was lost")
	}
	if strings.Contains(desktopFormatGatewayNode(s, "missing.example."), "状态：业务就绪") {
		t.Fatal("removed node retained another node's state")
	}
}

func TestGatewayNodeHidesRecoveredFailuresButKeepsDebugEvidence(t *testing.T) {
	s := debugViewFixture()
	ike := &s.Observation.IKE
	ike.Gateway, ike.Live, ike.ChildLive = "gateway.catofes.", true, true
	ike.LastFailure = &photonwindows.IKEFailureObservation{Gateway: ike.Gateway, Message: "previous timeout", Historical: true}
	ike.LastRejection = &photonwindows.IKEFailureObservation{Gateway: ike.Gateway, Event: "packet_rejected", Message: "previous AUTH failure", Historical: true}
	before, _ := json.Marshal(s)
	for _, ready := range []bool{false, true} {
		s.Observation.TunnelReady = ready
		text := desktopFormatGatewayNode(s, ike.Gateway)
		if strings.Contains(text, "previous timeout") || strings.Contains(text, "previous AUTH failure") {
			t.Fatal("established tunnel displayed a recovered failure", text)
		}
		debug := desktopFormatGateway(s)
		if !strings.Contains(debug, "previous timeout") || !strings.Contains(debug, "previous AUTH failure") {
			t.Fatal("debug view lost historical diagnostics", debug)
		}
	}
	s.Observation.TunnelReady = false
	after, _ := json.Marshal(s)
	if string(before) != string(after) {
		t.Fatal("display changed diagnostic evidence")
	}
	ike.Live, ike.ChildLive = false, false
	if text := desktopFormatGatewayNode(s, ike.Gateway); !strings.Contains(text, "previous timeout") {
		t.Fatal("disconnected tunnel lost failure details", text)
	}
}

func TestGatewayNodeUsesItsOwnMeshConnection(t *testing.T) {
	s := debugViewFixture()
	o := s.Observation
	o.IKE = photonwindows.IKEObservation{Gateway: "gateway.catofes.", Live: true, ChildLive: true}
	o.TunnelReady = true
	o.Connections = []photonwindows.ConnectionObservation{
		{Peer: "second.example.", IKE: photonwindows.IKEObservation{Gateway: "second.example.", Live: true, ChildLive: true}, BabelLive: true, TunnelReady: true},
		{Peer: "offline.example."},
	}
	if !slices.Contains(desktopGatewayNodes(s), "second.example.") {
		t.Fatal("live Mesh peer missing from node list")
	}
	for id, want := range map[string]string{
		"second.example.":  "状态：业务就绪",
		"offline.example.": "状态：未建立隧道",
	} {
		if got := desktopFormatGatewayNode(s, id); !strings.Contains(got, want) {
			t.Fatalf("node %s missing %q:\n%s", id, want, got)
		}
	}
}
