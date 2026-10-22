package main

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"github.com/HiggsNet/photon/internal/photonwindows"
	"github.com/HiggsNet/photon/pkg/core/gossip"
)

func TestDesktopReadinessUsesCanonicalReasonAndActualDeviceAddresses(t *testing.T) {
	observation := &photonwindows.Observation{Running: true, Admission: gossip.AdmissionDiagnosis{Reason: gossip.AdmissionReasonAdopted}}
	view := desktopReadinessPresentation(observation, true)
	if view.Status != "已入网，网关隧道未建立" || strings.Contains(view.Detail, "尚无当前配置") || strings.Contains(view.Tooltip, "分配") {
		t.Fatal("missing device was treated as missing IP authority")
	}
	observation.Readiness = photonwindows.ReadinessObservation{Stage: photonwindows.ReadinessStageAddressAssignment, Reason: "no usable signed assignment for the configured split routes"}
	observation.IKE = photonwindows.IKEObservation{Live: true, ChildLive: true}
	observation.Babel = photonwindows.BabelObservation{Local: netip.MustParseAddr("fe80::1"), Live: true, Neighbor: netip.MustParseAddr("fe80::2")}
	view = desktopReadinessPresentation(observation, true)
	if view.Status != "已入网，等待业务IP分配" || !strings.Contains(view.Detail, observation.Readiness.Reason) || !strings.Contains(view.Detail, "自动继续连接") || strings.Contains(view.Detail, "已有当前配置可用") {
		t.Fatal("canonical assignment wait was not displayed precisely")
	}
	if !strings.Contains(view.LinkSummary, "fe80::1") || !strings.Contains(view.Detail, "fe80::2") || strings.Contains(view.AddressSummary, "fe80") {
		t.Fatal("observed user-space link addresses were lost or mislabeled as configured business IP")
	}
	observation.Babel.Live = false
	if got := desktopReadinessPresentation(observation, true); strings.Contains(got.Detail, "fe80::2") {
		t.Fatal("expired Babel neighbor retained a live peer link address")
	}
	observation.Babel.Live = true
	observation.Readiness.Stage = photonwindows.ReadinessStageAddressAnnouncement
	view = desktopReadinessPresentation(observation, true)
	if view.Status != "已入网，等待地址同步" || !strings.Contains(view.Detail, "已有当前配置可用") || strings.Contains(view.Status, "等待业务IP分配") {
		t.Fatal("assignment intent and actual address publication were conflated")
	}
	observation.Readiness = photonwindows.ReadinessObservation{Reason: "another current-view authorization error"}
	view = desktopReadinessPresentation(observation, true)
	if view.Status != "" || !strings.Contains(view.Detail, observation.Readiness.Reason) {
		t.Fatal("an unclassified failure was relabeled as missing allocation")
	}
	observation.Readiness = photonwindows.ReadinessObservation{Stage: photonwindows.ReadinessStageAddressAssignment}
	observation.TunnelReady = true
	observation.Wintun = photonwindows.WintunObservation{Configured: true, Addresses: []netip.Prefix{netip.MustParsePrefix("198.18.253.2/32")}}
	view = desktopReadinessPresentation(observation, true)
	if view.Status != "" || view.Tooltip != "" || !strings.Contains(view.AddressSummary, "198.18.253.2/32") {
		t.Fatal("actual readiness was replaced by a wait or required both address families")
	}
	observation.Wintun.Addresses = append(observation.Wintun.Addresses, netip.MustParsePrefix("fd00:7068:b4::2/128"))
	view = desktopReadinessPresentation(observation, true)
	if !strings.Contains(view.AddressSummary, "共 2 个") || !strings.Contains(view.Detail, "198.18.253.2/32、fd00:7068:b4::2/128") {
		t.Fatal("actual configured address list was lost")
	}
	observation.Wintun.Truncated = true
	if view := desktopReadinessPresentation(observation, true); !strings.Contains(view.Detail, "样本已截断") {
		t.Fatal("truncated address sample was presented as complete")
	}
}

func TestDesktopReadinessDoesNotHideUnestablishedTunnelBehindMissingIP(t *testing.T) {
	// Regression for the real status copied by the user: admitted, missing an
	// address assignment, and no authenticated gateway or link-local pipeline.
	var observation photonwindows.Observation
	if err := json.Unmarshal([]byte(`{
		"running":true,"admission":{"pending":false,"reason":"adopted"},
		"readiness":{"stage":"address_assignment","reason":"leaf: no authorized unicast host assignment in configured split routes"},
		"wintun":{"configured":false,"addresses":null},
		"ike":{"live":false,"child_live":false,"generation":0},
		"babel":{"live":false,"local":"","neighbor":""}
	}`), &observation); err != nil {
		t.Fatal(err)
	}
	view := desktopReadinessPresentation(&observation, true)
	if view.Status != "已入网，网关隧道未建立" || !strings.Contains(view.Detail, "等待业务 IP 不表示隧道已经连通") || !strings.Contains(view.Detail, "尚无当前配置可用的有效业务 IP 授权") || !strings.Contains(view.LinkSummary, "尚未就绪") {
		t.Fatalf("no-SA/missing-IP diagnostic is misleading: %+v", view)
	}
	observation.Gateway = photonwindows.GatewayObservation{Rejected: "no authorized gateway contact", Candidates: []photonwindows.GatewayCandidateObservation{{Zone: "venus-aliyun-pek.catofes.", Rejected: "missing or mismatched record: ipsec/overlays/main"}}}
	if view := desktopReadinessPresentation(&observation, true); !strings.Contains(view.Detail, "venus-aliyun-pek.catofes.") || !strings.Contains(view.Detail, "ipsec/overlays/main") {
		t.Fatal("planner rejection was hidden from the connection details")
	}
	observation.IKE.Live = true
	if view := desktopReadinessPresentation(&observation, true); view.Status != "已入网，等待数据隧道" {
		t.Fatalf("IKE authentication was confused with a live Child SA: %+v", view)
	}
	observation.IKE.ChildLive = true
	if view := desktopReadinessPresentation(&observation, true); view.Status != "已入网，等待链路本地控制面" {
		t.Fatalf("missing link-local pipeline was hidden: %+v", view)
	}
	observation.Babel.Local = netip.MustParseAddr("fe80::1")
	if view := desktopReadinessPresentation(&observation, true); view.Status != "已入网，等待Babel邻居" {
		t.Fatalf("missing Babel neighbor was hidden: %+v", view)
	}
	observation.Babel.Live = true
	if view := desktopReadinessPresentation(&observation, true); view.Status != "已入网，等待业务IP分配" {
		t.Fatalf("confirmed control plane no longer shows independent address wait: %+v", view)
	}
}

func TestDesktopReadinessClearsUnavailablePendingAndDetachedAddresses(t *testing.T) {
	observation := &photonwindows.Observation{Running: true, Admission: gossip.AdmissionDiagnosis{Reason: gossip.AdmissionReasonAdopted}, Wintun: photonwindows.WintunObservation{Configured: true, Addresses: []netip.Prefix{netip.MustParsePrefix("198.18.253.2/32")}}, Babel: photonwindows.BabelObservation{Local: netip.MustParseAddr("fe80::1"), Live: true, Neighbor: netip.MustParseAddr("fe80::2")}, Readiness: photonwindows.ReadinessObservation{Stage: photonwindows.ReadinessStageAddressAssignment}}
	if got := desktopReadinessPresentation(observation, false); got != (desktopReadinessView{}) {
		t.Fatal("unavailable sample retained an address or waiting reason")
	}
	observation.Running = false
	if got := desktopReadinessPresentation(observation, true); got != (desktopReadinessView{}) {
		t.Fatal("stopped daemon retained an address or waiting reason")
	}
	observation.Running = true
	observation.Admission.Pending = true
	if got := desktopReadinessPresentation(observation, true); got != (desktopReadinessView{}) {
		t.Fatal("pending admission retained a configured address from another identity")
	}
	observation.Admission.Pending = false
	observation.Wintun.Configured = false
	if got := desktopReadinessPresentation(observation, true); strings.Contains(got.Detail, "198.18.253.2") || strings.Contains(got.AddressSummary, "198.18.253.2") {
		t.Fatal("detached device addresses were shown as currently configured")
	}
}
