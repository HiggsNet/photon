package main

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/HiggsNet/photon/internal/photonwindows"
	"github.com/HiggsNet/photon/pkg/core/gossip"
)

func TestDesktopReadinessUsesCanonicalReasonAndActualDeviceAddresses(t *testing.T) {
	observation := &photonwindows.Observation{Running: true, Admission: gossip.AdmissionDiagnosis{Reason: gossip.AdmissionReasonAdopted}}
	view := desktopReadinessPresentation(observation, true)
	if view.Status != "" || strings.Contains(view.Detail, "尚无当前配置") || strings.Contains(view.Tooltip, "分配") {
		t.Fatal("missing device was treated as missing IP authority")
	}
	observation.Readiness = photonwindows.ReadinessObservation{Stage: photonwindows.ReadinessStageAddressAssignment, Reason: "no usable signed assignment for the configured split routes"}
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
