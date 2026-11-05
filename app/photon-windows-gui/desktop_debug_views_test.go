package main

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/photonwindows"
	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

func debugViewFixture() desktopSnapshot {
	return desktopSnapshot{RuntimeState: "running", Observation: &photonwindows.Observation{
		Running: true, ObservedAt: time.Unix(1792119000, 0), Revision: 17,
		Admission: gossip.AdmissionDiagnosis{Reason: gossip.AdmissionReasonAdopted},
		Readiness: photonwindows.ReadinessObservation{Stage: photonwindows.ReadinessStageAddressAssignment, Reason: "no authorized business address in split routes"},
		Gateway:   photonwindows.GatewayObservation{Selected: "gateway.catofes.", PlanRevision: 16, EvaluatedAt: time.Unix(1792118999, 0)},
		IKE:       photonwindows.IKEObservation{Phase: "auth"},
	}}
}

func TestDesktopDebugOverviewSeparatesBlockerSessionStateAndTransferHistory(t *testing.T) {
	snapshot := debugViewFixture()
	snapshot.Observation.IKE.AttemptActive = true
	snapshot.Observation.IKE.AttemptGateway = "gateway.catofes."
	snapshot.Observation.Peers = []photonwindows.PeerObservation{
		{Peer: "done.", PullState: "completed", PullFailures: 200},
		{Peer: "failed.", PullState: "failed", PullSuccesses: 200},
		{Peer: "waiting.", PullState: "catalog_diffing"},
	}
	snapshot.Observation.PeersTruncated = true
	text := desktopFormatOverview(snapshot)
	for _, want := range []string{"[当前状态]\r\n已入网，网关隧道未建立", "当前阶段：等待 IKE 认证（auth）", "尝试网关：gateway.catofes.", "IKE 认证：否", "等待当前分流范围内可用的授权业务 IP", "已完成 1 · 失败 1 · 等待或进行中 1", "节点样本已截断"} {
		if !strings.Contains(text, want) {
			t.Fatalf("overview missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "200") || strings.Contains(text, "[当前状态]\r\n已连接") {
		t.Fatal("transfer counters were presented as session state or an unauthenticated target became connected")
	}
	snapshot.Observation.TunnelReady = true
	snapshot.Observation.IKE.Live, snapshot.Observation.IKE.ChildLive = true, true
	snapshot.Observation.IKE.Gateway = "gateway.catofes."
	snapshot.Observation.Wintun = photonwindows.WintunObservation{Configured: true, Addresses: []netip.Prefix{netip.MustParsePrefix("198.18.253.2/32")}}
	text = desktopFormatOverview(snapshot)
	if !strings.Contains(text, "[当前状态]\r\n已连接") || !strings.Contains(text, "实际业务 IP：198.18.253.2/32") {
		t.Fatal("actual readiness and single-family configured address were lost")
	}
	if strings.Contains(text, "尝试网关：") || strings.Contains(text, "当前阶段：等待 IKE 认证") {
		t.Fatal("authenticated overview retained an unauthenticated-attempt label")
	}
}

func TestDesktopDebugGatewaySeparatesAttemptFailureAndAuthenticatedFacts(t *testing.T) {
	snapshot := debugViewFixture()
	ike := &snapshot.Observation.IKE
	ike.AttemptActive, ike.AttemptGateway, ike.AttemptRemoteEndpoint = true, "gateway.catofes.", "192.0.2.4:4500"
	ike.AttemptGeneration, ike.SendAttempts = 9, 3
	ike.NextRetransmitAt = snapshot.Observation.ObservedAt.Add(time.Second)
	ike.LastFailure = &photonwindows.IKEFailureObservation{Event: "tunnel_stopped", Message: "previous timeout", At: snapshot.Observation.ObservedAt.Add(-time.Minute), Gateway: "previous.catofes.", Historical: true}
	snapshot.Observation.Gateway.Candidates = []photonwindows.GatewayCandidateObservation{{Zone: "gateway.catofes."}, {Zone: "rejected.catofes.", Rejected: "missing signed overlay"}}
	text := desktopFormatGateway(snapshot)
	for _, want := range []string{"[当前尝试（不表示已认证）]", "远端端点：192.0.2.4:4500", "发送轮数：3", "[最近失败（历史记录）]", "previous timeout", "IKE 认证有效：否", "[当前选择] gateway.catofes.", "[拒绝] rejected.catofes.", "原因：missing signed overlay", "计划版本：16"} {
		if !strings.Contains(text, want) {
			t.Fatalf("gateway missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "已认证网关：gateway.catofes.") || strings.Contains(text, "IKE 有效截止") {
		t.Fatal("attempt metadata was presented as authenticated state")
	}
	ike.AttemptActive, ike.Live, ike.ChildLive = false, true, true
	ike.Gateway = "gateway.catofes."
	snapshot.Observation.Babel = photonwindows.BabelObservation{Local: netip.MustParseAddr("fe80::1"), Live: true, Neighbor: netip.MustParseAddr("fe80::2")}
	text = desktopFormatGateway(snapshot)
	if !strings.Contains(text, "已认证网关：gateway.catofes.") || !strings.Contains(text, "当前邻居 IPv6：fe80::2") || !strings.Contains(text, "CHILD 数据隧道有效：是") {
		t.Fatal("authenticated and control-plane facts were lost")
	}
	if strings.Contains(text, "远端端点：192.0.2.4:4500") {
		t.Fatal("inactive attempt retained old endpoint as a current attempt")
	}
	ike.AttemptActive = true
	text = desktopFormatGateway(snapshot)
	if !strings.Contains(text, "[当前隧道与交换]") || !strings.Contains(text, "当前隧道网关：gateway.catofes.") || strings.Contains(text, "[当前尝试（不表示已认证）]") {
		t.Fatal("authenticated target was mislabeled as an unauthenticated attempt")
	}
}

func TestDesktopDebugPeerSelectsOneNodeAndLabelsHistoricalFailures(t *testing.T) {
	snapshot := debugViewFixture()
	when := snapshot.Observation.ObservedAt
	snapshot.Observation.Peers = []photonwindows.PeerObservation{
		{Peer: "other.catofes.", PullState: "failed", SessionFailure: &corestate.PeerFailure{Message: "OTHER_ERROR_SENTINEL"}},
		{Peer: "gateway.catofes.", PullState: "completed", UpdatedAt: when, LastEvent: "snapshot_applied", LastSyncUnix: when.Unix(), PullAttempts: 2, PullFailures: 2, LastPullUnix: when.Add(-time.Minute).Unix(), LastPullZone: "catofes.", LastPullError: "previous TCP refused", ChunkFallbacks: 1},
	}
	before, _ := json.Marshal(snapshot)
	text := desktopFormatPeer(snapshot, "gateway.catofes.")
	for _, want := range []string{"节点：gateway.catofes.", "[当前会话]", "状态：本次同步已完成", "原始状态：completed", "TCP 累计：尝试 2 · 成功 0 · 失败 2", "最后 TCP 错误（历史，不等于当前失败）：previous TCP refused", "UDP 分块回退计数：1"} {
		if !strings.Contains(text, want) {
			t.Fatalf("single peer missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "other.catofes.") || strings.Contains(text, "OTHER_ERROR_SENTINEL") || strings.Contains(text, "状态：同步失败") {
		t.Fatal("another peer or a historical TCP failure was confused with the selected current session")
	}
	row := desktopPeerRow(snapshot.Observation.Peers[1])
	if !strings.HasPrefix(row, "已同步 · ") || !strings.Contains(row, "gateway.catofes.") || strings.ContainsAny(row, "\r\n\t") {
		t.Fatalf("invalid selectable peer row %q", row)
	}
	missing := desktopFormatPeer(snapshot, "removed.catofes.")
	if strings.Contains(missing, "previous TCP refused") || strings.Contains(missing, "removed.catofes.") || !strings.Contains(missing, "请选择") && !strings.Contains(missing, "选择一项") {
		t.Fatal("removed selection retained old peer data")
	}
	after, _ := json.Marshal(snapshot)
	if string(before) != string(after) {
		t.Fatal("formatting mutated detached observation")
	}
}

func TestDesktopDebugViewsClearUnavailableDataAndEscapeRuntimeText(t *testing.T) {
	for _, state := range []string{"stopped", "starting", "stopping", "failed"} {
		snapshot := debugViewFixture()
		snapshot.RuntimeState = state
		for _, text := range []string{desktopFormatOverview(snapshot), desktopFormatGateway(snapshot), desktopFormatPeer(snapshot, "gateway.catofes.")} {
			if !strings.Contains(text, "已清空上次连接数据") || strings.Contains(text, "gateway.catofes.") || strings.Contains(text, "计划版本") {
				t.Fatalf("%s snapshot exposed stale live state: %s", state, text)
			}
		}
	}
	snapshot := debugViewFixture()
	snapshot.Error = "IPC disconnected"
	if text := desktopFormatOverview(snapshot); !strings.Contains(text, "IPC disconnected") || strings.Contains(text, "采样时间") {
		t.Fatal("IPC error retained old sampled facts")
	}
	snapshot.Error = ""
	snapshot.Observation.Gateway.Candidates = []photonwindows.GatewayCandidateObservation{{Zone: "evil.\r\n[FORGED]", Rejected: strings.Repeat("错误", 500) + "\x00"}}
	text := desktopFormatGateway(snapshot)
	if strings.Contains(text, "\r\n[FORGED]") || strings.ContainsRune(text, '\x00') || !strings.Contains(text, "…") {
		t.Fatal("runtime text forged another section or was not bounded")
	}
}

func TestDesktopDebugTimeUsesLocalZoneWithExplicitOffset(t *testing.T) {
	when := time.Date(2026, 10, 16, 3, 32, 0, 0, time.FixedZone("remote", -7*60*60))
	text := desktopDebugTime(when)
	decoded, err := time.Parse("2006-01-02 15:04:05 -07:00", text)
	if err != nil || !decoded.Equal(when) || text != when.In(time.Local).Format("2006-01-02 15:04:05 -07:00") {
		t.Fatalf("ambiguous or incorrect local timestamp %q: %v", text, err)
	}
	if desktopDebugTime(time.Time{}) != "尚无时间记录" || desktopDebugUnix(0) != "尚无时间记录" {
		t.Fatal("absent time became a real timestamp")
	}
}

func TestDesktopDebugIKEKeepsRejectedPacketSeparateFromLifecycleFailure(t *testing.T) {
	snapshot := debugViewFixture()
	ike := &snapshot.Observation.IKE
	ike.LastRejection = &photonwindows.IKEFailureObservation{Event: "packet_rejected", Message: "AUTH signature rejected", At: snapshot.Observation.ObservedAt.Add(-time.Second), Phase: "auth", Gateway: "gateway.catofes."}
	ike.LastFailure = &photonwindows.IKEFailureObservation{Event: "tunnel_stopped", Message: "exchange retry budget exhausted", At: snapshot.Observation.ObservedAt}
	text := desktopFormatGateway(snapshot)
	if !strings.Contains(text, "[最近拒包记录]") || !strings.Contains(text, "AUTH signature rejected") || !strings.Contains(text, "[最近失败]") || !strings.Contains(text, "exchange retry budget exhausted") || !strings.Contains(text, "单个拒包不表示整条隧道失败") {
		t.Fatal("later timeout erased the rejected packet or a single rejected packet became a lifecycle failure")
	}
	overview := desktopFormatOverview(snapshot)
	if !strings.Contains(overview, "[当前状态]\r\n已入网，网关隧道未建立") || !strings.Contains(overview, "最近拒包（不等于连接失败）") {
		t.Fatal("rejection replaced the canonical current connection state")
	}
	// The same record can occupy both slots before a later lifecycle event.
	copyRejection := *ike.LastRejection
	copyRejection.Historical = true
	ike.LastFailure = &copyRejection
	for _, text := range []string{desktopFormatGateway(snapshot), desktopFormatOverview(snapshot)} {
		if strings.Count(text, "AUTH signature rejected") != 1 {
			t.Fatal("the same rejected packet was displayed twice")
		}
	}
	ike.Live, ike.ChildLive, snapshot.Observation.TunnelReady = true, true, true
	ike.LastRejection.Historical = true
	text = desktopFormatGateway(snapshot)
	if !strings.Contains(text, "[最近拒包记录（历史）]") || strings.Contains(text, "[最近失败]") || !strings.Contains(text, "IKE 认证有效：是") {
		t.Fatal("an old rejected packet was presented as current connection failure")
	}
	if text := desktopFormatOverview(snapshot); !strings.Contains(text, "[当前状态]\r\n已连接") || strings.Contains(text, "AUTH signature rejected") {
		t.Fatal("a connected overview was displaced by an old packet rejection")
	}
}

func TestDesktopPeerRowsKeepCompactStates(t *testing.T) {
	for state, label := range map[string]string{"completed": "已同步", "failed": "失败", "idle": "等待", "object_pulling": "拉取中", "": "等待"} {
		row := desktopPeerRow(photonwindows.PeerObservation{Peer: "gateway.catofes.", PullState: state})
		if row != label+" · gateway.catofes." {
			t.Fatalf("long or misleading peer row: %q", row)
		}
	}
}
