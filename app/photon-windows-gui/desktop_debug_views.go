package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/HiggsNet/photon/internal/photonwindows"
)

// These views format only the detached public observation. They neither inspect
// the database nor infer remote health from a selected target or TCP counters.
func desktopFormatOverview(snapshot desktopSnapshot) string {
	text, observation := desktopDebugStart("运行概览", snapshot)
	if observation == nil {
		return text.String()
	}
	state := desktopReadinessPresentation(observation, true).Status
	switch {
	case observation.Admission.Pending:
		state = "等待入网授权"
	case observation.TunnelReady:
		state = "已连接"
	case state == "":
		state = "正在建立连接"
	}
	fmt.Fprintf(text, "\r\n[当前状态]\r\n%s\r\n", state)
	if !observation.IKE.Live && observation.IKE.AttemptActive {
		fmt.Fprintf(text, "当前阶段：%s\r\n", desktopDebugIKEPhase(observation.IKE.Phase))
		desktopDebugOptional(text, "尝试网关", observation.IKE.AttemptGateway)
	}
	if rejection := observation.IKE.LastRejection; rejection != nil && !observation.IKE.Live {
		label := "最近拒包（不等于连接失败）"
		if rejection.Historical {
			label = "先前拒包（历史）"
		}
		desktopDebugOptional(text, label, rejection.Message)
		fmt.Fprintf(text, "拒包记录时间：%s\r\n", desktopDebugTime(rejection.At))
	}
	if failure := observation.IKE.LastFailure; failure != nil && !observation.IKE.Live && !desktopDebugSameIKERecord(failure, observation.IKE.LastRejection) {
		label := "最近隧道失败"
		if failure.Historical {
			label = "先前隧道失败（历史）"
		}
		if desktopDebugIKERejected(failure.Event) {
			label = "最近拒包（不等于连接失败）"
			if failure.Historical {
				label = "先前拒包（历史）"
			}
		}
		desktopDebugOptional(text, label, failure.Message)
		fmt.Fprintf(text, "记录时间：%s\r\n", desktopDebugTime(failure.At))
	}
	if observation.Admission.Pending {
		desktopDebugOptional(text, "入网原因", observation.Admission.Reason)
		desktopDebugOptional(text, "说明", observation.Admission.ReasonDetail)
	}
	text.WriteString("\r\n[连接事实]\r\n")
	fmt.Fprintf(text, "业务可用：%s\r\nIKE 认证：%s\r\n数据隧道：%s\r\nBabel 邻居：%s\r\n", desktopDebugYes(observation.TunnelReady), desktopDebugYes(observation.IKE.Live), desktopDebugYes(observation.IKE.ChildLive), desktopDebugYes(observation.Babel.Live))
	if observation.Gateway.Selected != "" {
		desktopDebugOptional(text, "计划选择（不表示已连接）", observation.Gateway.Selected)
	}
	if observation.IKE.Live {
		desktopDebugOptional(text, "已认证网关", observation.IKE.Gateway)
	}
	desktopDebugAddresses(text, observation)
	return text.String()
}

func desktopFormatGateway(snapshot desktopSnapshot) string {
	text, observation := desktopDebugStart("网关与隧道", snapshot)
	if observation == nil {
		return text.String()
	}
	gateway := observation.Gateway
	if len(observation.Connections) > 0 {
		text.WriteString("\r\n[Mesh 连接 · 完全不中转]\r\n")
		for _, peer := range observation.Connections {
			fmt.Fprintf(text, "节点：%s · IKE %s · CHILD %s · Babel %s · 业务就绪 %s\r\n", peer.Peer, desktopDebugYes(peer.IKE.Live), desktopDebugYes(peer.IKE.ChildLive), desktopDebugYes(peer.BabelLive), desktopDebugYes(peer.TunnelReady))
			if peer.IKE.LastFailure != nil {
				desktopDebugIKERecord(text, peer.IKE.LastFailure, false)
			}
		}
		if observation.ConnectionsTruncated {
			text.WriteString("（连接列表已截断）\r\n")
		}
		desktopDebugOptional(text, "最近计划拒因", gateway.Rejected)
		return text.String()
	}
	if rejection := observation.IKE.LastRejection; rejection != nil {
		desktopDebugIKERecord(text, rejection, true)
	}
	if failure := observation.IKE.LastFailure; !desktopDebugSameIKERecord(failure, observation.IKE.LastRejection) {
		desktopDebugIKERecord(text, failure, failure != nil && desktopDebugIKERejected(failure.Event))
	}
	text.WriteString("\r\n[当前选择]\r\n")
	if gateway.Selected == "" {
		text.WriteString("当前没有通过重验的网关选择。\r\n")
	} else {
		desktopDebugOptional(text, "当前重验选择", gateway.Selected)
	}
	if observation.IKE.Live {
		desktopDebugOptional(text, "已认证网关", observation.IKE.Gateway)
	}
	desktopDebugOptional(text, "最近计划拒因", gateway.Rejected)
	if gateway.RevalidationRejected != gateway.Rejected {
		desktopDebugOptional(text, "当前重验拒因", gateway.RevalidationRejected)
	}
	if observation.IKE.Live {
		text.WriteString("\r\n[当前隧道与交换]\r\n")
	} else {
		text.WriteString("\r\n[当前尝试（不表示已认证）]\r\n")
	}
	if observation.IKE.AttemptActive {
		label := "尝试网关"
		if observation.IKE.Live {
			label = "当前隧道网关"
		}
		desktopDebugOptional(text, label, observation.IKE.AttemptGateway)
		desktopDebugOptional(text, "远端端点", observation.IKE.AttemptRemoteEndpoint)
		fmt.Fprintf(text, "目标代次：%d\r\n待响应交换发送轮数：%d（含首发，不是报文数）\r\n", observation.IKE.AttemptGeneration, observation.IKE.SendAttempts)
		if !observation.IKE.NextRetransmitAt.IsZero() {
			fmt.Fprintf(text, "下次重发时间：%s\r\n", desktopDebugTime(observation.IKE.NextRetransmitAt))
		}
	} else if !observation.IKE.Live {
		text.WriteString("当前没有进行中的隧道尝试。\r\n")
	}
	if !observation.IKE.RetryAt.IsZero() {
		fmt.Fprintf(text, "生命周期重试记录：%s\r\n", desktopDebugTime(observation.IKE.RetryAt))
	}
	desktopDebugOptional(text, "最近事件", observation.IKE.LastEvent)
	if !observation.IKE.LastEventAt.IsZero() {
		fmt.Fprintf(text, "事件时间：%s\r\n", desktopDebugTime(observation.IKE.LastEventAt))
	}
	text.WriteString("\r\n[认证与业务事实]\r\n")
	fmt.Fprintf(text, "IKE 生命周期：%s\r\nIKE 认证有效：%s\r\nCHILD 数据隧道有效：%s\r\n", desktopDebugIKEPhase(observation.IKE.Phase), desktopDebugYes(observation.IKE.Live), desktopDebugYes(observation.IKE.ChildLive))
	if observation.IKE.Live {
		fmt.Fprintf(text, "当前代次：%d\r\nIKE 有效截止：%s\r\n", observation.IKE.Generation, desktopDebugTime(observation.IKE.ExpiresAt))
	}
	if observation.IKE.ChildLive {
		fmt.Fprintf(text, "CHILD 有效截止：%s\r\n", desktopDebugTime(observation.IKE.ChildExpiresAt))
	}
	if observation.Babel.Local.IsValid() {
		fmt.Fprintf(text, "用户态链路本地 IPv6：%s\r\n", observation.Babel.Local)
	}
	fmt.Fprintf(text, "Babel 邻居有效：%s\r\n", desktopDebugYes(observation.Babel.Live))
	if observation.Babel.Live && observation.Babel.Neighbor.IsValid() {
		fmt.Fprintf(text, "当前邻居 IPv6：%s\r\n", observation.Babel.Neighbor)
	}
	fmt.Fprintf(text, "可用路由样本：%d", len(observation.Babel.Routes))
	if observation.RoutesTruncated {
		text.WriteString("（已截断）")
	}
	text.WriteString("\r\n")
	desktopDebugAddresses(text, observation)
	fmt.Fprintf(text, "\r\n[计划候选]\r\n计划采样：%s\r\n计划版本：%d\r\n", desktopDebugTime(gateway.EvaluatedAt), gateway.PlanRevision)
	text.WriteString("通过表示当时静态校验可尝试，不表示 IKE 已认证或服务可达。\r\n")
	for _, candidate := range gateway.Candidates {
		status := "可尝试"
		if candidate.Rejected != "" {
			status = "拒绝"
		} else if candidate.Zone == gateway.Selected {
			status = "当前选择"
		}
		fmt.Fprintf(text, "[%s] %s\r\n", status, desktopDebugCell(candidate.Zone, 128))
		if candidate.Rejected != "" {
			fmt.Fprintf(text, "  原因：%s\r\n", desktopDebugCell(candidate.Rejected, 256))
		}
	}
	if len(gateway.Candidates) == 0 {
		text.WriteString("尚无候选样本。\r\n")
	}
	if gateway.CandidatesTruncated {
		text.WriteString("候选样本已截断。\r\n")
	}
	return text.String()
}

func desktopDebugIKERecord(text *strings.Builder, failure *photonwindows.IKEFailureObservation, rejected bool) {
	if failure == nil {
		return
	}
	title := "[最近失败]"
	if failure.Historical {
		title = "[最近失败（历史记录）]"
	}
	if rejected {
		title = "[最近拒包记录]"
		if failure.Historical {
			title = "[最近拒包记录（历史）]"
		}
	}
	fmt.Fprintf(text, "\r\n%s\r\n", title)
	desktopDebugOptional(text, "原因", failure.Message)
	fmt.Fprintf(text, "记录时间：%s\r\n", desktopDebugTime(failure.At))
	desktopDebugOptional(text, "事件", failure.Event)
	desktopDebugOptional(text, "当时阶段", failure.Phase)
	desktopDebugOptional(text, "当时网关", failure.Gateway)
	desktopDebugOptional(text, "当时端点", failure.RemoteEndpoint)
	if rejected {
		text.WriteString("单个拒包不表示整条隧道失败；迟到或无关报文也可能被拒绝。\r\n")
	}
	if failure.Historical {
		if rejected {
			text.WriteString("这是先前拒包记录，不代表当前尝试或当前连接失败。\r\n")
		} else {
			text.WriteString("这是先前失败记录，不代表当前尝试或当前连接失败。\r\n")
		}
	}
}

func desktopDebugIKERejected(event string) bool {
	return event == "packet_rejected" || strings.HasSuffix(event, "_packet_rejected")
}

func desktopDebugSameIKERecord(left, right *photonwindows.IKEFailureObservation) bool {
	return left != nil && right != nil && left.Event == right.Event && left.Message == right.Message && left.At.Equal(right.At) && left.Phase == right.Phase && left.Gateway == right.Gateway && left.RemoteEndpoint == right.RemoteEndpoint && left.Generation == right.Generation
}

func desktopFormatPeer(snapshot desktopSnapshot, peerID string) string {
	text, observation := desktopDebugStart("Gossip 节点", snapshot)
	if observation == nil {
		return text.String()
	}
	peer, ok := observation.Find(peerID)
	if !ok {
		text.WriteString("\r\n请从当前节点列表选择一项；已移出样本的节点不保留旧详情。\r\n")
		if observation.PeersTruncated {
			text.WriteString("节点样本已截断，未显示不代表节点不存在。\r\n")
		}
		return text.String()
	}
	data, err := json.MarshalIndent(peer, "", "  ")
	if err != nil {
		fmt.Fprintf(text, "\r\n节点诊断不可用：%s\r\n", err)
	} else {
		fmt.Fprintf(text, "\r\n节点：%s\r\n", desktopDebugCell(peer.PeerID, 256))
		text.WriteString(strings.ReplaceAll(string(data), "\n", "\r\n"))
	}
	return text.String()
}

func desktopDebugStart(title string, snapshot desktopSnapshot) (*strings.Builder, *photonwindows.Observation) {
	text := new(strings.Builder)
	text.WriteString(title + "\r\n")
	if !desktopLiveSnapshot(snapshot) {
		text.WriteString("\r\n实时数据不可用，已清空上次连接数据。\r\n")
		desktopDebugOptional(text, "运行状态", snapshot.RuntimeState)
		desktopDebugOptional(text, "原因", snapshot.Error)
		return text, nil
	}
	fmt.Fprintf(text, "采样时间：%s（本地时间）\r\n数据版本：%d\r\n", desktopDebugTime(snapshot.Observation.ObservedAt), snapshot.Observation.Revision)
	return text, snapshot.Observation
}

func desktopDebugAddresses(text *strings.Builder, observation *photonwindows.Observation) {
	text.WriteString("\r\n[业务地址与接口]\r\n")
	fmt.Fprintf(text, "Wintun 已配置：%s\r\n", desktopDebugYes(observation.Wintun.Configured))
	if observation.Wintun.Configured {
		for _, address := range observation.Wintun.Addresses {
			if address.IsValid() {
				fmt.Fprintf(text, "实际业务 IP：%s\r\n", address)
			}
		}
		if observation.Wintun.Truncated {
			text.WriteString("接口地址样本已截断。\r\n")
		}
	}
	switch observation.Readiness.Stage {
	case photonwindows.ReadinessStageAddressAssignment:
		text.WriteString("地址条件：等待当前分流范围内可用的授权业务 IP\r\n")
	case photonwindows.ReadinessStageAddressAnnouncement:
		text.WriteString("地址条件：等待已授权地址的本机声明同步\r\n")
	}
	desktopDebugOptional(text, "地址条件说明", observation.Readiness.Reason)
}

func desktopDebugIKEPhase(phase string) string {
	switch phase {
	case "idle":
		return "空闲"
	case "init":
		return "建立 IKE 初始交换（init）"
	case "auth":
		return "等待 IKE 认证（auth）"
	case "established":
		return "交换已完成（仍以认证有效标志为准）"
	default:
		if phase == "" {
			return "尚无阶段记录"
		}
		return desktopDebugCell(phase, 64)
	}
}

func desktopDebugTime(value time.Time) string {
	if value.IsZero() {
		return "尚无时间记录"
	}
	return value.In(time.Local).Format("2006-01-02 15:04:05 -07:00")
}

func desktopDebugUnix(value int64) string {
	if value == 0 {
		return "尚无时间记录"
	}
	return desktopDebugTime(time.Unix(value, 0))
}

func desktopDebugYes(value bool) string {
	if value {
		return "是"
	}
	return "否"
}

func desktopDebugOptional(text *strings.Builder, label, value string) {
	if value != "" {
		fmt.Fprintf(text, "%s：%s\r\n", label, desktopDebugCell(value, 256))
	}
}

// Runtime errors and peer identities may contain control characters. Keep them
// in a single visual cell instead of allowing them to forge another section.
func desktopDebugCell(value string, limit int) string {
	var text strings.Builder
	count := 0
	for _, r := range value {
		if count == limit {
			text.WriteString("…")
			break
		}
		count++
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029' {
			fmt.Fprintf(&text, "\\u%04x", r)
		} else {
			text.WriteRune(r)
		}
	}
	return text.String()
}
