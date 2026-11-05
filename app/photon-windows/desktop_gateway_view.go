package main

import (
	"fmt"
	"slices"

	"github.com/HiggsNet/photon/internal/photonwindows"
)

// Join only identities present in the current public sample. A retained error
// may name a previous gateway; it must not become the active gateway's error.
func desktopGatewayNodes(snapshot desktopSnapshot) []string {
	if !desktopLiveSnapshot(snapshot) {
		return nil
	}
	o := snapshot.Observation
	ids := []string{o.Gateway.Selected, o.IKE.Gateway, o.IKE.AttemptGateway}
	for _, connection := range o.Connections {
		ids = append(ids, connection.Peer)
	}
	for _, candidate := range o.Gateway.Candidates {
		ids = append(ids, candidate.Zone)
	}
	for _, record := range []*photonwindows.IKEFailureObservation{o.IKE.LastFailure, o.IKE.LastRejection} {
		if record != nil {
			ids = append(ids, record.Gateway)
		}
	}
	slices.Sort(ids)
	return slices.DeleteFunc(slices.Compact(ids), func(id string) bool { return id == "" })
}

func desktopGatewayConnection(o *photonwindows.Observation, id string) (photonwindows.ConnectionObservation, bool) {
	for _, connection := range o.Connections {
		if connection.Peer == id {
			return connection, true
		}
	}
	return photonwindows.ConnectionObservation{IKE: o.IKE, BabelLive: o.Babel.Live, TunnelReady: o.TunnelReady}, false
}

func desktopGatewayState(o *photonwindows.Observation, id string) string {
	connection, meshPeer := desktopGatewayConnection(o, id)
	ike := connection.IKE
	switch {
	case ike.Live && ike.Gateway == id && ike.ChildLive && connection.TunnelReady:
		return "业务就绪"
	case ike.Live && ike.Gateway == id && ike.ChildLive:
		return "隧道已建立"
	case ike.Live && ike.Gateway == id:
		return "已认证"
	case ike.AttemptActive && ike.AttemptGateway == id:
		return "连接中"
	}
	if f := ike.LastFailure; f != nil && f.Gateway == id && !f.Historical && !desktopDebugIKERejected(f.Event) {
		return "连接失败"
	}
	if meshPeer {
		return "未建立隧道"
	}
	if o.Gateway.Selected == id {
		return "待连接"
	}
	for _, candidate := range o.Gateway.Candidates {
		if candidate.Zone == id {
			if candidate.Rejected != "" {
				return "不可尝试"
			}
			return "候选"
		}
	}
	return "历史记录"
}

func desktopFormatGatewayNode(snapshot desktopSnapshot, id string) string {
	if id == "" {
		return desktopFormatGateway(snapshot)
	}
	text, o := desktopDebugStart("节点连接详情", snapshot)
	if o == nil {
		return text.String()
	}
	if !slices.Contains(desktopGatewayNodes(snapshot), id) {
		text.WriteString("\r\n请选择当前列表中的节点；已移出样本的节点不保留旧详情。\r\n")
		return text.String()
	}
	// Lead with the selected node's conclusion. Sample metadata belongs after
	// the connection facts, rather than pushing them below the first viewport.
	text.Reset()
	fmt.Fprintf(text, "\r\n节点：%s\r\n状态：%s\r\n", desktopDebugCell(id, 256), desktopGatewayState(o, id))
	for _, candidate := range o.Gateway.Candidates {
		if candidate.Zone == id && candidate.Rejected != "" {
			desktopDebugOptional(text, "计划拒因", candidate.Rejected)
			break
		}
	}
	connection, meshPeer := desktopGatewayConnection(o, id)
	ike := connection.IKE
	live := ike.Live && ike.Gateway == id
	attempt := ike.AttemptActive && ike.AttemptGateway == id
	text.WriteString("\r\n[连接状态]\r\n")
	fmt.Fprintf(text, "IKE 认证有效：%s\r\nCHILD 数据隧道有效：%s\r\n", desktopDebugYes(live), desktopDebugYes(live && ike.ChildLive))
	if live {
		fmt.Fprintf(text, "当前代次：%d\r\nIKE 有效截止：%s\r\n", ike.Generation, desktopDebugTime(ike.ExpiresAt))
		if ike.ChildLive {
			fmt.Fprintf(text, "CHILD 有效截止：%s\r\n", desktopDebugTime(ike.ChildExpiresAt))
		}
		fmt.Fprintf(text, "Babel 邻居有效：%s\r\n业务可用：%s\r\n", desktopDebugYes(connection.BabelLive), desktopDebugYes(connection.TunnelReady))
		if (!meshPeer || o.IKE.Gateway == id) && o.Babel.Local.IsValid() {
			fmt.Fprintf(text, "用户态链路本地 IPv6：%s\r\n", o.Babel.Local)
		}
		if (!meshPeer || o.IKE.Gateway == id) && o.Babel.Live && o.Babel.Neighbor.IsValid() {
			fmt.Fprintf(text, "当前邻居 IPv6：%s\r\n", o.Babel.Neighbor)
		}
		routes := len(o.Babel.Routes)
		if meshPeer {
			routes = 0
			for _, route := range o.Babel.Routes {
				if route.Peer == id {
					routes++
				}
			}
		}
		fmt.Fprintf(text, "可用路由样本：%d\r\n", routes)
		if o.RoutesTruncated {
			text.WriteString("路由样本已截断。\r\n")
		}
		desktopDebugAddresses(text, o)
	} else if !attempt {
		text.WriteString("此节点当前没有已认证隧道或进行中的连接尝试。\r\n")
	}
	// AttemptGateway also identifies retained lifecycle diagnostics after an
	// attempt ends. Only active attempts expose their endpoint as current.
	if attempt {
		text.WriteString("\r\n[当前交换]\r\n")
		desktopDebugOptional(text, "阶段", desktopDebugIKEPhase(ike.Phase))
		desktopDebugOptional(text, "远端端点", ike.AttemptRemoteEndpoint)
		fmt.Fprintf(text, "目标代次：%d\r\n交换发送轮数：%d（含首发）\r\n", ike.AttemptGeneration, ike.SendAttempts)
		if !ike.NextRetransmitAt.IsZero() {
			fmt.Fprintf(text, "下次重发时间：%s\r\n", desktopDebugTime(ike.NextRetransmitAt))
		}
	}
	if ike.AttemptGateway == id {
		desktopDebugOptional(text, "最近事件", ike.LastEvent)
		if !ike.LastEventAt.IsZero() {
			fmt.Fprintf(text, "事件时间：%s\r\n", desktopDebugTime(ike.LastEventAt))
		}
		if !ike.RetryAt.IsZero() {
			fmt.Fprintf(text, "生命周期重试记录：%s\r\n", desktopDebugTime(ike.RetryAt))
		}
	}
	if rejection := ike.LastRejection; rejection != nil && rejection.Gateway == id {
		desktopDebugIKERecord(text, rejection, true)
	}
	if failure := ike.LastFailure; failure != nil && failure.Gateway == id && !desktopDebugSameIKERecord(failure, ike.LastRejection) {
		desktopDebugIKERecord(text, failure, desktopDebugIKERejected(failure.Event))
	}
	text.WriteString("\r\n[候选与选择]\r\n")
	fmt.Fprintf(text, "当前计划选择：%s\r\n", desktopDebugYes(o.Gateway.Selected == id))
	for _, candidate := range o.Gateway.Candidates {
		if candidate.Zone == id {
			if candidate.Rejected == "" {
				text.WriteString("计划校验：可尝试（不表示已连接）\r\n")
			}
			break
		}
	}
	fmt.Fprintf(text, "计划采样：%s\r\n计划版本：%d\r\n", desktopDebugTime(o.Gateway.EvaluatedAt), o.Gateway.PlanRevision)
	if o.Gateway.CandidatesTruncated {
		text.WriteString("候选样本已截断；未显示不表示节点不存在。\r\n")
	}
	fmt.Fprintf(text, "\r\n[诊断样本]\r\n采样时间：%s\r\n数据版本：%d\r\n", desktopDebugTime(o.ObservedAt), o.Revision)
	return text.String()
}
