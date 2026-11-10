package main

import (
	"slices"
	"strings"

	"github.com/HiggsNet/photon/internal/gossipview"
	"github.com/HiggsNet/photon/internal/photonwindows"
)

// Dashboard rows use the current detached sample only. A completed Gossip
// exchange is a sync result, not an ongoing socket or a data-plane probe.
type desktopNodeRow struct {
	Peer, Gossip, Tunnel, Health string
}

func desktopDashboardNodes(snapshot desktopSnapshot) []desktopNodeRow {
	if !desktopLiveSnapshot(snapshot) {
		return nil
	}
	o := snapshot.Observation
	nodes := make(map[string]*desktopNodeRow)
	node := func(id string) *desktopNodeRow {
		if nodes[id] == nil {
			nodes[id] = &desktopNodeRow{Peer: id, Gossip: "— 未采样", Tunnel: "— 未连接", Health: "— 未检测"}
		}
		return nodes[id]
	}
	for _, id := range desktopGatewayNodes(snapshot) {
		node(id)
	}
	for _, peer := range o.Peers {
		node(peer.PeerID).Gossip = peer.SyncStatus + " · " + gossipview.FormatTime(peer.LastSyncUnix)
	}
	connections := o.Connections
	if len(connections) == 0 && o.IKE.Gateway != "" {
		connections = []photonwindows.ConnectionObservation{{Peer: o.IKE.Gateway, IKE: o.IKE, BabelLive: o.Babel.Live, TunnelReady: o.TunnelReady}}
	}
	if o.Admission.Pending {
		connections = nil
	}
	type linkFacts struct {
		attempting, child, failed, babel, ipv4, ipv6 bool
	}
	links := make(map[string]linkFacts)
	for _, c := range connections {
		facts := links[c.Peer]
		facts.attempting = facts.attempting || c.IKE.AttemptActive
		facts.failed = facts.failed || c.IKE.LastFailure != nil && !c.IKE.LastFailure.Historical
		if c.IKE.Live && c.IKE.ChildLive {
			facts.child = true
			facts.babel = facts.babel || c.BabelLive
			// Route samples are already authorized for the local addresses. Require
			// this peer's ready state and match the peer, never borrow another path.
			if c.TunnelReady {
				facts.ipv4 = facts.ipv4 || c.IPv4RouteReady
				facts.ipv6 = facts.ipv6 || c.IPv6RouteReady
				if c.OuterFamily == "" {
					for _, route := range o.Babel.Routes {
						if route.Peer != c.Peer && !(len(o.Connections) == 0 && route.Peer == "") {
							continue
						}
						if route.Prefix.IsValid() {
							facts.ipv4 = facts.ipv4 || route.Prefix.Addr().Is4()
							facts.ipv6 = facts.ipv6 || route.Prefix.Addr().Is6()
						}
					}
				}
			}
		}
		links[c.Peer] = facts
	}
	for peer, facts := range links {
		r := node(peer)
		switch {
		case facts.ipv4 && facts.ipv6:
			r.Tunnel = "✓ IPv4  ✓ IPv6"
		case facts.ipv4:
			r.Tunnel = "✓ IPv4"
		case facts.ipv6:
			r.Tunnel = "✓ IPv6"
		case facts.child:
			r.Tunnel = "… 待就绪"
		case facts.failed:
			r.Tunnel = "! 连接异常"
		case facts.attempting:
			r.Tunnel = "… 连接中"
		}
		switch {
		case facts.babel:
			r.Health = "✓ Babel 在线"
		case facts.child:
			r.Health = "… 等待邻居"
		}
	}
	rows := make([]desktopNodeRow, 0, len(nodes))
	for id, r := range nodes {
		if id != "" {
			rows = append(rows, *r)
		}
	}
	slices.SortFunc(rows, func(a, b desktopNodeRow) int { return strings.Compare(b.Peer, a.Peer) })
	return rows
}

func desktopDashboardStatus(snapshot desktopSnapshot, admission desktopAdmissionView) (string, string) {
	switch {
	case snapshot.Error != "":
		return "状态暂不可用", "请到日志与诊断查看原因"
	case snapshot.RuntimeState == "starting":
		return "正在连接", "正在启动 Photon"
	case snapshot.RuntimeState == "stopping":
		return "正在断开", "正在停止连接"
	case snapshot.RuntimeState == "failed":
		return "连接失败", "请到日志与诊断查看原因"
	case !desktopLiveSnapshot(snapshot):
		return "未连接", "开启右上角开关，连接 Photon 网络"
	case admission.Pending:
		return "等待入网授权", strings.TrimPrefix(admission.Label, "入网：待授权 · ")
	case admission.Adopted:
		if snapshot.Observation.TunnelReady {
			return "已入网", "网络已连接"
		}
		detail := desktopReadinessPresentation(snapshot.Observation, true).Status
		if detail == "" {
			detail = "正在建立节点连接"
		}
		return "已入网", strings.TrimPrefix(detail, "已入网，")
	default:
		return "正在连接", "正在同步入网状态"
	}
}
