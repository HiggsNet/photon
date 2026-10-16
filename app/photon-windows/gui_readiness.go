package main

import (
	"fmt"
	"strings"

	"github.com/HiggsNet/photon/internal/photonwindows"
	"github.com/HiggsNet/photon/pkg/core/gossip"
)

type desktopReadinessView struct {
	Status, Tooltip, AddressSummary, LinkSummary, Detail string
}

// Waiting reasons come from the daemon's current verified view. Device absence
// alone cannot distinguish missing IP authority from SA, platform or DAD work.
// Wintun addresses remain actual device observations, never allocation intent.
func desktopReadinessPresentation(observation *photonwindows.Observation, available bool) desktopReadinessView {
	if !available || observation == nil || !observation.Running || observation.Admission.Pending {
		return desktopReadinessView{}
	}
	var out desktopReadinessView
	var addresses []string
	if observation.Wintun.Configured {
		for _, address := range observation.Wintun.Addresses {
			if address.IsValid() {
				addresses = append(addresses, address.String())
			}
		}
	}
	if len(addresses) == 0 {
		out.AddressSummary = "接口业务 IP：尚未配置"
		out.Detail = "实际已配置业务 IP：暂无；接口就绪后会在此显示地址。"
	} else {
		out.AddressSummary = "接口业务 IP：" + addresses[0]
		if len(addresses) > 1 {
			out.AddressSummary += fmt.Sprintf("（共 %d 个）", len(addresses))
		}
		out.Detail = "实际已配置业务 IP：" + strings.Join(addresses, "、") + "。"
		if observation.Wintun.Truncated {
			out.Detail += "接口样本已截断。"
		}
	}
	out.LinkSummary = "隧道链路 IPv6：尚未就绪"
	if local := observation.Babel.Local; local.IsValid() {
		out.LinkSummary = "隧道链路 IPv6：" + local.String()
		out.Detail += "\r\n隧道链路 IPv6（用户态）：本地 " + local.String() + "。"
	}
	if observation.Babel.Live && observation.Babel.Neighbor.IsValid() {
		out.Detail += "\r\n实时对端链路 IPv6：" + observation.Babel.Neighbor.String() + "。"
	}
	if observation.TunnelReady {
		return out
	}
	if observation.Admission.Reason != gossip.AdmissionReasonAdopted {
		return out
	}
	switch observation.Readiness.Stage {
	case photonwindows.ReadinessStageAddressAssignment:
		out.Status = "已入网，等待业务IP分配"
		out.Tooltip = "Photon · 等待业务 IP 分配"
		out.Detail = "尚无当前配置可用的有效业务 IP 授权分配。请由管理员分配有效业务 IP 并同步；收到后会自动继续连接，无需重新连接。隧道链路 IPv6 用于控制面，与业务 IP 分配分别显示。\r\n" + out.Detail
	case photonwindows.ReadinessStageAddressAnnouncement:
		out.Status = "已入网，等待地址同步"
		out.Tooltip = "Photon · 等待本机地址同步"
		out.Detail = "已有当前配置可用的有效业务 IP 授权分配，正在等待本机地址声明/同步生效；就绪后会自动继续连接，无需重新连接。\r\n" + out.Detail
	}
	if observation.Readiness.Reason != "" {
		out.Detail += "\r\n当前就绪诊断：" + observation.Readiness.Reason
	}
	return out
}
