package main

import (
	"strings"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	"github.com/HiggsNet/photon/pkg/core/share"
)

// Requests contain public admission material. Keep the complete bounded value;
// truncation would produce a different, unusable request for the administrator.
const desktopJoinRequestLimit = 16 << 10

type desktopAdmissionView struct {
	Pending, Adopted        bool
	Label, Request, Tooltip string
}

func desktopAdmissionPresentation(diagnosis gossip.AdmissionDiagnosis, available bool) desktopAdmissionView {
	if !available {
		return desktopAdmissionView{Label: "入网：准备有效配置后安装并启动服务；首次启动会自动生成本机身份。"}
	}
	if !diagnosis.Pending {
		if diagnosis.Reason == gossip.AdmissionReasonAdopted {
			return desktopAdmissionView{Adopted: true, Label: "入网：已入网。", Tooltip: "Photon · 已入网，正在连接"}
		}
		return desktopAdmissionView{Label: "入网：当前服务未提供入网状态。"}
	}
	reasons := map[string]string{
		gossip.AdmissionReasonMissingZoneKey:         "本机身份尚不可用，请检查服务诊断后重试。",
		gossip.AdmissionReasonMissingParentZone:      "正在同步上级域信息，请检查引导节点连接。",
		gossip.AdmissionReasonMissingDelegation:      "等待上级管理员授权；请复制入网请求并提交给管理员。",
		gossip.AdmissionReasonDelegationKeyMismatch:  "已有授权与本机公钥不匹配，请将本次请求交给上级管理员核对。",
		gossip.AdmissionReasonVerifyDelegationFailed: "上级授权校验失败，请管理员检查授权签名或有效期。",
		gossip.AdmissionReasonNoBootstrapSync:        "尚未完成引导同步，请检查引导节点配置与连接。",
		gossip.AdmissionReasonWaitingForAdoption:     "授权已收到，正在同步并完成入网，无需重启服务。",
	}
	reason := reasons[diagnosis.Reason]
	if reason == "" {
		reason = "正在等待入网授权，请检查引导连接并联系上级管理员。"
	}
	view := desktopAdmissionView{Pending: true, Label: "入网：待授权 · " + reason, Tooltip: "Photon · 待授权"}
	request := diagnosis.JoinRequestB64
	if request != "" && len(request) <= desktopJoinRequestLimit && !strings.ContainsRune(request, '\x00') {
		var decoded gossip.JoinRequest
		if err := share.DecodeBase64JSON(request, &decoded); err == nil && gossip.ValidateJoinRequest(&decoded) == nil && decoded.Zone == diagnosis.ManagedZone {
			view.Request = request
		}
	}
	if request != "" && view.Request == "" {
		view.Label += " 当前入网请求不可用，请等待状态刷新。"
	}
	return view
}
