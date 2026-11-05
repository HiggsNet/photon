package main

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/HiggsNet/photon/internal/photonwindows"
)

type routeKey struct{ destination, source netip.Prefix }

func (key routeKey) label() string {
	if key.source.IsValid() {
		return key.destination.String() + "  来源 " + key.source.String()
	}
	return key.destination.String()
}

func desktopRouteGroups(routes []photonwindows.RouteObservation) ([]routeKey, map[routeKey][]photonwindows.RouteObservation) {
	groups := make(map[routeKey][]photonwindows.RouteObservation)
	var keys []routeKey
	for _, route := range routes {
		key := routeKey{route.Prefix, route.SourcePrefix}
		if _, exists := groups[key]; !exists {
			keys = append(keys, key)
		}
		groups[key] = append(groups[key], route)
	}
	slices.SortFunc(keys, func(a, b routeKey) int {
		if order := a.destination.Compare(b.destination); order != 0 {
			return order
		}
		return a.source.Compare(b.source)
	})
	return keys, groups
}

func desktopFormatRoutes(routes []photonwindows.RouteObservation, truncated bool) string {
	keys, groups := desktopRouteGroups(routes)
	var text strings.Builder
	fmt.Fprintf(&text, "Babel 路由样本 · %d 组 / %d 条路径\r\n", len(keys), len(routes))
	if truncated {
		text.WriteString("样本已截断，未显示的路径可能仍然存在。\r\n")
	}
	for _, key := range keys {
		fmt.Fprintf(&text, "\r\n%s", key.destination)
		if key.source.IsValid() {
			fmt.Fprintf(&text, "  来源 %s", key.source)
		}
		text.WriteString("\r\n")
		paths := groups[key]
		slices.SortFunc(paths, func(a, b photonwindows.RouteObservation) int {
			if order := strings.Compare(a.Peer, b.Peer); order != 0 {
				return order
			}
			if order := strings.Compare(a.Origin, b.Origin); order != 0 {
				return order
			}
			return int(a.Metric) - int(b.Metric)
		})
		for _, path := range paths {
			peer := path.Peer
			if peer == "" {
				peer = "当前网关"
			}
			fmt.Fprintf(&text, "  经 %s  metric %d", desktopDebugCell(peer, 128), path.Metric)
			if path.Origin != "" {
				fmt.Fprintf(&text, "  起源 %s", desktopDebugCell(path.Origin, 128))
			}
			text.WriteString("\r\n")
		}
	}
	return text.String()
}

func desktopFormatRouteSelection(snapshot desktopSnapshot, key routeKey) string {
	if !desktopLiveSnapshot(snapshot) {
		return "尚无实时 Babel 路由。"
	}
	o := snapshot.Observation
	routes := o.Babel.Routes
	if key.destination.IsValid() {
		routes = slices.DeleteFunc(slices.Clone(routes), func(route photonwindows.RouteObservation) bool {
			return route.Prefix != key.destination || route.SourcePrefix != key.source
		})
		if len(routes) == 0 {
			return key.label() + "\r\n当前样本没有该前缀的路径。"
		}
	}
	return desktopFormatRoutes(routes, o.RoutesTruncated)
}

func desktopFormatNodeAddresses(snapshot desktopSnapshot) string {
	if !desktopLiveSnapshot(snapshot) || len(snapshot.Observation.NodeAddresses) == 0 {
		return "尚无已验证的节点地址分配样本。"
	}
	o := snapshot.Observation
	addresses := slices.Clone(o.NodeAddresses)
	slices.SortFunc(addresses, func(a, b photonwindows.NodeAddressObservation) int {
		if order := strings.Compare(a.Node, b.Node); order != 0 {
			return order
		}
		return a.Prefix.Compare(b.Prefix)
	})
	var text strings.Builder
	fmt.Fprintf(&text, "已验证的 IPAM 分配与路由通告 · %d 条\r\n", len(addresses))
	text.WriteString("通告状态来自签名路由记录，实际路径请查看 Babel 路由。\r\n")
	if o.NodeAddressesTruncated {
		text.WriteString("地址样本已截断。\r\n")
	}
	node := ""
	for _, address := range addresses {
		if node != address.Node {
			node = address.Node
			fmt.Fprintf(&text, "\r\n%s\r\n", desktopDebugCell(node, 128))
		}
		state := "已分配"
		if address.Announced {
			state = "已通告"
		}
		fmt.Fprintf(&text, "  %s  ·  %s\r\n", address.Prefix, state)
	}
	return text.String()
}
