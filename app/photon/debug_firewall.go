package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"

	"github.com/HiggsNet/photon/internal/inspect"
	inspecttext "github.com/HiggsNet/photon/internal/inspect/text"
	"github.com/HiggsNet/photon/pkg/firewall"
	"github.com/urfave/cli/v3"
)

func debugFirewall(_ context.Context, cmd *cli.Command) error {
	if cmd.Bool("host") && cmd.String("netns") != "" {
		return fmt.Errorf("--host and --netns cannot be used together")
	}
	rt, err := NewAppContext()
	if err != nil {
		return err
	}
	return debugFirewallWithRuntimeFiltered(rt, os.Stdout, cmd.String("netns"), cmd.Bool("host"), cmd.Bool("json"))
}

func debugFirewallWithRuntimeFiltered(rt *AppContext, w io.Writer, netns string, hostOnly, jsonOutput bool) error {
	view, err := firewallViewWithRuntime(rt, netns, hostOnly)
	if err != nil {
		return err
	}
	if jsonOutput {
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		return encoder.Encode(view)
	}
	return inspecttext.WriteDebugFirewall(w, view)
}

func showFirewall(filter string, verbose bool) error {
	rt, err := NewAppContext()
	if err != nil {
		return err
	}
	view, err := firewallViewWithRuntime(rt, "", false)
	if err != nil {
		return err
	}
	return inspecttext.WriteFirewall(os.Stdout, view, filter, verbose)
}

func firewallViewWithRuntime(rt *AppContext, netns string, hostOnly bool) (inspect.FirewallDebugView, error) {
	view, ok, err := readCanonicalViewViaControl[inspect.FirewallDebugView](rt, controlRequest{Method: "firewall_view", NetNS: netns, Host: hostOnly})
	if err != nil {
		return inspect.FirewallDebugView{}, err
	}
	if ok {
		return view, nil
	}
	return inspect.FirewallDebugView{}, fmt.Errorf("daemon control socket unavailable; firewall runtime state requires a running daemon")
}

func filterFirewallDebugInstances(instances []FirewallInstanceConfig, netns string, hostOnly bool) []FirewallInstanceConfig {
	if netns == "" && !hostOnly {
		return instances
	}
	filtered := make([]FirewallInstanceConfig, 0, len(instances))
	for _, inst := range instances {
		if hostOnly && !inst.IsHost {
			continue
		}
		if netns != "" && inst.NetNS != netns && inst.ID != netns {
			continue
		}
		filtered = append(filtered, inst)
	}
	return filtered
}

func buildFirewallDebugView(config *appConfig, instances []FirewallInstanceConfig, snapshot *firewall.FirewallObservation) inspect.FirewallDebugView {
	input := inspect.FirewallDebugInput{
		Instances: make([]inspect.FirewallInstanceInput, 0, len(instances)),
		Reconcile: snapshot,
	}
	for _, inst := range instances {
		policy := netnsForwardingPolicy(config, inst.NetNS)
		scope := inst.NetNS
		if inst.IsHost {
			scope = "host"
		}
		instInput := inspect.FirewallInstanceInput{
			ID:            inst.ID,
			Scope:         scope,
			Enabled:       inst.Enabled,
			Mode:          inst.Mode,
			Backend:       inst.Backend,
			DefaultPolicy: inst.DefaultPolicy,
			OwnerPrefix:   inst.OwnerPrefix,
			Transit:       policy.Transit,
			AllowPrefixes: len(policy.AllowPrefixes),
			DenyPrefixes:  len(policy.DenyPrefixes),
			AllowFilters:  firewallPrefixStrings(policy.AllowPrefixes),
			DenyFilters:   firewallPrefixStrings(policy.DenyPrefixes),
			AllowPeers:    append([]string(nil), policy.AllowPeers...),
			DenyPeers:     append([]string(nil), policy.DenyPeers...),
			MetricHint:    policy.MetricHint,
			IsHost:        inst.IsHost,
			HostIKE:       inst.HostPorts.IKE,
			HostNATT:      inst.HostPorts.NATT,
			RedirectGrace: inst.RedirectGrace.Enabled,
			InlineHooks:   firewallInlineHookViews(inst.NativeHooks),
		}
		for _, svc := range inst.LocalServices {
			instInput.LocalServices = append(instInput.LocalServices, inspect.FirewallLocalServiceView{
				Proto: svc.Proto,
				Port:  svc.Port,
			})
		}
		input.Instances = append(input.Instances, instInput)
	}
	return inspect.BuildFirewallDebug(input)
}

func firewallPrefixStrings(prefixes []netip.Prefix) []string {
	out := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		out = append(out, prefix.String())
	}
	return out
}

func firewallInlineHookViews(hooks firewall.NativeHooks) []inspect.FirewallInlineHookView {
	points := []firewall.HookPoint{
		firewall.HookPreInput,
		firewall.HookPostInput,
		firewall.HookPreForward,
		firewall.HookPostForward,
		firewall.HookPreOutput,
		firewall.HookPostOutput,
		firewall.HookHostPrePrerouting,
		firewall.HookHostPostPrerouting,
		firewall.HookHostPreInput,
		firewall.HookHostPostInput,
	}
	var out []inspect.FirewallInlineHookView
	appendRules := func(backend, family string, rules firewall.InlineHookRules) {
		for _, point := range points {
			for _, expression := range rules.Rules(point) {
				out = append(out, inspect.FirewallInlineHookView{
					Backend: backend, Family: family, Point: string(point), Expression: expression,
				})
			}
		}
	}
	appendRules(firewall.BackendNFT, "", hooks.NFT)
	appendRules(firewall.BackendIptables, "ipv4", hooks.IPTables.IPv4)
	appendRules(firewall.BackendIptables, "ipv6", hooks.IPTables.IPv6)
	return out
}
