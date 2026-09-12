package main

import (
	"context"
	"fmt"
	"net/netip"
	"os"

	"github.com/HiggsNet/photon/internal/inspect"
	inspecttext "github.com/HiggsNet/photon/internal/inspect/text"
	"github.com/HiggsNet/photon/internal/photonlinux/healthprobe"
	pingdebug "github.com/HiggsNet/photon/internal/ping"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/health"
)

// debugPing resolves the IPsec link targets for a peer zone and pings each one
// (current SA, plus old and new SA during a rotate) across IPv4/IPv6. It runs
// the pings directly in the CLI process via the health ICMP prober.
func debugPing(ctx context.Context, peerZone zone.ZonePath, opts pingdebug.Options) error {
	rt, err := NewAppContext()
	if err != nil {
		return err
	}
	controlTargets, online, err := readCanonicalViewViaControl[[]inspect.HealthTarget](rt, controlRequest{Method: "ping_targets"})
	if err != nil {
		return err
	}
	var targets []health.ProbeTarget
	if online {
		targets, err = healthTargetsFromInspect(controlTargets)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("daemon control socket unavailable; ping targets require current daemon runtime state")
	}
	if rt.Config != nil {
		opts.FallbackCount = rt.Config.Health.Burst
		opts.FallbackTimeout = rt.Config.Health.Timeout
	}
	resolved := pingdebug.ResolveOptions(opts)
	selected := pingdebug.SelectTargetsResolved(targets, string(peerZone), resolved)

	prober := healthprobe.NewICMProber(nil)
	outcomes := pingdebug.Run(ctx, prober, selected, resolved.ProbeConfig())
	view := pingdebug.BuildDebugView(string(peerZone), outcomes, pingdebug.DistinctPeerZones(targets), resolved.Count, resolved.Timeout)
	return inspecttext.WritePingDebug(os.Stdout, view)
}

func healthTargetsFromInspect(targets []inspect.HealthTarget) ([]health.ProbeTarget, error) {
	out := make([]health.ProbeTarget, 0, len(targets))
	for _, target := range targets {
		local, err := parseOptionalAddr(target.LocalTunnelAddr)
		if err != nil {
			return nil, fmt.Errorf("invalid daemon local tunnel address for %s: %w", target.InstanceID, err)
		}
		peer, err := parseOptionalAddr(target.PeerTunnelAddr)
		if err != nil {
			return nil, fmt.Errorf("invalid daemon peer tunnel address for %s: %w", target.InstanceID, err)
		}
		out = append(out, health.ProbeTarget{
			ProbeID: target.ProbeID, InstanceID: target.InstanceID, GroupID: target.GroupID,
			PeerZone: target.PeerZone, LocalZone: target.LocalZone, Overlay: target.Overlay,
			NetNS: target.NetNS, InterfaceName: target.InterfaceName, UnderlayFamily: target.UnderlayFamily,
			LocalTunnelAddr: local, PeerTunnelAddr: peer, Generation: target.Generation,
			ProbeRole: target.ProbeRole, Role: target.Role, State: target.State, Staged: target.Staged,
		})
	}
	return out, nil
}

func parseOptionalAddr(value string) (netip.Addr, error) {
	if value == "" || value == "invalid IP" {
		return netip.Addr{}, nil
	}
	return netip.ParseAddr(value)
}
