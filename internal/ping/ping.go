package ping

import (
	"context"
	"errors"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	"github.com/HiggsNet/photon/pkg/health"
)

const (
	DefaultCount   = 4
	DefaultTimeout = time.Second
)

type Options struct {
	Count           int
	Timeout         time.Duration
	FallbackCount   int
	FallbackTimeout time.Duration
	Family          string
	Role            string
}

type ResolvedOptions struct {
	Count   int
	Timeout time.Duration
	Family  string
	Role    string
}

type Outcome struct {
	Target health.ProbeTarget
	Family string
	Result health.ProbeResult
}

func ResolveOptions(opts Options) ResolvedOptions {
	count := opts.Count
	if count <= 0 {
		count = opts.FallbackCount
	}
	if count <= 0 {
		count = DefaultCount
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = opts.FallbackTimeout
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return ResolvedOptions{
		Count:   count,
		Timeout: timeout,
		Family:  opts.Family,
		Role:    opts.Role,
	}
}

func (opts ResolvedOptions) ProbeConfig() health.ProbeConfig {
	return health.ProbeConfig{Timeout: opts.Timeout, Burst: opts.Count}
}

func SelectTargetsResolved(targets []health.ProbeTarget, peerZone string, opts ResolvedOptions) []health.ProbeTarget {
	out := make([]health.ProbeTarget, 0, len(targets))
	for _, target := range targets {
		if !target.PeerTunnelAddr.IsValid() {
			continue
		}
		if string(target.PeerZone) != peerZone {
			continue
		}
		if opts.Family != "" && FamilyForTarget(target) != opts.Family {
			continue
		}
		if opts.Role != "" && Role(target) != opts.Role {
			continue
		}
		out = append(out, target)
	}
	return out
}

func Run(ctx context.Context, prober health.Prober, targets []health.ProbeTarget, cfg health.ProbeConfig) []Outcome {
	out := make([]Outcome, len(targets))
	var wg sync.WaitGroup
	wg.Add(len(targets))
	for i, target := range targets {
		go func() {
			defer wg.Done()
			result := health.ProbeResult{InstanceID: target.InstanceID, Err: errors.New("no prober configured")}
			if prober != nil {
				result = prober.Probe(ctx, target, cfg)
			}
			out[i] = Outcome{
				Target: target,
				Family: FamilyForTarget(target),
				Result: result,
			}
		}()
	}
	wg.Wait()
	return out
}

func BuildDebugView(peerZone string, outcomes []Outcome, availableZones []string, count int, timeout time.Duration) inspect.PingDebugView {
	view := inspect.PingDebugView{
		Zone:           peerZone,
		AvailableZones: append([]string(nil), availableZones...),
		Count:          count,
		Timeout:        timeout,
	}
	for _, outcome := range outcomes {
		view.Targets = append(view.Targets, inspect.PingTargetView{
			InstanceID:   outcome.Target.InstanceID,
			ProbeID:      outcome.Target.ProbeID,
			Role:         Role(outcome.Target),
			Family:       outcome.Family,
			TunnelFamily: FamilyFor(outcome.Target.PeerTunnelAddr),
			Interface:    outcome.Target.InterfaceName,
			NetNS:        outcome.Target.NetNS,
			LocalTunnel:  outcome.Target.LocalTunnelAddr.String(),
			PeerTunnel:   outcome.Target.PeerTunnelAddr.String(),
			Success:      outcome.Result.Success,
			RTT:          outcome.Result.RTT,
			Failure:      inspect.BuildFailure(inspect.FailureCodeHealthProbe, outcome.Result.Err),
		})
	}
	return inspect.BuildPingDebugView(view)
}

func DistinctPeerZones(targets []health.ProbeTarget) []string {
	seen := map[string]struct{}{}
	for _, target := range targets {
		if target.PeerZone != "" {
			seen[target.PeerZone] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for peerZone := range seen {
		out = append(out, peerZone)
	}
	sort.Strings(out)
	return out
}

func FamilyFor(addr netip.Addr) string {
	if addr.Is6() {
		return "ipv6"
	}
	return "ipv4"
}

// FamilyForTarget returns the underlay path family when the planner retained
// it. Older snapshots without that field fall back to the tunnel address
// family so debug ping remains usable across upgrades.
func FamilyForTarget(target health.ProbeTarget) string {
	if target.UnderlayFamily == "ipv4" || target.UnderlayFamily == "ipv6" {
		return target.UnderlayFamily
	}
	return FamilyFor(target.PeerTunnelAddr)
}

func Role(target health.ProbeTarget) string {
	if target.ProbeRole != "" {
		return target.ProbeRole
	}
	return "active"
}
