package main

import (
	"context"
	"fmt"
	"os"

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
	targets, online, err := readCanonicalViewViaControl[[]health.ProbeTarget](rt, controlRequest{Method: "ping_targets"})
	if err != nil {
		return err
	}
	if !online {
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
