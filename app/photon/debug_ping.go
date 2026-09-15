package main

import (
	"context"
	"fmt"
	"os"

	"github.com/HiggsNet/photon/internal/inspect"
	inspecttext "github.com/HiggsNet/photon/internal/inspect/text"
	pingdebug "github.com/HiggsNet/photon/internal/ping"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

// debugPing resolves the IPsec link targets for a peer zone and pings each one
// (current SA, plus old and new SA during a rotate) across IPv4/IPv6. Target
// selection and probing run in the daemon that owns the Linux runtime.
func debugPing(ctx context.Context, peerZone zone.ZonePath, opts pingdebug.Options) error {
	rt, err := NewAppContext()
	if err != nil {
		return err
	}
	view, online, err := readCanonicalViewViaControlContext[inspect.PingDebugView](ctx, rt, controlRequest{
		Method: "ping_view",
		Zone:   string(peerZone),
		Ping:   &opts,
	})
	if err != nil {
		return err
	}
	if !online {
		return fmt.Errorf("daemon control socket unavailable; ping targets require current daemon runtime state")
	}
	return inspecttext.WritePingDebug(os.Stdout, view)
}
