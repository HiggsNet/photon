//go:build !windows

package photonwindows

import (
	"context"
	"net/netip"
)

func watchNetworkChangesForTargets(ctx context.Context, _ func() []netip.Addr) (<-chan struct{}, func() error, error) {
	return watchNetworkChanges(ctx)
}

// The portable composition is exercised on Linux too; native network change
// delivery belongs to the Windows host, not the common GossipDriver.
func watchNetworkChanges(ctx context.Context) (<-chan struct{}, func() error, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	return nil, func() error { return nil }, nil
}
