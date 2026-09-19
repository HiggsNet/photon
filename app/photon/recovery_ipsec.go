package main

import (
	"context"
	"errors"
	"fmt"

	photonlinux "github.com/HiggsNet/photon/internal/photonlinux"
)

func recoveryCleanupIPsec(ctx context.Context, includeOrphans, direct bool) error {
	rt, err := NewAppContext()
	if err != nil {
		return err
	}
	rt.DisableControl = direct
	if response, ok, err := cleanupIPsecViaControl(rt, includeOrphans); err != nil {
		return err
	} else if ok {
		fmt.Printf("cleaned %d ipsec link(s), %d orphan connection(s) via daemon\n", response.CleanedLinks, response.CleanedOrphans)
		return nil
	}
	cleaned, orphans, err := recoveryCleanupIPsecDirect(ctx, rt, includeOrphans)
	if err != nil {
		return err
	}
	fmt.Printf("cleaned %d ipsec link(s), %d orphan connection(s) directly\n", cleaned, orphans)
	return nil
}

func cleanupIPsecViaControl(rt *AppContext, includeOrphans bool) (*controlResponse, bool, error) {
	if rt != nil && rt.DisableControl {
		return nil, false, nil
	}
	path := controlSocketPath(rt.Config)
	response, err := sendControlRequest(path, controlRequest{Method: "ipsec_cleanup", Orphans: includeOrphans})
	if err != nil && isControlSocketUnavailable(err) {
		return nil, true, fmt.Errorf("daemon control socket unavailable; use --direct for an explicit offline write: %w", err)
	}
	return response, true, err
}

func recoveryCleanupIPsecDirect(ctx context.Context, rt *AppContext, includeOrphans bool) (int, int, error) {
	if rt == nil {
		return 0, 0, errors.New("runtime is nil")
	}
	if !includeOrphans {
		return 0, 0, nil
	}
	if rt.Config == nil {
		return 0, 0, errors.New("config is nil")
	}
	platformDriver, err := photonlinux.NewIPsecCleanupDriver(rt.Config.IPsec)
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = platformDriver.Close() }()
	orphans, err := platformDriver.CleanupIPsecOrphans(ctx, nil)
	return 0, orphans, err
}
