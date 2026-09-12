package main

import (
	"context"
	"errors"
	"fmt"

	photonlinux "github.com/HiggsNet/photon/internal/photonlinux"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
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
	platformDriver, err := newLinuxDriverForIPsecCleanup(rt.Config)
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = platformDriver.Close() }()
	orphans, err := platformDriver.CleanupIPsecOrphans(ctx, nil)
	return 0, orphans, err
}

// newLinuxDriverForIPsecCleanup assembles a one-shot platform driver for the
// explicit offline recovery path. Unlike the daemon driver factory, it must
// connect to StrongSwan even when no link groups are currently configured so
// that stale Photon-named connections can still be removed.
func newLinuxDriverForIPsecCleanup(config *appConfig) (*photonlinux.LinuxDriver, error) {
	if config == nil {
		return nil, errors.New("config is nil")
	}
	driver := config.IPsec.Driver
	if driver == "" {
		driver = ipsecDriverStrongSwan
	}
	switch driver {
	case ipsecDriverDryRun:
		dryRun := &ipsec.DryRunDriver{}
		return photonlinux.NewLinuxDriver(photonlinux.LinuxDriverOptions{IPsecDriver: dryRun, XFRMDriver: dryRun})
	case ipsecDriverStrongSwan:
		client, err := ipsec.NewGoviciClient(config.IPsec.VICISocket)
		if err != nil {
			return nil, fmt.Errorf("initialize strongswan vici client: %w", err)
		}
		return photonlinux.NewLinuxDriver(photonlinux.LinuxDriverOptions{
			IPsecDriver: &ipsec.StrongSwanDriver{VICI: client},
			XFRMDriver:  ipsec.NewSystemXFRMDriver(config.IPsec.DefaultNetNS),
			Close:       client.Close,
		})
	default:
		return nil, fmt.Errorf("unsupported ipsec driver %q", driver)
	}
}
