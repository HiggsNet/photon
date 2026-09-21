package main

import (
	"context"
	"errors"
	"fmt"

	photonlinux "github.com/HiggsNet/photon/internal/photonlinux"
)

func recoveryCleanupIPsec(ctx context.Context, includeOrphans, direct bool) error {
	config, err := loadAppConfig()
	if err != nil {
		return err
	}

	if response, ok, err := cleanupIPsecViaControl(config, includeOrphans, direct); err != nil {
		return err
	} else if ok {
		fmt.Printf("cleaned %d ipsec link(s), %d orphan connection(s) via daemon\n", response.CleanedLinks, response.CleanedOrphans)
		return nil
	}
	connections, err := recoveryCleanupIPsecDirect(ctx, config, includeOrphans)
	if err != nil {
		return err
	}
	fmt.Printf("cleaned %d Photon-named StrongSwan connection(s) directly; XFRM interfaces were not removed\n", connections)
	return nil
}

func cleanupIPsecViaControl(config *appConfig, includeOrphans bool, direct bool) (*controlResponse, bool, error) {
	if direct {
		return nil, false, nil
	}
	path := controlSocketPath(config)
	response, err := sendControlRequest(path, controlRequest{Method: "ipsec_cleanup", Orphans: includeOrphans})
	if err != nil && isControlSocketUnavailable(err) {
		return nil, true, fmt.Errorf("daemon control socket unavailable; use --direct --orphans to explicitly remove all Photon-named StrongSwan connections without deleting XFRM interfaces: %w", err)
	}
	return response, true, err
}

func recoveryCleanupIPsecDirect(ctx context.Context, config *appConfig, includeOrphans bool) (int, error) {
	if config == nil {
		return 0, errors.New("config is nil")
	}
	if !includeOrphans {
		return 0, errors.New("direct IPsec cleanup requires --orphans: offline recovery can only remove all Photon-named StrongSwan connections, not managed links or XFRM interfaces")
	}
	platformDriver, err := photonlinux.NewIPsecCleanupDriver(config.IPsec)
	if err != nil {
		return 0, err
	}
	defer func() { _ = platformDriver.Close() }()
	// Offline recovery has no observed link owners or connection keep set.
	// The explicit --orphans flag opts into removing every Photon-named connection.
	return platformDriver.CleanupIPsecOrphans(ctx, nil)
}
