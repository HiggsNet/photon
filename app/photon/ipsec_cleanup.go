package main

import (
	"context"
	"errors"
	"fmt"
	"time"

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
	boltStore, startup, err := openLinuxDaemonState(rt)
	if err != nil {
		return 0, 0, err
	}
	defer boltStore.Close()
	defer startup.Common.Close()
	view := startup.Common.ReadView()
	runtimeCandidate := photonlinux.CloneRuntimeState(startup.Runtime)
	now := rt.Now()
	if len(runtimeCandidate.LinkInstances) == 0 && !includeOrphans {
		runtimeCandidate.IPsecReconcile = markIPsecCleanupReconcile(runtimeCandidate.IPsecReconcile, now)
		if err := photonlinux.CommitRuntimeState(boltStore, view.Revision, runtimeCandidate); err != nil {
			return 0, 0, err
		}
		return 0, 0, nil
	}
	platformDriver, err := newLinuxDriverForIPsecCleanup(rt.Config)
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = platformDriver.Close() }()
	cleaned := 0
	if len(runtimeCandidate.LinkInstances) > 0 {
		ids := make([]string, 0, len(runtimeCandidate.LinkInstances))
		for id := range runtimeCandidate.LinkInstances {
			ids = append(ids, id)
		}
		cleaned, err = cleanupLinuxDriverIPsecLinks(ctx, runtimeCandidate, ids, platformDriver, now)
		if err != nil {
			return cleaned, 0, err
		}
	} else {
		runtimeCandidate.IPsecReconcile = markIPsecCleanupReconcile(runtimeCandidate.IPsecReconcile, now)
	}
	orphans := 0
	if includeOrphans {
		orphans, err = platformDriver.CleanupIPsecOrphans(ctx, managedIPsecConnectionNamesFromLinks(runtimeCandidate.LinkInstances))
		if err != nil {
			return cleaned, orphans, err
		}
	}
	if err != nil {
		return cleaned, orphans, err
	}
	if err := photonlinux.CommitRuntimeState(boltStore, view.Revision, runtimeCandidate); err != nil {
		return cleaned, orphans, err
	}
	return cleaned, orphans, nil
}

func (d *Daemon) handleIPsecCleanupEvent(ctx context.Context, includeOrphans bool) (int, int, error) {
	if d == nil || d.StateStore == nil || d.App == nil {
		return 0, 0, errors.New("daemon service is not initialized")
	}
	common, runtimeCandidate := d.StateStore.readCommonAndRuntime()
	if common.State == nil || runtimeCandidate == nil {
		return 0, 0, errors.New("daemon state is not loaded")
	}
	platformDriver := d.linuxDriver
	if len(runtimeCandidate.LinkInstances) > 0 || includeOrphans {
		if platformDriver == nil {
			return 0, 0, errors.New("linux driver is not initialized")
		}
	}

	cleaned := 0
	orphans := 0
	now := d.now()
	var err error
	if len(runtimeCandidate.LinkInstances) > 0 {
		ids := make([]string, 0, len(runtimeCandidate.LinkInstances))
		for id := range runtimeCandidate.LinkInstances {
			ids = append(ids, id)
		}
		cleaned, err = cleanupLinuxDriverIPsecLinks(ctx, runtimeCandidate, ids, platformDriver, now)
		if err != nil {
			return cleaned, orphans, err
		}
	} else {
		runtimeCandidate.IPsecReconcile = markIPsecCleanupReconcile(runtimeCandidate.IPsecReconcile, now)
	}
	if includeOrphans {
		orphans, err = platformDriver.CleanupIPsecOrphans(ctx, managedIPsecConnectionNamesFromLinks(runtimeCandidate.LinkInstances))
		if err != nil {
			return cleaned, orphans, err
		}
	}
	if _, committed, err := d.StateStore.commitIPsecIfRevision(
		uint64(common.Revision),
		runtimeCandidate.IPsecTransportKey,
		runtimeCandidate.LinkInstances,
		runtimeCandidate.IPsecReconcile,
	); err != nil {
		return cleaned, orphans, err
	} else if !committed {
		return cleaned, orphans, errDaemonStateRevisionStale
	}
	d.notifyStateChanged()
	return cleaned, orphans, nil
}

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

func cleanupLinuxDriverIPsecLinks(ctx context.Context, runtime *linuxRuntimeState, ids []string, platformDriver *photonlinux.LinuxDriver, now time.Time) (int, error) {
	if runtime == nil {
		return 0, errors.New("linux runtime state is nil")
	}
	links, cleaned, err := cleanupIPsecLinkInstanceSet(ctx, runtime.LinkInstances, ids, platformDriver)
	if err != nil {
		return cleaned, err
	}
	runtime.LinkInstances = links
	if cleaned > 0 {
		runtime.IPsecReconcile = markIPsecCleanupReconcile(runtime.IPsecReconcile, now)
	}
	return cleaned, nil
}

func cleanupIPsecLinkInstanceSet(ctx context.Context, linkInstances map[string]linkInstanceState, ids []string, platformDriver *photonlinux.LinuxDriver) (map[string]linkInstanceState, int, error) {
	instances := linkInstancesToIPsec(linkInstances)
	remaining, cleaned, err := platformDriver.CleanupIPsecLinks(ctx, instances, ids)
	if err != nil {
		return nil, cleaned, err
	}
	return linkInstancesFromIPsec(remaining), cleaned, nil
}

func managedIPsecConnectionNamesFromLinks(links map[string]linkInstanceState) map[string]bool {
	out := make(map[string]bool)
	for _, inst := range linkInstancesToIPsec(links) {
		for _, name := range []string{inst.TransportID, inst.IKEName, inst.StagedIKEName} {
			if name != "" {
				out[name] = true
			}
		}
	}
	return out
}

func markIPsecCleanupReconcile(reconcile *ipsecReconcileState, now time.Time) *ipsecReconcileState {
	if reconcile == nil {
		reconcile = &ipsecReconcileState{}
	}
	reconcile.LastRunUnix = now.Unix()
	reconcile.DesiredLinks = 0
	reconcile.LastError = ""
	reconcile.Desired = nil
	reconcile.Actions = nil
	reconcile.ActualSAs = nil
	reconcile.Skipped = nil
	return reconcile
}
