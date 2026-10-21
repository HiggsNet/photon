package main

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func recoveryCleanupIPsec(ctx context.Context, includeOrphans, direct bool) error {
	rt, err := NewRuntime()
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

func cleanupIPsecViaControl(rt *Runtime, includeOrphans bool) (*controlResponse, bool, error) {
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

func recoveryCleanupIPsecDirect(ctx context.Context, rt *Runtime, includeOrphans bool) (int, int, error) {
	if rt == nil {
		return 0, 0, errors.New("runtime is nil")
	}
	state, err := rt.LoadState()
	if err != nil {
		return 0, 0, err
	}
	state.Lock()
	defer state.Unlock()
	if len(state.LinkInstances) == 0 && !includeOrphans {
		markIPsecCleanupSnapshot(state, rt.Now())
		if err := rt.SaveState(state); err != nil {
			return 0, 0, err
		}
		return 0, 0, nil
	}
	drivers, err := newIPsecCleanupDrivers(rt.Config)
	if err != nil {
		return 0, 0, err
	}
	if drivers.close != nil {
		defer func() { _ = drivers.close() }()
	}
	cleaned := 0
	if len(state.LinkInstances) > 0 {
		cleaned, err = cleanupIPsecLinkInstances(ctx, state, drivers.ipsecDriver, drivers.xfrmDriver, rt.Now())
		if err != nil {
			return cleaned, 0, err
		}
	} else {
		markIPsecCleanupSnapshot(state, rt.Now())
	}
	orphans := 0
	if includeOrphans {
		orphans, err = cleanupIPsecOrphanConnections(ctx, state, drivers.ipsecDriver)
		if err != nil {
			return cleaned, orphans, err
		}
	}
	if err != nil {
		return cleaned, orphans, err
	}
	if err := rt.SaveState(state); err != nil {
		return cleaned, orphans, err
	}
	return cleaned, orphans, nil
}

func (d *DaemonService) handleIPsecCleanupEvent(ctx context.Context, includeOrphans bool) (int, int, error) {
	if d == nil || d.Sync == nil || d.StateStore == nil || d.Sync.App == nil {
		return 0, 0, errors.New("daemon service is not initialized")
	}
	workspace, rev := d.StateStore.ipsecSnapshot()
	if workspace == nil {
		return 0, 0, errors.New("daemon state is not loaded")
	}
	ipsecDriver := d.IPsecDriver
	xfrmDriver := d.XFRMDriver
	var closeFn func() error
	if len(workspace.LinkInstances) > 0 || includeOrphans {
		if ipsecDriver == nil || xfrmDriver == nil {
			drivers, err := newIPsecCleanupDrivers(d.Sync.App.Config)
			if err != nil {
				return 0, 0, err
			}
			ipsecDriver = drivers.ipsecDriver
			xfrmDriver = drivers.xfrmDriver
			closeFn = drivers.close
		}
	}
	if closeFn != nil {
		defer func() { _ = closeFn() }()
	}

	cleaned := 0
	orphans := 0
	cleanupState := func(state *stateFile) error {
		now := d.Sync.now()
		var err error
		if len(state.LinkInstances) > 0 {
			cleaned, err = cleanupIPsecLinkInstances(ctx, state, ipsecDriver, xfrmDriver, now)
			if err != nil {
				return err
			}
		} else {
			markIPsecCleanupSnapshot(state, now)
		}
		if includeOrphans {
			orphans, err = cleanupIPsecOrphanConnections(ctx, state, ipsecDriver)
			if err != nil {
				return err
			}
		}
		return nil
	}

	if err := cleanupState(workspace); err != nil {
		return cleaned, orphans, err
	}
	if _, committed := d.StateStore.commitIPsecIfRevision(
		rev,
		workspace.IPsecTransportKey,
		workspace.IPsecPortRecord,
		workspace.LinkInstances,
		workspace.IPsecReconcile,
	); !committed {
		return cleaned, orphans, errDaemonStateRevisionStale
	}
	if err := d.saveCommittedState(); err != nil {
		return cleaned, orphans, err
	}
	d.notifyStateChanged()
	return cleaned, orphans, nil
}

func newIPsecCleanupDrivers(config *appConfig) (configuredIPsecDrivers, error) {
	if config == nil {
		return configuredIPsecDrivers{}, errors.New("config is nil")
	}
	driver := config.IPsec.Driver
	if driver == "" {
		driver = ipsecDriverStrongSwan
	}
	switch driver {
	case ipsecDriverDryRun:
		dryRun := &ipsec.DryRunDriver{}
		return configuredIPsecDrivers{ipsecDriver: dryRun, xfrmDriver: dryRun}, nil
	case ipsecDriverStrongSwan:
		client, err := ipsec.NewGoviciClient(config.IPsec.VICISocket)
		if err != nil {
			return configuredIPsecDrivers{}, fmt.Errorf("initialize strongswan vici client: %w", err)
		}
		return configuredIPsecDrivers{
			ipsecDriver: &ipsec.StrongSwanDriver{VICI: client, XFRMBackend: ipsec.XFRMBackend(config.IPsec.XFRMBackend)},
			xfrmDriver:  newXFRMDriverForBackend(config.IPsec),
			close:       client.Close,
		}, nil
	default:
		return configuredIPsecDrivers{}, fmt.Errorf("unsupported ipsec driver %q", driver)
	}
}

func cleanupIPsecLinkInstances(ctx context.Context, state *stateFile, ipsecDriver ipsec.IPsecDriver, xfrmDriver ipsec.XFRMDriver, now time.Time) (int, error) {
	if state == nil {
		return 0, errors.New("state is nil")
	}
	if ipsecDriver == nil {
		return 0, errors.New("ipsec driver is nil")
	}
	if xfrmDriver == nil {
		return 0, errors.New("xfrm driver is nil")
	}
	instances := linkInstancesToIPsec(state.LinkInstances)
	ids := make([]string, 0, len(instances))
	for id := range instances {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	cleaned := 0
	for _, id := range ids {
		inst := instances[id]
		if err := inst.Owner.Validate(inst); err != nil {
			return cleaned, fmt.Errorf("refuse cleanup of unmanaged ipsec link %s: %w", id, err)
		}
		action := ipsec.ReconcileAction{Action: ipsec.ReconcileActionTeardown, Instance: &inst}
		if _, err := ipsec.ApplyReconcileAction(ctx, ipsecDriver, xfrmDriver, action, ipsec.NetNSSpec{}); err != nil {
			return cleaned, fmt.Errorf("cleanup ipsec link %s: %w", id, err)
		}
		delete(instances, id)
		cleaned++
	}
	state.LinkInstances = linkInstancesFromIPsec(instances)
	markIPsecCleanupSnapshot(state, now)
	return cleaned, nil
}

func cleanupIPsecLinkInstancesByID(ctx context.Context, state *stateFile, ids []string, ipsecDriver ipsec.IPsecDriver, xfrmDriver ipsec.XFRMDriver, now time.Time) (int, error) {
	if state == nil {
		return 0, errors.New("state is nil")
	}
	if len(ids) == 0 {
		return 0, nil
	}
	if ipsecDriver == nil {
		return 0, errors.New("ipsec driver is nil")
	}
	if xfrmDriver == nil {
		return 0, errors.New("xfrm driver is nil")
	}
	instances := linkInstancesToIPsec(state.LinkInstances)
	sortedIDs := append([]string(nil), ids...)
	sort.Strings(sortedIDs)
	cleaned := 0
	for _, id := range sortedIDs {
		inst, ok := instances[id]
		if !ok {
			continue
		}
		if err := inst.Owner.Validate(inst); err != nil {
			return cleaned, fmt.Errorf("refuse cleanup of unmanaged ipsec link %s: %w", id, err)
		}
		action := ipsec.ReconcileAction{Action: ipsec.ReconcileActionTeardown, Instance: &inst}
		if _, err := ipsec.ApplyReconcileAction(ctx, ipsecDriver, xfrmDriver, action, ipsec.NetNSSpec{}); err != nil {
			return cleaned, fmt.Errorf("cleanup ipsec link %s: %w", id, err)
		}
		delete(instances, id)
		cleaned++
	}
	state.LinkInstances = linkInstancesFromIPsec(instances)
	if cleaned > 0 {
		markIPsecCleanupSnapshot(state, now)
	}
	return cleaned, nil
}

func cleanupIPsecOrphanConnections(ctx context.Context, state *stateFile, ipsecDriver ipsec.IPsecDriver) (int, error) {
	lister, ok := ipsecDriver.(ipsec.ConnectionLister)
	if !ok {
		return 0, fmt.Errorf("ipsec driver does not support listing loaded connections")
	}
	conns, err := lister.ListConnections(ctx)
	if err != nil {
		return 0, fmt.Errorf("list ipsec connections: %w", err)
	}
	keep := managedIPsecConnectionNames(state)
	cleaned := 0
	for _, conn := range conns {
		if !isPhotonIPsecConnectionName(conn.Name) || keep[conn.Name] {
			continue
		}
		if err := ipsecDriver.TerminateSA(ctx, conn.Name); err != nil {
			return cleaned, fmt.Errorf("terminate orphan ipsec connection %s: %w", conn.Name, err)
		}
		if err := ipsecDriver.UnloadConnection(ctx, conn.Name); err != nil {
			return cleaned, fmt.Errorf("unload orphan ipsec connection %s: %w", conn.Name, err)
		}
		cleaned++
	}
	return cleaned, nil
}

func managedIPsecConnectionNames(state *stateFile) map[string]bool {
	out := make(map[string]bool)
	if state == nil {
		return out
	}
	for _, inst := range linkInstancesToIPsec(state.LinkInstances) {
		for _, name := range []string{inst.TransportID, inst.IKEName, inst.StagedIKEName} {
			if name != "" {
				out[name] = true
			}
		}
	}
	return out
}

func isPhotonIPsecConnectionName(name string) bool {
	return strings.HasPrefix(name, "ipsec-")
}

func markIPsecCleanupSnapshot(state *stateFile, now time.Time) {
	if state.IPsecReconcile == nil {
		state.IPsecReconcile = &ipsecReconcileState{}
	}
	state.IPsecReconcile.LastRunUnix = now.Unix()
	state.IPsecReconcile.DesiredLinks = 0
	state.IPsecReconcile.LastError = ""
	state.IPsecReconcile.Desired = nil
	state.IPsecReconcile.Actions = nil
	state.IPsecReconcile.ActualSAs = nil
	state.IPsecReconcile.Skipped = nil
}
