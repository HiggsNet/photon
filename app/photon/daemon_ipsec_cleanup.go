package main

import (
	"context"
	"errors"
	"time"

	photonlinux "github.com/HiggsNet/photon/internal/photonlinux"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func (d *Daemon) handleIPsecCleanupEvent(ctx context.Context, includeOrphans bool) (int, int, error) {
	if d == nil || d.State == nil || d.App == nil {
		return 0, 0, errors.New("daemon service is not initialized")
	}
	common := d.State.Common.ReadView()
	runtime := d.State.ReadLinux()
	if common.State == nil || runtime == nil {
		return 0, 0, errors.New("daemon state is not loaded")
	}
	links, reconcile := d.linuxObservation.ipsecSnapshot()
	platformDriver := d.linuxDriver
	if len(links) > 0 || includeOrphans {
		if platformDriver == nil {
			return 0, 0, errors.New("linux driver is not initialized")
		}
	}

	cleaned := 0
	orphans := 0
	now := d.now()
	var err error
	if len(links) > 0 {
		ids := make([]string, 0, len(links))
		for id := range links {
			ids = append(ids, id)
		}
		links, cleaned, err = cleanupIPsecLinkInstanceSet(ctx, links, ids, platformDriver)
		if err != nil {
			return cleaned, orphans, err
		}
	}
	reconcile = markIPsecCleanupReconcile(reconcile, now)
	if includeOrphans {
		orphans, err = platformDriver.CleanupIPsecOrphans(ctx, managedIPsecConnectionNamesFromLinks(links))
		if err != nil {
			return cleaned, orphans, err
		}
	}
	if uint64(d.State.Common.VerifiedRevision()) != uint64(common.Revision) {
		return cleaned, orphans, errStateRevisionStale
	}
	d.linuxObservation.replaceIPsec(links, reconcile)
	d.notifyStateChanged()
	return cleaned, orphans, nil
}

func cleanupIPsecLinkInstanceSet(ctx context.Context, linkInstances map[string]ipsec.LinkInstance, ids []string, platformDriver *photonlinux.LinuxDriver) (map[string]ipsec.LinkInstance, int, error) {
	remaining, cleaned, err := platformDriver.CleanupIPsecLinks(ctx, linkInstances, ids)
	if err != nil {
		return nil, cleaned, err
	}
	return remaining, cleaned, nil
}

func managedIPsecConnectionNamesFromLinks(links map[string]ipsec.LinkInstance) map[string]bool {
	out := make(map[string]bool)
	for _, inst := range links {
		for _, name := range []string{inst.TransportID, inst.IKEName, inst.StagedIKEName} {
			if name != "" {
				out[name] = true
			}
		}
	}
	return out
}

func markIPsecCleanupReconcile(reconcile *ipsecObservationSummary, now time.Time) *ipsecObservationSummary {
	if reconcile == nil {
		reconcile = &ipsecObservationSummary{}
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
