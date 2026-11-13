package main

import (
	"context"
	"errors"

	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func (d *Daemon) handleIPsecCleanupEvent(ctx context.Context, includeOrphans bool) (int, int, error) {
	if d.State == nil || d.Config == nil {
		return 0, 0, errors.New("daemon service is not initialized")
	}
	common := d.State.Common.ReadView()
	if common.State == nil {
		return 0, 0, errors.New("daemon state is not loaded")
	}
	links, _ := d.linuxObservation.ipsecSnapshot()
	platformDriver := d.linuxDriver
	if len(links) > 0 || includeOrphans {
		if platformDriver == nil {
			return 0, 0, errors.New("linux driver is not initialized")
		}
	}

	cleaned := 0
	orphans := 0
	var err error
	if len(links) > 0 {
		ids := make([]string, 0, len(links))
		for id := range links {
			ids = append(ids, id)
		}
		links, cleaned, err = platformDriver.CleanupIPsecLinks(ctx, links, ids)
	}
	if err == nil && includeOrphans {
		orphans, err = platformDriver.CleanupIPsecOrphans(ctx, managedIPsecConnectionNamesFromLinks(links))
	}
	d.recordIPsecCleanup(links, err)
	return cleaned, orphans, err
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

func (d *Daemon) recordIPsecCleanup(links map[string]ipsec.LinkInstance, err error) {
	d.linuxObservation.replaceIPsec(links, &ipsecObservationSummary{LastRunUnix: d.now().Unix(), LastFailure: err})
	// Cleanup changes live platform state, including partial progress on error.
	// Rebuild desired links and their consumers without a signed-state notice.
	d.markReconcileDirty(reconcileAll)
}
