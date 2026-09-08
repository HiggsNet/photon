package main

import (
	"maps"
	"sync"

	photonstate "github.com/HiggsNet/photon/internal/state"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

// linuxObservation is the daemon's live platform view. It has no persistence
// or worker of its own and is empty again after a process restart.
type linuxObservation struct {
	mu             sync.RWMutex
	ipsecLinks     map[string]ipsec.LinkInstance
	ipsecReconcile *ipsecReconcileState
}

func (o *linuxObservation) ipsecSnapshot() (map[string]ipsec.LinkInstance, *ipsecReconcileState) {
	if o == nil {
		return make(map[string]ipsec.LinkInstance), nil
	}
	o.mu.RLock()
	defer o.mu.RUnlock()
	links := maps.Clone(o.ipsecLinks)
	if links == nil {
		links = make(map[string]ipsec.LinkInstance)
	}
	return links, photonstate.CloneIPsecReconcileState(o.ipsecReconcile)
}

func (o *linuxObservation) replaceIPsec(links map[string]ipsec.LinkInstance, reconcile *ipsecReconcileState) {
	if o == nil {
		return
	}
	o.mu.Lock()
	o.ipsecLinks = maps.Clone(links)
	o.ipsecReconcile = photonstate.CloneIPsecReconcileState(reconcile)
	o.mu.Unlock()
}

func (d *Daemon) ipsecStateSnapshot() (map[string]linkInstanceState, *ipsecReconcileState) {
	links, reconcile := d.linuxObservation.ipsecSnapshot()
	return linkInstancesFromIPsec(links), reconcile
}
