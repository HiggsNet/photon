package main

import (
	"maps"
	"sync"

	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

// linuxObservation is the daemon's live platform view. It has no persistence
// or worker of its own and is empty again after a process restart.
type linuxObservation struct {
	mu             sync.RWMutex
	ipsecLinks     map[string]ipsec.LinkInstance
	ipsecReconcile *ipsecObservationSummary
}

// ipsecObservationSummary is the daemon's online summary of the latest observed
// IPsec reconcile. It is process-local and is never written to StateStore.
type ipsecObservationSummary struct {
	LastRunUnix    int64
	SourceRevision uint64
	DesiredLinks   int
	Desired        []desiredLinkState
	ActualSAs      []linkSAState
	Actions        []linkActionState
	Skipped        []linkSkipState
	LastError      string
}

func cloneIPsecObservationSummary(in *ipsecObservationSummary) *ipsecObservationSummary {
	if in == nil {
		return nil
	}
	out := *in
	out.Desired = append([]desiredLinkState(nil), in.Desired...)
	out.ActualSAs = append([]linkSAState(nil), in.ActualSAs...)
	out.Actions = append([]linkActionState(nil), in.Actions...)
	out.Skipped = append([]linkSkipState(nil), in.Skipped...)
	return &out
}

func (o *linuxObservation) ipsecSnapshot() (map[string]ipsec.LinkInstance, *ipsecObservationSummary) {
	if o == nil {
		return make(map[string]ipsec.LinkInstance), nil
	}
	o.mu.RLock()
	defer o.mu.RUnlock()
	links := maps.Clone(o.ipsecLinks)
	if links == nil {
		links = make(map[string]ipsec.LinkInstance)
	}
	return links, cloneIPsecObservationSummary(o.ipsecReconcile)
}

func (o *linuxObservation) replaceIPsec(links map[string]ipsec.LinkInstance, reconcile *ipsecObservationSummary) {
	if o == nil {
		return
	}
	o.mu.Lock()
	o.ipsecLinks = maps.Clone(links)
	o.ipsecReconcile = cloneIPsecObservationSummary(reconcile)
	o.mu.Unlock()
}
