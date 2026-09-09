package main

import (
	"maps"
	"sync"

	"github.com/HiggsNet/photon/pkg/firewall"
	"github.com/HiggsNet/photon/pkg/routing/bird"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

// linuxObservation is the daemon's live platform view. It has no persistence
// or worker of its own and is empty again after a process restart.
type linuxObservation struct {
	mu                sync.RWMutex
	ipsecLinks        map[string]ipsec.LinkInstance
	ipsecReconcile    *ipsecObservationSummary
	routingReconcile  *routingObservation
	firewallReconcile *firewall.FirewallObservation
}

// routingObservation is online diagnostic state. It is rebuilt after
// every daemon start and is never persisted in the Linux runtime state.
type routingObservation struct {
	Instances   map[string]*bird.InstanceObservation
	LastRunUnix int64
	LastError   string
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

func (o *linuxObservation) routingSnapshot() *routingObservation {
	if o == nil {
		return nil
	}
	o.mu.RLock()
	defer o.mu.RUnlock()
	if o.routingReconcile == nil {
		return nil
	}
	return cloneRoutingObservation(o.routingReconcile)
}

func (o *linuxObservation) replaceRouting(reconcile *routingObservation) {
	if o == nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if reconcile == nil {
		o.routingReconcile = nil
		return
	}
	o.routingReconcile = cloneRoutingObservation(reconcile)
}

func cloneRoutingObservation(in *routingObservation) *routingObservation {
	if in == nil {
		return nil
	}
	out := *in
	if in.Instances != nil {
		out.Instances = make(map[string]*bird.InstanceObservation, len(in.Instances))
		for netns, instance := range in.Instances {
			if instance == nil {
				out.Instances[netns] = nil
				continue
			}
			copyInstance := *instance
			copyInstance.Overlays = append([]string(nil), instance.Overlays...)
			out.Instances[netns] = &copyInstance
		}
	}
	return &out
}

func (o *linuxObservation) firewallSnapshot() *firewall.FirewallObservation {
	if o == nil {
		return nil
	}
	o.mu.RLock()
	defer o.mu.RUnlock()
	return cloneFirewallObservation(o.firewallReconcile)
}

func (o *linuxObservation) replaceFirewall(reconcile *firewall.FirewallObservation) {
	if o == nil {
		return
	}
	o.mu.Lock()
	o.firewallReconcile = cloneFirewallObservation(reconcile)
	o.mu.Unlock()
}

func cloneFirewallObservation(in *firewall.FirewallObservation) *firewall.FirewallObservation {
	if in == nil {
		return nil
	}
	out := *in
	if in.Instances != nil {
		out.Instances = make(map[string]*firewall.FirewallInstanceObservation, len(in.Instances))
		for id, entry := range in.Instances {
			if entry == nil {
				out.Instances[id] = nil
				continue
			}
			copyEntry := *entry
			out.Instances[id] = &copyEntry
		}
	}
	return &out
}
