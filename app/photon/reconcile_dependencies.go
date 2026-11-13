package main

import corestate "github.com/HiggsNet/photon/pkg/core/state"

// Dependencies belong to daemon consumers, not to the portable Store. Unknown
// local intents and remote/authority changes retain the conservative all-layer
// path. Runtime IPsec outputs independently invalidate routing and firewall.
type reconcileLayers uint8

const (
	reconcileIPsec reconcileLayers = 1 << iota
	reconcileRoutes
	reconcileFirewall
	reconcileAll = reconcileIPsec | reconcileRoutes | reconcileFirewall
)

func localIntentReconcileLayers(intent corestate.LocalIntent) reconcileLayers {
	if commonMutationAffectsRouting(intent) {
		return reconcileRoutes | reconcileFirewall
	}
	switch intent := intent.(type) {
	case corestate.PublishSOCKS5Intent, corestate.WithdrawSOCKS5Intent:
		// Service discovery has no Linux platform consumer.
		return 0
	case corestate.PutProtocolRecordIntent:
		switch intent.Kind {
		case corestate.ProtocolRecordGossipEndpoint, corestate.ProtocolRecordIPsec:
			return reconcileIPsec
		case corestate.ProtocolRecordRoutingNetns:
			// This is an announcement; local namespace setup uses config.
			return 0
		}
	}
	return reconcileAll
}

func (d *Daemon) markReconcileDirty(layers reconcileLayers) {
	if d.linuxDriver == nil {
		return
	}
	d.ipsecDirty = d.ipsecDirty || layers&reconcileIPsec != 0
	d.routingDirty = d.routingDirty || layers&reconcileRoutes != 0
	d.firewallDirty = d.firewallDirty || layers&reconcileFirewall != 0
}
