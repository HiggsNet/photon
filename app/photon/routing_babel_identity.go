package main

import (
	"context"
	"encoding/json"
	"slices"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/routing"
	"github.com/HiggsNet/photon/pkg/routing/bird"
)

const babelIdentityLease = 2 * time.Minute

// routingBabelIdentityProtocolIntent runs under publishLocalProtocols' existing
// transaction owner. Live observations are never reused across revisions or
// daemon restarts; commitLocalProtocols checks the snapshot revision before
// signing. Unavailable/empty/ambiguous evidence removes that instance's ID.
func (d *Daemon) routingBabelIdentityProtocolIntent(ctx context.Context, verified *corestate.VerifiedState, now time.Time) (*corestate.PutProtocolRecordIntent, error) {
	if verified == nil || verified.Network == nil || verified.ManagedZone.IsRoot() || !verified.ManagedZone.Valid() || len(verified.IdentityPrivateKey) == 0 || d.Config == nil {
		return nil, nil
	}
	var ids []string
	ars, err := routing.BuildAuthorizedRouteSet(verified.Network, now)
	if err == nil {
		local := routing.LocalAssignedPrefixes(ars, verified.ManagedZone, true)
		local = append(local, routing.AuthorizedPrefixes(ars, []zone.ZonePath{verified.ManagedZone})...)
		if len(local) > 0 {
			for _, inst := range d.Config.Routing.EnabledInstances() {
				if len(ids) >= routing.MaxBabelIdentities {
					ids = nil
					break
				}
				observeCtx, cancel := context.WithTimeout(ctx, birdHealthObservationTimeout)
				protocol := bird.BabelProtocolName(inst.Bird.NetNSName)
				output, observeErr := d.linuxDriver.RawBird(observeCtx, inst.Bird.ControlSocketPath, "show babel entries "+protocol)
				cancel()
				if observeErr != nil {
					continue
				}
				id, parseErr := bird.LocalBabelIdentity(output, protocol, local)
				if parseErr == nil && id != "" {
					ids = append(ids, id)
				}
			}
		}
	}
	slices.Sort(ids)
	ids = slices.Compact(ids)
	var previous *routing.BabelIdentityRecord
	if zs := verified.Network.Zones[verified.ManagedZone]; zs != nil {
		if record := zs.Records[routing.RecordKeyBabelIdentity]; record != nil {
			previous, _ = routing.ParseBabelIdentityRecord(record, now)
		}
	}
	// Never create empty records on installations that have not published an ID.
	// Existing live records are explicitly withdrawn, then refreshed only near
	// lease expiry. Expired records already deny admission without another write.
	if len(ids) == 0 && previous == nil {
		return nil, nil
	}
	if previous != nil && slices.Equal(previous.RouterIDs, ids) && (len(ids) == 0 || previous.ExpiresAt > now.Add(babelIdentityLease/2).Unix()) {
		return nil, nil
	}
	value, err := json.Marshal(routing.BabelIdentityRecord{Version: 1, RouterIDs: ids, ExpiresAt: now.Add(babelIdentityLease).Unix()})
	if err != nil {
		return nil, err
	}
	return &corestate.PutProtocolRecordIntent{Kind: corestate.ProtocolRecordBabelIdentity, Zone: verified.ManagedZone, Key: routing.RecordKeyBabelIdentity, Type: routing.RecordTypeBabelIdentity, Value: value}, nil
}

// publishRoutingBabelIdentity refreshes just the routing record after reconcile;
// unrelated endpoint/IPsec publication remains on its existing timer. Both use
// the same planner and revision-checked local protocol transaction boundary.
func (d *Daemon) publishRoutingBabelIdentity(ctx context.Context) error {
	view := d.State.Common.ReadView()
	now := d.now()
	intent, err := d.routingBabelIdentityProtocolIntent(ctx, view.State, now)
	if err != nil || intent == nil {
		return err
	}
	result, err := commitLocalProtocols(ctx, d.State, uint64(view.Revision), []corestate.LocalIntent{*intent}, nil, now)
	if err != nil {
		return err
	}
	if result.Common.Committed {
		d.refreshGossipDiscovery()
		d.notifyStateChanged()
	}
	return nil
}
