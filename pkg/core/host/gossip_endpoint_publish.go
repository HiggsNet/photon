package host

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

// GossipEndpointIntentInput separates platform endpoint collection from the
// common protocol decision that publishes the signed endpoint record.
type GossipEndpointIntentInput struct {
	Verified  *corestate.VerifiedState
	Endpoints []gossip.LocalEndpoint
	Disabled  bool
	Now       time.Time
	TTL       time.Duration
	Grace     time.Duration
	Refresh   time.Duration
}

// PlanGossipEndpointIntent returns the common endpoint-record mutation, or nil
// when identity admission is incomplete or the record is already current.
func PlanGossipEndpointIntent(input GossipEndpointIntentInput) (*corestate.PutProtocolRecordIntent, error) {
	verified := input.Verified
	if !gossipEndpointIdentityReady(verified) {
		return nil, nil
	}
	zoneState := verified.Network.Zones[verified.ManagedZone]
	var previous *gossip.EndpointRecord
	if existing := zoneState.Records[gossip.EndpointRecordKeyUDP]; existing != nil {
		var decoded gossip.EndpointRecord
		if json.Unmarshal(existing.Value, &decoded) == nil {
			previous = &decoded
		}
	}
	if input.Disabled && previous != nil && len(previous.Endpoints) == 0 {
		return nil, nil
	}

	endpoints := input.Endpoints
	grace := input.Grace
	if input.Disabled {
		if previous == nil {
			return nil, nil
		}
		endpoints = nil
		previous = nil
		grace = 0
	}
	record := gossip.LocalEndpointsToRecordWithPolicy(endpoints, previous, input.Now, input.TTL, grace)
	value, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	if existing := zoneState.Records[gossip.EndpointRecordKeyUDP]; existing != nil && !input.Disabled {
		if bytes.Equal(existing.Value, value) || (gossip.EndpointRecordEndpointsEqual(previous, record) && !gossipEndpointRefreshDue(previous, input.Now, input.Refresh)) {
			return nil, nil
		}
	}
	return &corestate.PutProtocolRecordIntent{
		Kind: corestate.ProtocolRecordGossipEndpoint, Zone: verified.ManagedZone,
		Key: gossip.EndpointRecordKeyUDP, Type: "sync.endpoint", Value: value,
	}, nil
}

func gossipEndpointIdentityReady(verified *corestate.VerifiedState) bool {
	if verified == nil || verified.Network == nil || verified.ManagedZone == "" || verified.ManagedZone == zone.RootZone || len(verified.IdentityPrivateKey) != ed25519.PrivateKeySize {
		return false
	}
	zoneState := verified.Network.Zones[verified.ManagedZone]
	if zoneState == nil || zoneState.Authority == nil {
		return false
	}
	public := verified.IdentityPrivateKey.Public().(ed25519.PublicKey)
	return zoneState.Authority.HasPublicKey(public)
}

func gossipEndpointRefreshDue(previous *gossip.EndpointRecord, now time.Time, refresh time.Duration) bool {
	if previous == nil || len(previous.Endpoints) == 0 {
		return true
	}
	if refresh <= 0 {
		refresh = gossip.DefaultEndpointRefresh
	}
	base := previous.UpdatedAt
	if base == 0 {
		for _, endpoint := range previous.Endpoints {
			if endpoint.LastObserved > base {
				base = endpoint.LastObserved
			}
		}
	}
	return base == 0 || !now.Before(time.Unix(base, 0).Add(refresh))
}
