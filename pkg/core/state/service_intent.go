package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/routing"
	photonservice "github.com/HiggsNet/photon/pkg/service"
)

const socks5ServiceID = "socks5"

func applyPublishSOCKS5Intent(state *VerifiedState, intent PublishSOCKS5Intent, now time.Time) (*zone.Record, zone.ZonePath, error) {
	if state == nil || !state.ManagedZone.Valid() {
		return nil, "", ErrInvalidStateRoot
	}
	key, err := photonservice.RecordKey(socks5ServiceID)
	if err != nil {
		return nil, "", err
	}
	endpoints := make([]photonservice.SOCKS5Endpoint, 0, len(intent.Endpoints))
	for _, endpoint := range intent.Endpoints {
		address, err := netip.ParseAddr(endpoint.Address)
		if err != nil {
			return nil, "", fmt.Errorf("invalid service address %q: %w", endpoint.Address, err)
		}
		endpoint.Address = address.String()
		endpoints = append(endpoints, endpoint)
	}
	sort.Slice(endpoints, func(i, j int) bool {
		if endpoints[i].Region != endpoints[j].Region {
			return endpoints[i].Region < endpoints[j].Region
		}
		if endpoints[i].Address != endpoints[j].Address {
			return endpoints[i].Address < endpoints[j].Address
		}
		return endpoints[i].Port < endpoints[j].Port
	})
	value := photonservice.SOCKS5Record{Type: photonservice.TypeSOCKS5, Endpoints: endpoints}
	if err := value.Validate(); err != nil {
		return nil, "", err
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, "", err
	}
	authorized, err := routing.BuildAuthorizedRouteSet(state.Network, now)
	if err != nil {
		return nil, "", err
	}
	probe := &zone.Record{Zone: state.ManagedZone, Key: key, Type: photonservice.RecordTypeSOCKS5, Value: encoded}
	if _, err := photonservice.AuthorizeSOCKS5Record(probe, authorized); err != nil {
		return nil, "", err
	}
	return applyPutRecordIntent(state, PutRecordIntent{
		Zone: state.ManagedZone, Key: key, Type: photonservice.RecordTypeSOCKS5, Value: encoded,
	}, now)
}

func applyWithdrawSOCKS5Intent(state *VerifiedState, now time.Time) (*zone.Record, zone.ZonePath, error) {
	if state == nil || !state.ManagedZone.Valid() {
		return nil, "", ErrInvalidStateRoot
	}
	key, err := photonservice.RecordKey(socks5ServiceID)
	if err != nil {
		return nil, "", err
	}
	current := recordAt(state, state.ManagedZone, key)
	if current == nil {
		return nil, "", fmt.Errorf("service %q is not published", socks5ServiceID)
	}
	value, err := photonservice.ParseSOCKS5Record(current)
	if err != nil {
		return nil, "", fmt.Errorf("current service record is invalid: %w", err)
	}
	if !value.IsActive() {
		return current, "", nil
	}
	active := false
	value.Active = &active
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, "", err
	}
	record, changed, err := applyPutRecordIntent(state, PutRecordIntent{
		Zone: state.ManagedZone, Key: key, Type: photonservice.RecordTypeSOCKS5, Value: encoded,
	}, now)
	if errors.Is(err, zone.ErrStaleRecord) {
		return nil, "", fmt.Errorf("service %q withdrawal is stale: %w", socks5ServiceID, err)
	}
	return record, changed, err
}
