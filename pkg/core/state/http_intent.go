package state

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/routing"
	service "github.com/HiggsNet/photon/pkg/service"
)

func applyPublishHTTPIntent(state *VerifiedState, intent PublishHTTPIntent, now time.Time) (*zone.Record, zone.ZonePath, error) {
	if state == nil || !state.ManagedZone.Valid() {
		return nil, "", ErrInvalidStateRoot
	}
	if err := intent.Service.Validate(); err != nil {
		return nil, "", err
	}
	if !intent.Service.IsActive() {
		return nil, "", errors.New("cannot publish an inactive http service")
	}
	encoded, err := json.Marshal(intent.Service)
	if err != nil {
		return nil, "", err
	}
	authorized, err := routing.BuildAuthorizedRouteSet(state.Network, now)
	if err != nil {
		return nil, "", err
	}
	probe := &zone.Record{Zone: state.ManagedZone, Key: "services/http", Type: service.RecordTypeHTTP, Value: encoded}
	if _, err := service.AuthorizeProxyRecord(probe, authorized); err != nil {
		return nil, "", err
	}
	return applyPutRecordIntent(state, PutRecordIntent{Zone: probe.Zone, Key: probe.Key, Type: probe.Type, Value: encoded}, now)
}

func applyWithdrawHTTPIntent(state *VerifiedState, now time.Time) (*zone.Record, zone.ZonePath, error) {
	if state == nil || !state.ManagedZone.Valid() {
		return nil, "", ErrInvalidStateRoot
	}
	current := recordAt(state, state.ManagedZone, "services/http")
	value, err := service.ParseHTTPRecord(current)
	if err != nil {
		return nil, "", err
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
	return applyPutRecordIntent(state, PutRecordIntent{Zone: state.ManagedZone, Key: current.Key, Type: current.Type, Value: encoded}, now)
}
