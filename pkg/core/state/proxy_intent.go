package state

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/service"
)

type ProxyCapabilityIntent struct {
	Mutation service.ProxyMutation
	Renew    bool
}

func (ProxyCapabilityIntent) isLocalIntent() {}

func applyProxyCapabilityIntent(state *VerifiedState, intent ProxyCapabilityIntent, now time.Time) (*zone.Record, zone.ZonePath, error) {
	if !state.ManagedZone.Valid() {
		return nil, "", errors.New("managed Zone is not initialized")
	}
	current := recordAt(state, state.ManagedZone, service.RecordKeyProxy)
	mutation := intent.Mutation
	if intent.Renew && mutation.Record == nil {
		return nil, "", errors.New("proxy renewal needs a capability")
	}
	if mutation.AnnouncePort != 0 {
		return nil, "", errors.New("proxy announce host must be resolved before committing")
	}
	var version uint64
	if current != nil {
		version = current.Version
	}
	if mutation.ExpectedVersion != nil && *mutation.ExpectedVersion != version {
		return nil, "", fmt.Errorf("proxy record version is %d, expected %d", version, *mutation.ExpectedVersion)
	}
	var record service.ProxyCapability
	if mutation.Record == nil {
		var err error
		record, err = service.ParseProxyCapability(current)
		if err != nil {
			return nil, "", err
		}
		record.Active = false
	} else {
		record = *mutation.Record
		if !record.Active || !record.ExpiresAt.After(now) {
			return nil, "", errors.New("proxy publication needs an active, unexpired capability")
		}
		if err := record.Validate(); err != nil {
			return nil, "", err
		}
	}
	if intent.Renew {
		if current == nil {
			return nil, "", nil
		}
		prior, err := service.ParseProxyCapability(current)
		if err != nil {
			return nil, "", err
		}
		expiry := prior.ExpiresAt
		prior.ExpiresAt = record.ExpiresAt
		// A timer may run after a withdrawal, after a port or identity change,
		// or alongside another renewal. It can only extend the matching record.
		if !reflect.DeepEqual(prior, record) || !expiry.After(now) {
			return nil, "", nil
		}
		if !record.ExpiresAt.After(expiry) || expiry.Sub(now) > record.ExpiresAt.Sub(now)/2 {
			return cloneRecord(current), "", nil
		}
	}
	value, err := json.Marshal(record)
	if err != nil {
		return nil, "", err
	}
	if current != nil && current.Type == service.RecordTypeProxy && bytes.Equal(current.Value, value) {
		return cloneRecord(current), "", nil
	}
	return applyPutRecordIntent(state, PutRecordIntent{
		Zone: state.ManagedZone, Key: service.RecordKeyProxy, Type: service.RecordTypeProxy, Value: value,
	}, now)
}
