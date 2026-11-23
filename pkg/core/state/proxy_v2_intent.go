package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/service"
)

// ProxyV2Intent can only publish locally-owned proxy records. A complete
// replacement is one commit so a port change is visible across its endpoints.
type ProxyV2Intent struct{ Publication service.ProxyV2Publication }

func (ProxyV2Intent) isLocalIntent() {}

func applyProxyV2Intent(state *VerifiedState, intent ProxyV2Intent, now time.Time) (*zone.Record, zone.ZonePath, error) {
	owner := state.ManagedZone
	if !owner.Valid() || owner.IsRoot() || len(intent.Publication.Records) > 128 {
		return nil, "", errors.New("invalid local proxy publication")
	}
	desired := make(map[string]service.ProxyV2Record)
	for _, item := range intent.Publication.Records {
		body, lease, err := service.ParseProxyV2Record(item)
		if err != nil {
			return nil, "", fmt.Errorf("%s: %w", item.Key, err)
		}
		if !lease.ValidAt(now) || lease.ExpiresAt > now.Add(48*time.Hour).Unix() {
			return nil, "", errors.New("proxy publication needs an active lease of at most 48 hours")
		}
		if _, exists := desired[item.Key]; exists {
			return nil, "", errors.New("duplicate proxy record")
		}
		item.Value, err = json.Marshal(body)
		if err != nil {
			return nil, "", err
		}
		desired[item.Key] = item
	}
	if intent.Publication.Replace {
		if zs := state.Network.Zones[owner]; zs != nil {
			for key, current := range zs.Records {
				if _, exists := desired[key]; exists || !strings.HasPrefix(key, service.ProxyV2Prefix) {
					continue
				}
				item := service.ProxyV2Record{Key: key, Type: current.Type, Value: current.Value}
				body, lease, err := service.ParseProxyV2Record(item)
				if err != nil || !lease.Active {
					continue
				}
				proxyV2Lease(body).Active = false
				item.Value, err = json.Marshal(body)
				if err != nil {
					return nil, "", err
				}
				desired[key] = item
			}
		}
	}
	var result *zone.Record
	var changed zone.ZonePath
	for _, key := range slices.Sorted(maps.Keys(desired)) {
		item := desired[key]
		current := recordAt(state, owner, key)
		if current != nil && current.Type == item.Type {
			prior, oldLease, oldErr := service.ParseProxyV2Record(service.ProxyV2Record{Key: key, Type: current.Type, Value: current.Value})
			next, lease, _ := service.ParseProxyV2Record(item)
			if oldErr == nil {
				proxyV2Lease(prior).ExpiresAt = lease.ExpiresAt
				if reflect.DeepEqual(prior, next) && (!lease.Active ||
					oldLease.ExpiresAt <= lease.ExpiresAt && oldLease.ExpiresAt-now.Unix() >= (lease.ExpiresAt-now.Unix())/2) {
					continue
				}
			}
		}
		record, path, err := applyPutRecordIntent(state, PutRecordIntent{
			Zone: owner, Key: key, Type: item.Type, Value: item.Value,
		}, now)
		if err != nil {
			return nil, "", err
		}
		if path != "" {
			result, changed = record, path
		}
	}
	return result, changed, nil
}

func proxyV2Lease(value any) *service.ProxyV2Lease {
	switch value := value.(type) {
	case *service.ProxyV2Identity:
		return &value.ProxyV2Lease
	case *service.ProxyV2TLS:
		return &value.ProxyV2Lease
	case *service.ProxyV2Endpoint:
		return &value.ProxyV2Lease
	default:
		panic("validated proxy record had an unknown type")
	}
}
