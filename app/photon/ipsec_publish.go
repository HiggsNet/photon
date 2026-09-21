package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"time"

	"github.com/HiggsNet/photon/internal/photonlinux"
	photonstate "github.com/HiggsNet/photon/internal/state"
	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

type localIPsecPublishPlan struct {
	Intents      []corestate.LocalIntent
	TransportKey *photonstate.IPsecTransportKeyState
}

func (d *Daemon) ipsecProtocolPlan(verified *corestate.VerifiedState, runtime *photonlinux.LinuxState) (localIPsecPublishPlan, error) {
	var plan localIPsecPublishPlan
	if verified == nil || verified.Network == nil || runtime == nil || d.Config == nil {
		d.logDebug("ipsec", "publish_skipped", map[string]any{"reason": "runtime_incomplete"})
		return plan, nil
	}
	config := d.Config
	if verified.ManagedZone == zone.RootZone {
		d.logDebug("ipsec", "publish_skipped", map[string]any{"reason": "root_zone"})
		return plan, nil
	}
	if !verified.ManagedZone.Valid() {
		d.logDebug("ipsec", "publish_skipped", map[string]any{"reason": "invalid_managed_zone", "managed_zone": verified.ManagedZone})
		return plan, nil
	}
	if len(verified.IdentityPrivateKey) == 0 {
		d.logDebug("ipsec", "publish_skipped", map[string]any{"reason": "missing_zone_private_key", "managed_zone": verified.ManagedZone})
		return plan, nil
	}
	if gossip.AutoJoinPending(verified) {
		d.logDebug("ipsec", "publish_skipped", map[string]any{"reason": "auto_join_pending", "managed_zone": verified.ManagedZone})
		return plan, nil
	}
	if len(config.IPsec.LinkGroups) == 0 {
		d.logDebug("ipsec", "publish_skipped", map[string]any{"reason": "no_link_groups", "managed_zone": verified.ManagedZone})
		return plan, nil
	}
	d.logDebug("ipsec", "publish_started", map[string]any{
		"managed_zone": verified.ManagedZone,
		"role":         config.IPsec.Role,
		"link_groups":  len(config.IPsec.LinkGroups),
	})
	now := d.now()
	key, keyRecord, err := ensureIPsecTransportKey(runtime, verified.IdentityPrivateKey, now)
	if err != nil {
		return plan, err
	}
	plan.TransportKey = photonstate.CloneIPsecTransportKeyState(key)
	records, err := localIPsecRecords(config, verified, keyRecord, now)
	if err != nil {
		return plan, err
	}
	for _, item := range records {
		if port, ok := item.value.(*ipsec.PortRecord); ok {
			d.logDebug("ipsec", "port_publish_decision", ipsecPortPublishLogFields(config, existingIPsecPortRecord(verified), port, now))
		}
		value, err := json.Marshal(item.value)
		if err != nil {
			return localIPsecPublishPlan{}, err
		}
		if zs := verified.Network.Zones[verified.ManagedZone]; zs != nil {
			if current := zs.Records[item.key]; current != nil && current.Type == item.recordType && bytes.Equal(current.Value, value) {
				continue
			}
		}
		plan.Intents = append(plan.Intents, corestate.PutProtocolRecordIntent{
			Kind: corestate.ProtocolRecordIPsec, Zone: verified.ManagedZone, Key: item.key, Type: item.recordType, Value: value,
		})
		d.logDebug("ipsec", "publish_record_decision", map[string]any{
			"managed_zone": verified.ManagedZone,
			"key":          item.key,
			"updated":      true,
		})
	}
	d.logDebug("ipsec", "publish_planned", map[string]any{
		"managed_zone":   verified.ManagedZone,
		"records":        len(records),
		"record_updates": len(plan.Intents),
	})
	return plan, nil
}

func ipsecPortPublishLogFields(config *appConfig, previous *ipsec.PortRecord, record *ipsec.PortRecord, now time.Time) map[string]any {
	fields := map[string]any{
		"now": now.Unix(),
	}
	if config != nil {
		fields["rotate_interval_seconds"] = int64(config.IPsec.PortRotateInterval.Seconds())
		fields["previous_grace_seconds"] = int64(config.IPsec.PortPreviousGrace.Seconds())
	}
	if previous != nil {
		fields["existing_mode"] = previous.Mode
		if previous.Current != nil {
			fields["existing_generation"] = previous.Current.Generation
		}
		fields["existing_updated_at"] = previous.UpdatedAt
		if previous.Range != nil {
			fields["existing_range"] = fmt.Sprintf("%d-%d", previous.Range.From, previous.Range.To)
		}
		if config != nil && config.IPsec.PortRotateInterval > 0 && previous.UpdatedAt > 0 {
			dueAt := time.Unix(previous.UpdatedAt, 0).Add(config.IPsec.PortRotateInterval)
			fields["rotate_due_at"] = dueAt.Unix()
			fields["rotate_due"] = !now.Before(dueAt)
		}
	} else {
		fields["existing_generation"] = 0
	}
	if record != nil {
		fields["record_mode"] = record.Mode
		fields["record_updated_at"] = record.UpdatedAt
		if record.Range != nil {
			fields["record_range"] = fmt.Sprintf("%d-%d", record.Range.From, record.Range.To)
		}
		if record.Current != nil {
			fields["record_generation"] = record.Current.Generation
			fields["record_ike_advertised"] = record.Current.IKE.Advertised
			fields["record_natt_advertised"] = record.Current.NATT.Advertised
		}
		if len(record.Previous) > 0 {
			fields["previous_count"] = len(record.Previous)
			fields["previous_generation"] = record.Previous[0].Generation
			fields["previous_valid_until"] = record.Previous[0].ValidUntil
		}
	}
	return fields
}

type localIPsecRecord struct {
	key        string
	recordType string
	value      any
}

func ensureIPsecTransportKey(linuxState *photonlinux.LinuxState, identityPrivateKey ed25519.PrivateKey, now time.Time) (*photonstate.IPsecTransportKeyState, *ipsec.TransportKeyRecord, error) {
	if linuxState == nil {
		return nil, nil, fmt.Errorf("LinuxState is nil")
	}
	if key := linuxState.IPsecTransportKey; key != nil && len(key.PublicKey) > 0 && len(key.PrivateKey) > 0 {
		record := photonlinux.PublicTransportKeyRecord(key)
		return key, record, nil
	}
	var forbiddenPublicKeys [][]byte
	if len(identityPrivateKey) == ed25519.PrivateKeySize {
		forbiddenPublicKeys = [][]byte{identityPrivateKey.Public().(ed25519.PublicKey)}
	}
	generated, record, err := ipsec.GenerateTransportKeyRecord(ipsec.AlgorithmEd25519, now, 0, forbiddenPublicKeys...)
	if err != nil {
		return nil, nil, err
	}
	return &photonstate.IPsecTransportKeyState{
		Kind:        generated.Kind,
		Algorithm:   generated.Algorithm,
		PublicKey:   generated.PublicKey,
		PrivateKey:  generated.PrivateKey,
		Fingerprint: record.Fingerprint,
		NotBefore:   record.NotBefore,
		NotAfter:    record.NotAfter,
		UpdatedAt:   record.UpdatedAt,
	}, record, nil
}

func localIPsecRecords(config *appConfig, verified *corestate.VerifiedState, key *ipsec.TransportKeyRecord, now time.Time) ([]localIPsecRecord, error) {
	if config == nil {
		return nil, fmt.Errorf("config is nil")
	}
	if key == nil {
		return nil, fmt.Errorf("transport key record is required")
	}
	addresses := localIPsecAddressRecord(config, verified, now)
	ports, err := ipsec.PlanPortPublication(config.IPsec.PortMode, &config.IPsec.PortRange, config.IPsec.PortRotateInterval, config.IPsec.PortPreviousGrace, existingIPsecPortRecord(verified), now)
	if err != nil {
		return nil, err
	}
	profile := ipsec.BuildProfileRecord(verified.ManagedZone, key.Fingerprint, config.IPsec.Role, config.IPsec.LinkGroups, addresses)

	records := []localIPsecRecord{
		{key: ipsec.RecordKeyTransportKey, recordType: ipsec.RecordTypeTransportKey, value: *key},
		{key: ipsec.RecordKeyProfile, recordType: ipsec.RecordTypeProfile, value: profile},
		{key: ipsec.RecordKeyAddresses, recordType: ipsec.RecordTypeAddresses, value: addresses},
		{key: ipsec.RecordKeyPorts, recordType: ipsec.RecordTypePorts, value: ports},
	}
	var existing map[string]*zone.Record
	if verified.Network != nil {
		if zs := verified.Network.Zones[verified.ManagedZone]; zs != nil {
			existing = zs.Records
		}
	}
	for _, intent := range ipsec.BuildOverlayIntentRecords(config.IPsec.LinkGroups, addresses.PublicationFamilies(), existing, now) {
		records = append(records, localIPsecRecord{key: ipsec.OverlayIntentRecordKey(intent.OverlayID), recordType: ipsec.RecordTypeOverlayIntent, value: intent})
	}
	return records, nil
}

func localIPsecAddressRecord(config *appConfig, verified *corestate.VerifiedState, now time.Time) ipsec.AddressRecord {
	var endpoints *gossip.EndpointRecord
	if config.IPsec.AnnounceGossipEndpoints && verified != nil && verified.Network != nil && verified.ManagedZone != "" {
		if zs := verified.Network.Zones[verified.ManagedZone]; zs != nil {
			if record := zs.Records[gossip.EndpointRecordKeyUDP]; record != nil {
				var decoded gossip.EndpointRecord
				if json.Unmarshal(record.Value, &decoded) == nil {
					endpoints = &decoded
				}
			}
		}
	}
	return photonlinux.BuildIPsecAddressRecord(config.IPsec.AnnounceAddrs, config.AdvertiseAddrs, config.IPsec.AnnounceDNS, config.ListenAddr, endpoints, now)
}

func existingIPsecPortRecord(verified *corestate.VerifiedState) *ipsec.PortRecord {
	if verified == nil || verified.Network == nil || !verified.ManagedZone.Valid() {
		return nil
	}
	zs := verified.Network.Zones[verified.ManagedZone]
	if zs == nil || zs.Records == nil || zs.Records[ipsec.RecordKeyPorts] == nil {
		return nil
	}
	record, err := ipsec.ParsePortRecord(zs.Records[ipsec.RecordKeyPorts])
	if err != nil {
		return nil
	}
	return record
}
