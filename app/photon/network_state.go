package main

import (
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

func configureValidation(network *zone.NetworkState) {
	network.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
}

func normalizeState(network *zone.NetworkState) {
	if network.Zones == nil {
		network.Zones = make(map[zone.ZonePath]*zone.ZoneState)
	}
	for path, state := range network.Zones {
		if state.Path == "" {
			state.Path = path
		}
		if state.Delegations == nil {
			state.Delegations = make(map[zone.ZonePath]*zone.Delegation)
		}
		if state.Revocations == nil {
			state.Revocations = make(map[zone.ZonePath]*zone.DelegationRevocation)
		}
		if state.Records == nil {
			state.Records = make(map[string]*zone.Record)
		}
		if state.RecordHistory == nil {
			state.RecordHistory = make(map[string][]*zone.Record)
		}
	}
}
