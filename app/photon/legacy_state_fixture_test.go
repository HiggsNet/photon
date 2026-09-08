package main

import "github.com/HiggsNet/photon/pkg/core/zone"

// saveStateAt writes the retired aggregate schema. It is intentionally
// test-only and must be used only to seed legacy migration/codec coverage.
func saveStateAt(path string, state *stateFile) error {
	store, err := zone.OpenBoltStore(path, 0o600)
	if err != nil {
		return err
	}
	defer store.Close()
	return store.SaveNetworkAndMetaJSON(cliMetaKey, stateMetaFromState(state), state.Network)
}

func stateMetaFromState(state *stateFile) stateMeta {
	if state == nil {
		return stateMeta{}
	}
	return stateMeta{
		ManagedZone:       state.ManagedZone,
		IdentityKeyPath:   state.IdentityKeyPath,
		RootPrivateKey:    state.RootPrivateKey,
		ZonePrivateKey:    state.ZonePrivateKey,
		SyncPeers:         state.SyncPeers,
		PeerCleanups:      state.PeerCleanups,
		IPsecTransportKey: state.IPsecTransportKey,
		RoutingReconcile:  state.RoutingReconcile,
		FirewallReconcile: state.FirewallReconcile,
		EndpointACLs:      state.EndpointACLs,
		BirdInstances:     state.BirdInstances,
	}
}

// loadLegacyStateAt reads only the retired zone:* plus _meta/cli_state schema.
// Current partitioned databases must be read through the typed owner loaders.
func loadLegacyStateAt(path string) (*stateFile, error) {
	store, err := zone.OpenBoltStore(path, 0o600)
	if err != nil {
		return nil, err
	}
	network, err := store.LoadNetwork()
	if err != nil {
		_ = store.Close()
		return nil, err
	}
	var meta stateMeta
	if err := store.LoadMetaJSON(cliMetaKey, &meta); err != nil {
		_ = store.Close()
		return nil, err
	}
	if err := store.Close(); err != nil {
		return nil, err
	}
	return &stateFile{
		ManagedZone:       meta.ManagedZone,
		IdentityKeyPath:   meta.IdentityKeyPath,
		RootPrivateKey:    meta.RootPrivateKey,
		ZonePrivateKey:    meta.ZonePrivateKey,
		Network:           network,
		SyncPeers:         meta.SyncPeers,
		PeerCleanups:      meta.PeerCleanups,
		IPsecTransportKey: meta.IPsecTransportKey,
		RoutingReconcile:  meta.RoutingReconcile,
		FirewallReconcile: meta.FirewallReconcile,
		EndpointACLs:      meta.EndpointACLs,
		BirdInstances:     meta.BirdInstances,
	}, nil
}
