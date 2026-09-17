package main

import (
	"crypto/ed25519"
	"fmt"
	"github.com/HiggsNet/photon/internal/photonlinux"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

func runRootInit() error {
	rt, err := NewAppContext()
	if err != nil {
		return err
	}
	if rootPub, controlled, err := initRootViaControl(rt); err != nil {
		return err
	} else if controlled {
		fmt.Printf("initialized root via daemon in %s\n", rt.StatePath)
		fmt.Printf("root public key: %s\n", formatPublicKey(rootPub))
		return nil
	}
	rootPub, err := initializeRootState(rt)
	if err != nil {
		return err
	}
	fmt.Printf("initialized root in %s\n", rt.StatePath)
	fmt.Printf("root public key: %s\n", formatPublicKey(rootPub))
	return nil
}

func initializeRootState(rt *AppContext) (ed25519.PublicKey, error) {
	rootPub, rootPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	rootAuthority := photoncrypto.ConfiguredRootAuthority(rootPub)
	ns := zone.NewNetworkState()
	ns.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, rootAuthority)
	store, err := corestate.OpenBoltStore(rt.StatePath, 0o600, daemonBoltLockTimeout)
	if err != nil {
		return nil, err
	}
	defer store.Close()
	candidate := &corestate.CommitCandidate{Verified: &corestate.VerifiedState{
		ManagedZone:          zone.RootZone,
		Network:              ns,
		TrustedRootPublicKey: append(ed25519.PublicKey(nil), rootPub...),
		RootPrivateKey:       append(ed25519.PrivateKey(nil), rootPriv...),
	}}
	if err := initializeStateDB(store, candidate, 0, &photonlinux.LinuxState{}); err != nil {
		return nil, err
	}
	return rootPub, nil
}
