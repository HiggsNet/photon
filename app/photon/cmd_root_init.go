package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"github.com/HiggsNet/photon/internal/photonlinux"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

func runRootInit() error {
	config, err := loadAppConfig()
	if err != nil {
		return err
	}
	if err := checkRootInitViaControl(config); err != nil {
		return err
	}
	rootPub, err := initializeRootState(config)
	if err != nil {
		return err
	}
	fmt.Printf("initialized root in %s\n", config.StatePath)
	fmt.Printf("root public key: %s\n", base64.StdEncoding.EncodeToString(rootPub))
	return nil
}

func initializeRootState(config *appConfig) (ed25519.PublicKey, error) {
	rootPub, rootPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	rootAuthority := photoncrypto.ConfiguredRootAuthority(rootPub)
	ns := zone.NewNetworkState()
	ns.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, rootAuthority)
	store, err := corestate.OpenBoltStore(config.StatePath, 0o600, daemonBoltLockTimeout)
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
