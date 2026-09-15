package main

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

func rootPubkey() error {
	rt, err := NewAppContext()
	if err != nil {
		return err
	}
	if publicKey, ok, err := readCanonicalViewViaControl[ed25519.PublicKey](rt, controlRequest{Method: "root_public_key"}); err != nil {
		return err
	} else if ok {
		if len(publicKey) == 0 {
			return errors.New("root authority has no public key")
		}
		fmt.Println(formatPublicKey(publicKey))
		return nil
	}
	common, _, err := loadOfflineOwnerViews(rt)
	if err != nil {
		return err
	}
	if common.State == nil || common.State.Network == nil {
		return errors.New("common state is not initialized")
	}
	root := common.State.Network.Zones[zone.RootZone]
	if root == nil || root.Authority == nil || len(root.Authority.Keys) == 0 {
		return errors.New("root authority has no public key")
	}
	fmt.Println(formatPublicKey(root.Authority.Keys[0].Key))
	return nil
}
