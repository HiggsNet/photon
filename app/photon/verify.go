package main

import (
	"fmt"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

func verifyChain(path zone.ZonePath) error {
	config, err := loadAppConfig()
	if err != nil {
		return err
	}
	if ok, err := verifyChainViaControl(config, path, false); err != nil {
		return err
	} else if ok {
		fmt.Printf("verified chain for %s\n", path)
		return nil
	}
	common, _, err := loadOfflineOwnerViews(config)
	if err != nil {
		return err
	}
	if common.State == nil || common.State.Network == nil {
		return fmt.Errorf("common state is not initialized")
	}
	configureValidation(common.State.Network)
	if err := photoncrypto.VerifyChain(common.State.Network, path, time.Now()); err != nil {
		return err
	}
	fmt.Printf("verified chain for %s\n", path)
	return nil
}
