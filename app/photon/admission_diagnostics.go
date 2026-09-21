package main

import (
	"fmt"
	"os"
	"time"

	inspecttext "github.com/HiggsNet/photon/internal/inspect/text"
	"github.com/HiggsNet/photon/pkg/core/gossip"
)

func debugAdmission() error {
	config, err := loadAppConfig()
	if err != nil {
		return err
	}
	if diagnosis, ok, err := admissionStatusViaControl(config, false); err != nil {
		return err
	} else if ok {
		fmt.Fprintln(os.Stdout, "daemon: online")
		return inspecttext.WriteAdmissionDiagnosis(os.Stdout, diagnosis)
	}
	common, _, err := loadOfflineOwnerViews(config)
	if err != nil {
		return err
	}
	if common.State == nil {
		return fmt.Errorf("common state owner is not initialized")
	}
	fmt.Fprintln(os.Stdout, "source: checkpoint (daemon offline; last-known gossip runtime)")
	diagnosis := gossip.DiagnoseAutoJoinAdmission(common.State, common.Gossip, bootstrapPeerIDs(config.Bootstrap), time.Now())
	return inspecttext.WriteAdmissionDiagnosis(os.Stdout, diagnosis)
}
