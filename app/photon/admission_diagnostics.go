package main

import (
	"fmt"
	"os"

	inspecttext "github.com/HiggsNet/photon/internal/inspect/text"
	"github.com/HiggsNet/photon/pkg/core/gossip"
)

func debugAdmission() error {
	rt, err := NewAppContext()
	if err != nil {
		return err
	}
	if diagnosis, ok, err := admissionStatusViaControl(rt); err != nil {
		return err
	} else if ok {
		fmt.Fprintln(os.Stdout, "daemon: online")
		return inspecttext.WriteAdmissionDiagnosis(os.Stdout, diagnosis)
	}
	common, _, err := loadOfflineOwnerViews(rt)
	if err != nil {
		return err
	}
	if common.State == nil {
		return fmt.Errorf("common state owner is not initialized")
	}
	fmt.Fprintln(os.Stdout, "source: checkpoint (daemon offline; last-known gossip runtime)")
	diagnosis := gossip.DiagnoseAutoJoinAdmission(common.State, common.Gossip, bootstrapPeerIDs(rt.Config.Bootstrap), rt.Now())
	return inspecttext.WriteAdmissionDiagnosis(os.Stdout, diagnosis)
}
