package host

import (
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

// AdmissionDiagnosis derives auto-join status from the current common view.
// It needs neither a running transport nor an active event loop.
func (driver *GossipDriver) AdmissionDiagnosis(now time.Time) gossip.AdmissionDiagnosis {
	if driver == nil || driver.gossipState == nil {
		return gossip.AdmissionDiagnosis{}
	}
	return driver.AdmissionDiagnosisFromView(driver.gossipState.ReadView(), now)
}

// AdmissionDiagnosisFromView uses the verified state already sampled by the caller.
func (driver *GossipDriver) AdmissionDiagnosisFromView(view corestate.View, now time.Time) gossip.AdmissionDiagnosis {
	config := driver.GossipConfig()
	bootstrap := config.Discovery.BootstrapPeers
	for peer := range config.Discovery.Bootstrap {
		bootstrap = append(bootstrap, peer)
	}
	return gossip.DiagnoseAutoJoinAdmission(view.State, view.Gossip, bootstrap, now)
}
