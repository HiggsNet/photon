package host

import (
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
)

// AdmissionDiagnosis derives auto-join status from the current common view.
// It needs neither a running transport nor an active event loop.
func (driver *GossipDriver) AdmissionDiagnosis(now time.Time) gossip.AdmissionDiagnosis {
	if driver == nil || driver.gossipState == nil {
		return gossip.AdmissionDiagnosis{}
	}
	view := driver.gossipState.ReadView()
	config := driver.GossipConfig()
	bootstrap := config.Discovery.BootstrapPeers
	for peer := range config.Discovery.Bootstrap {
		bootstrap = append(bootstrap, peer)
	}
	return gossip.DiagnoseAutoJoinAdmission(view.State, view.Gossip, bootstrap, now)
}
