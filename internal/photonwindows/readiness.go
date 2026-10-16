package photonwindows

import (
	"errors"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

const (
	ReadinessStageAddressAssignment   = "address_assignment"
	ReadinessStageAddressAnnouncement = "address_announcement"
)

// ReadinessObservation explains confirmed address admission blockers from the
// current verified view. An empty stage leaves other connection states to the
// existing admission/IKE/Babel observations; only TunnelReady means usable.
type ReadinessObservation struct {
	Stage  string `json:"stage,omitempty"`
	Reason string `json:"reason,omitempty"`
}

func observeLeafReadiness(config *Config, view corestate.View, now time.Time) ReadinessObservation {
	var err error
	if config == nil || view.State == nil || view.State.Network == nil {
		err = errLeafRouteAuthorityUnavailable
	} else if err = photoncrypto.VerifyPinnedRoot(view.State.Network, config.TrustedRootPublicKey); err == nil {
		err = photoncrypto.VerifyChain(view.State.Network, config.ManagedZone, now)
		if err == nil {
			_, _, err = requiredLeafDeviceIntentFromSet(config, currentAuthorizedRouteSet(config, view, now))
		}
	}
	var out ReadinessObservation
	if err != nil {
		out.Reason = boundedObservationText(err.Error())
	}
	switch {
	case errors.Is(err, errLeafHostAssignmentUnavailable):
		out.Stage = ReadinessStageAddressAssignment
	case errors.Is(err, errLeafHostAnnouncementUnavailable):
		out.Stage = ReadinessStageAddressAnnouncement
	}
	return out
}
