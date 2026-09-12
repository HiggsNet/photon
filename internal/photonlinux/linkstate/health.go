// Package linkstate projects Linux link runtime outputs for common consumers.
package linkstate

import (
	"strings"

	photonstate "github.com/HiggsNet/photon/internal/state"
	"github.com/HiggsNet/photon/pkg/health"
)

// HealthTargets derives probe policy inputs from provider-neutral link
// outputs. Platform execution remains owned by photonlinux healthprobe.
func HealthTargets(outputs []photonstate.LinkOutput, localZone string) []health.ProbeTarget {
	targets := make([]health.ProbeTarget, 0, len(outputs))
	for _, output := range outputs {
		if !output.LocalAddr.IsValid() || !output.PeerAddr.IsValid() {
			continue
		}
		probeRole := output.RuntimeRole
		if output.RuntimeRole == photonstate.LinkRuntimeActive {
			probeRole = "active"
			if hasStagedOutput(outputs, output.ID) {
				probeRole = "old"
			}
		}
		target := health.ProbeTarget{
			InstanceID:      output.ID,
			GroupID:         output.GroupID,
			PeerZone:        string(output.PeerZone),
			LocalZone:       localZone,
			Overlay:         output.GroupID,
			NetNS:           output.NetNS,
			InterfaceName:   output.InterfaceName,
			UnderlayFamily:  photonstate.LinkPathFamily(output.PathKey),
			Generation:      output.Generation,
			ProbeRole:       probeRole,
			State:           output.State,
			LocalTunnelAddr: output.LocalAddr,
			PeerTunnelAddr:  output.PeerAddr,
		}
		if probeRole != "active" {
			target.ProbeID = ProbeID(output.ID, probeRole)
		}
		if output.RuntimeRole == photonstate.LinkRuntimeStaged {
			target.InstanceID = strings.TrimSuffix(output.ID, "#"+photonstate.LinkRuntimeStaged)
			target.ProbeID = ProbeID(target.InstanceID, "staged")
			target.Staged = true
		}
		targets = append(targets, target)
	}
	return targets
}

// ProbeID identifies an active, old, or staged probe for one logical link.
func ProbeID(instanceID, role string) string {
	if role == "" || role == "active" {
		return instanceID
	}
	return instanceID + "#" + role
}

func hasStagedOutput(outputs []photonstate.LinkOutput, linkID string) bool {
	for _, output := range outputs {
		if output.ID == ProbeID(linkID, photonstate.LinkRuntimeStaged) {
			return true
		}
	}
	return false
}
