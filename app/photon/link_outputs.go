package main

import (
	"cmp"
	"maps"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"

	photonstate "github.com/HiggsNet/photon/internal/state"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

type ipsecChildSession struct {
	ikeName  string
	xfrmIfID uint32
}

// linkConsumerInputsEqual ignores diagnostics that cannot affect routing or
// firewall policy. Rotation phase is separate from LinkOutput but controls
// BIRD's old/staged interface costs even when both interfaces stay unchanged.
func linkConsumerInputsEqual(previous map[string]ipsec.LinkInstance, previousSummary *ipsecObservationSummary, current map[string]ipsec.LinkInstance, currentSummary *ipsecObservationSummary) bool {
	if !maps.EqualFunc(previous, current, func(a, b ipsec.LinkInstance) bool {
		return a.RotatePhase == b.RotatePhase
	}) {
		return false
	}
	return slices.EqualFunc(buildLinkOutputs(previous, previousSummary), buildLinkOutputs(current, currentSummary), func(a, b photonstate.LinkOutput) bool {
		a.LastTransition, b.LastTransition = 0, 0
		a.Endpoint, b.Endpoint = "", ""
		a.Readiness.Session, b.Readiness.Session = "", ""
		return a == b
	})
}

// buildLinkOutputs projects provider-owned runtime state into the common
// Babel-facing consumer contract. It deliberately carries no owner, SA name,
// action, rotate phase, or other lifecycle input.
func buildLinkOutputs(instances map[string]ipsec.LinkInstance, reconcile *ipsecObservationSummary) []photonstate.LinkOutput {
	desired := make(map[string][]photonstate.DesiredLinkObservation)
	installedSessions := make(map[ipsecChildSession]string)
	if reconcile != nil {
		for _, item := range reconcile.Desired {
			desired[item.InstanceID] = append(desired[item.InstanceID], item)
		}
		for _, sa := range reconcile.ActualSAs {
			if sa.Name != "" && sa.XFRMIfID != 0 && strings.EqualFold(sa.ChildState, "INSTALLED") {
				installedSessions[ipsecChildSession{sa.Name, sa.XFRMIfID}] = photonstate.LinkReadyReady
			}
		}
	}
	ids := sortedLinkInstanceIDs(instances)
	out := make([]photonstate.LinkOutput, 0, len(ids)*2)
	for _, id := range ids {
		inst := instances[id]
		wants := desired[id]
		if len(wants) == 0 {
			wants = []photonstate.DesiredLinkObservation{{}}
		}
		for i, want := range wants {
			base := newIPsecLinkOutput(inst, want)
			// The SA snapshot precedes apply. A single runtime just put back into
			// connecting may have replaced the SA that was in that snapshot.
			// Staging preserves the old runtime, so check its own SA separately.
			if inst.ActualState != ipsec.LinkStateConnecting || inst.StagedInterfaceName != "" {
				base.Readiness.Session = cmp.Or(installedSessions[ipsecChildSession{inst.IKEName, inst.XFRMIfID}], photonstate.LinkReadyNotReady)
			}
			if len(wants) > 1 && base.PathKey == "" {
				base.ID += "#path-" + strconv.Itoa(i)
			}
			if inst.StagedInterfaceName != "" {
				// During rotate the current runtime must be projected only from its
				// live observation. The desired addresses may already describe
				// the staged generation and must not be guessed onto the old link.
				base.InterfaceName = inst.InterfaceName
				base.LocalAddr = inst.LocalTunnelAddr
				base.PeerAddr = inst.PeerTunnelAddr
				base.Readiness.Interface = interfaceReadiness(base.InterfaceName, base.State)
			}
			out = append(out, base)
			if i != 0 || inst.StagedInterfaceName == "" {
				continue
			}
			staged := base
			staged.ID = cmp.Or(inst.LinkID, inst.ID, want.LinkID, want.InstanceID) + "#" + photonstate.LinkRuntimeStaged
			staged.InterfaceName = inst.StagedInterfaceName
			staged.LocalAddr = inst.StagedLocalTunnelAddr
			staged.PeerAddr = inst.StagedPeerTunnelAddr
			staged.Generation = inst.StagedGeneration
			staged.RuntimeRole = photonstate.LinkRuntimeStaged
			staged.Endpoint = ""
			staged.Readiness.Session = cmp.Or(installedSessions[ipsecChildSession{inst.StagedIKEName, inst.StagedXFRMIfID}], photonstate.LinkReadyNotReady)
			staged.Readiness.Interface = interfaceReadiness(staged.InterfaceName, staged.State)
			out = append(out, staged)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func newIPsecLinkOutput(inst ipsec.LinkInstance, desired photonstate.DesiredLinkObservation) photonstate.LinkOutput {
	id := cmp.Or(inst.LinkID, desired.LinkID, inst.ID, desired.InstanceID)
	iface := cmp.Or(inst.InterfaceName, desired.InterfaceName)
	local := inst.LocalTunnelAddr
	if !local.IsValid() {
		local = parseScopedAddr(desired.LocalTunnelAddr)
	}
	peer := inst.PeerTunnelAddr
	if !peer.IsValid() {
		peer = parseScopedAddr(desired.PeerTunnelAddr)
	}
	netns := cmp.Or(scopedNetNS(desired.LocalTunnelAddr), scopedNetNS(desired.PeerTunnelAddr))
	return photonstate.LinkOutput{
		ID:            id,
		GroupID:       cmp.Or(inst.GroupID, desired.GroupID),
		PeerZone:      cmp.Or(inst.PeerZone, desired.PeerZone),
		Provider:      cmp.Or(inst.TransportKind, ipsec.ProviderStrongSwan),
		PathKey:       cmp.Or(inst.PathKey, desired.PathKey),
		NetNS:         netns,
		InterfaceName: iface,
		LocalAddr:     local,
		PeerAddr:      peer,
		Generation:    inst.RemoteGeneration,
		RuntimeRole:   photonstate.LinkRuntimeActive,
		State:         inst.ActualState,
		Readiness: photonstate.LinkReadiness{
			Session:   photonstate.LinkReadyNotReady,
			Interface: interfaceReadiness(iface, inst.ActualState),
			Routing:   photonstate.LinkReadyUnknown,
			Health:    photonstate.LinkReadyUnknown,
		},
		Endpoint:       cmp.Or(inst.Endpoint, desired.Endpoint),
		LastTransition: inst.LastTransition,
	}
}

func parseScopedAddr(value string) netip.Addr {
	addr, _ := netip.ParseAddr(stripScope(value))
	return addr
}

func interfaceReadiness(iface, state string) string {
	if iface != "" && state != "" && state != "removing" && state != "failed" {
		return photonstate.LinkReadyReady
	}
	return photonstate.LinkReadyNotReady
}
