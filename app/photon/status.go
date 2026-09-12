package main

import (
	"os"

	"github.com/HiggsNet/photon/internal/inspect"
	inspecttext "github.com/HiggsNet/photon/internal/inspect/text"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/routing/bird"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func showStatus() error {
	rt, err := NewAppContext()
	if err != nil {
		return err
	}
	if view, online, err := readCanonicalViewViaControl[inspect.StatusView](rt, controlRequest{Method: "status_view"}); err != nil {
		return err
	} else if online {
		return inspecttext.WriteStatus(os.Stdout, view)
	}
	common, _, err := loadOfflineOwnerViews(rt)
	if err != nil {
		return err
	}
	return inspecttext.WriteStatus(os.Stdout, statusViewFromOwners(rt, common, nil, nil, nil, nil, false))
}

func statusViewFromOwners(rt *AppContext, common corestate.View, links map[string]ipsec.LinkInstance, reconcile *ipsecObservationSummary, birdInstances map[string]*bird.InstanceObservation, health []inspect.HealthSample, daemonOnline bool) inspect.StatusView {
	if common.State == nil {
		return inspect.BuildStatus(inspect.StatusInput{DaemonOnline: daemonOnline})
	}
	verified := common.State
	var bootstrap []syncConfigPeer
	if rt != nil && rt.Config != nil {
		bootstrap = rt.Config.Bootstrap
	}
	input := inspect.StatusInput{
		DaemonOnline:   daemonOnline,
		GossipSource:   "checkpoint",
		PlatformSource: "unavailable",
		ManagedZone:    verified.ManagedZone,
		Admission:      diagnoseAutoJoinAdmission(verified, common.Gossip, bootstrap, rt.Now()),
	}
	if daemonOnline {
		input.GossipSource = "runtime"
		input.PlatformSource = "runtime"
		input.Links = buildStoredLinkInspection(rt, links, reconcile, birdInstances, health).Inspection
	}
	cfg := inspect.PeerLifecycleConfig{}
	hasOverlay := false
	if rt != nil && rt.Config != nil {
		cfg = rt.Config.PeerLifecycle
		hasOverlay = len(rt.Config.IPsec.LinkGroups) > 0
	}
	input.Peers = derivePeerStatuses(verified.ManagedZone, verified.Network, common.Gossip, links, reconcile, rt.Now(), cfg, hasOverlay)
	return inspect.BuildStatus(input)
}

// daemonStatusView is the single operational-status projection shared by the
// local control transport and Observer HTTP. It combines a common view with
// current Linux observations and returns a detached canonical inspect DTO.
func daemonStatusView(d *Daemon) inspect.DaemonStatusView {
	if d == nil || d.State == nil {
		return inspect.DaemonStatusView{DaemonOnline: false}
	}
	store := d.State
	view := store.Common.ReadView()
	linkInstances, ipsecReconcile := d.linuxObservation.ipsecSnapshot()
	routingReconcile := d.linuxObservation.routingSnapshot()
	desiredLinks := 0
	var lastLinkFailure error
	var lastRoutingFailure error
	ipsecLastRunUnix := int64(0)
	routingLastRunUnix := int64(0)
	if routingReconcile != nil {
		lastRoutingFailure = routingReconcile.LastFailure
		routingLastRunUnix = routingReconcile.LastRunUnix
	}
	if ipsecReconcile != nil {
		desiredLinks = ipsecReconcile.DesiredLinks
		lastLinkFailure = ipsecReconcile.LastFailure
		ipsecLastRunUnix = ipsecReconcile.LastRunUnix
	}
	if view.State == nil {
		return inspect.DaemonStatusView{DaemonOnline: false}
	}
	knownZones := 0
	if view.State.Network != nil {
		knownZones = len(view.State.Network.Zones)
	}
	knownPeers := 0
	lastSyncUnix := int64(0)
	if view.Gossip != nil {
		knownPeers = len(view.Gossip.Peers)
		for _, peer := range view.Gossip.Peers {
			if peer.LastSyncUnix > lastSyncUnix {
				lastSyncUnix = peer.LastSyncUnix
			}
		}
	}
	peerID := ""
	listenAddr := ""
	if d.gossipDriver != nil {
		peerID = d.gossipDriver.GossipConfig().PeerID
	}
	if d.App != nil && d.App.Config != nil {
		listenAddr = d.App.Config.ListenAddr
	}
	return inspect.BuildDaemonStatus(inspect.DaemonStatusInput{
		PeerID:             peerID,
		ManagedZone:        string(view.State.ManagedZone),
		ListenAddr:         listenAddr,
		DaemonOnline:       true,
		StateRevision:      uint64(view.Revision),
		KnownZones:         knownZones,
		KnownPeers:         knownPeers,
		LinkInstances:      len(linkInstances),
		DesiredLinks:       desiredLinks,
		LastLinkFailure:    lastLinkFailure,
		LastRoutingFailure: lastRoutingFailure,
		LastSyncUnix:       lastSyncUnix,
		IPsecLastRunUnix:   ipsecLastRunUnix,
		RoutingLastRunUnix: routingLastRunUnix,
	})
}
