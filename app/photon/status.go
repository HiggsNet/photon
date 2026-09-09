package main

import (
	"os"

	"github.com/HiggsNet/photon/internal/inspect"
	inspecttext "github.com/HiggsNet/photon/internal/inspect/text"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/routing/bird"
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
	common, runtime, err := loadOfflineOwnerViews(rt)
	if err != nil {
		return err
	}
	return inspecttext.WriteStatus(os.Stdout, statusViewFromOwners(rt, common, runtime, nil, nil, nil, nil, false))
}

func statusViewFromOwners(rt *AppContext, common corestate.View, runtime *linuxRuntimeState, links map[string]linkInstanceState, reconcile *ipsecObservationSummary, birdInstances map[string]*bird.InstanceObservation, health []healthLinkJSON, daemonOnline bool) inspect.StatusView {
	if common.State == nil || runtime == nil {
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
	input.Peers = derivePeerStatuses(verified.ManagedZone, verified.Network, common.Gossip, runtime.PeerCleanups, links, reconcile, rt.Now(), cfg, hasOverlay)
	return inspect.BuildStatus(input)
}

// daemonStatusView is the single operational-status projection shared by the
// local control transport and Observer HTTP. It reads the two state owners
// once and returns a detached canonical inspect DTO.
func daemonStatusView(d *Daemon) inspect.DaemonStatusView {
	if d == nil || d.StateStore == nil || d.StateStore.common == nil {
		return inspect.DaemonStatusView{DaemonOnline: false}
	}
	store := d.StateStore
	store.writeMu.Lock()
	view := store.common.ReadView()
	store.mu.RLock()
	meta := store.metaLocked()
	linkInstances, ipsecReconcile := d.linuxObservation.ipsecSnapshot()
	routingReconcile := d.linuxObservation.routingSnapshot()
	desiredLinks := 0
	lastLinkError := ""
	lastRoutingError := ""
	ipsecLastRunUnix := int64(0)
	routingLastRunUnix := int64(0)
	if routingReconcile != nil {
		lastRoutingError = routingReconcile.LastError
		routingLastRunUnix = routingReconcile.LastRunUnix
	}
	if ipsecReconcile != nil {
		desiredLinks = ipsecReconcile.DesiredLinks
		lastLinkError = ipsecReconcile.LastError
		ipsecLastRunUnix = ipsecReconcile.LastRunUnix
	}
	store.mu.RUnlock()
	store.writeMu.Unlock()
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
	if config := d.currentGossipConfig(); config != nil {
		peerID = config.PeerID
		listenAddr = config.ListenAddr
	}
	return inspect.BuildDaemonStatus(inspect.DaemonStatusInput{
		PeerID:             peerID,
		ManagedZone:        string(view.State.ManagedZone),
		ListenAddr:         listenAddr,
		DaemonOnline:       true,
		StateRevision:      uint64(view.Revision),
		Dirty:              meta.Dirty,
		ReconcileProgress:  meta.ReconcileProgress,
		KnownZones:         knownZones,
		KnownPeers:         knownPeers,
		LinkInstances:      len(linkInstances),
		DesiredLinks:       desiredLinks,
		LastLinkError:      lastLinkError,
		LastRoutingError:   lastRoutingError,
		LastSyncUnix:       lastSyncUnix,
		IPsecLastRunUnix:   ipsecLastRunUnix,
		RoutingLastRunUnix: routingLastRunUnix,
	})
}
