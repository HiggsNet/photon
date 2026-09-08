package main

import (
	"context"
	"slices"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	"github.com/HiggsNet/photon/pkg/core/gossip"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/routing/bird"
	photonservice "github.com/HiggsNet/photon/pkg/service"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func (d *DaemonService) setState(state *stateFile) {
	d.replaceCommittedState(state)
}

func (sr *SyncRuntime) publishIPsecRecords(state *stateFile) error {
	changed, err := sr.publishIPsecRecordsInState(state)
	if err != nil || !changed {
		return err
	}
	if err := sr.saveStateSnapshotAtRevision(state, 0); err != nil {
		return err
	}
	if sr != nil && state != nil {
		sr.logger().Debug("ipsec", "publish_saved", map[string]any{"managed_zone": state.ManagedZone})
	}
	return nil
}

func (d *DaemonService) recordBirdHealthObservationUnavailable(netnsName string, overlays []string) {
	if d == nil || d.StateStore == nil {
		return
	}
	readCommittedForTest(d.StateStore, func(state *stateFile) {
		d.recordBirdHealthObservationUnavailableForState(state, netnsName, overlays)
	})
}

func (d *DaemonService) recordBirdHealthObservation(netnsName string, overlays []string, observed *bird.BirdObservedState) {
	if d == nil || d.StateStore == nil {
		return
	}
	readCommittedForTest(d.StateStore, func(state *stateFile) {
		d.recordBirdHealthObservationForState(state, netnsName, overlays, observed)
	})
}

func (d *DaemonService) completeSyncSession(session *SyncSession, networkChanged bool) {
	if session == nil {
		return
	}
	peerID := session.PeerID
	d.recordSyncPeerState(peerID, "peer_sync", func(state *stateFile) {
		recordPeerSyncAt(state, peerID, session.lastError, d.Sync.now())
	})
	d.completeSyncSessionAfterPeerState(session, networkChanged)
}

func xfrmLinkStateMatchesCandidate(state ipsec.XFRMLinkState, spec ipsec.TransportLinkSpec) bool {
	d := &DaemonService{}
	matches, _ := d.xfrmLinkStateMatchReason(state, spec)
	return matches
}

func (d *DaemonService) firewallReconcileInterval() time.Duration {
	if d == nil || d.Sync == nil || d.Sync.App == nil || d.Sync.App.Config == nil || len(firewallInstancesEnabled(d.Sync.App.Config)) == 0 {
		return 0
	}
	return defaultFirewallReconcileInterval
}

func nextFirewallReconcileTime(now time.Time, interval time.Duration) time.Time {
	if interval <= 0 {
		return time.Time{}
	}
	return now.Add(interval)
}

func assignIPAMWithRuntime(rt *Runtime, path zone.ZonePath, prefix string, assignedTo zone.ZonePath, shared bool) error {
	return assignIPAMWithRuntimeTag(rt, path, prefix, assignedTo, shared, "")
}

func revokeIPAMAssignmentWithRuntime(rt *Runtime, path zone.ZonePath, prefix string) error {
	return revokeIPAMAssignmentWithRuntimeTo(rt, path, prefix, "")
}

func pullObjectTCP(addr string, req *gossip.ObjectPullRequest) (*gossip.ObjectPullResponse, error) {
	return pullObjectTCPForPeer("", addr, req)
}

func pullObjectTCPForPeer(peerID, addr string, req *gossip.ObjectPullRequest) (*gossip.ObjectPullResponse, error) {
	return pullObjectTCPForPeerUntil(peerID, addr, req, time.Time{})
}

func objectPullLookup(getState func() *stateFile) func(*gossip.ObjectPullRequest) *gossip.ObjectPullResponse {
	return func(req *gossip.ObjectPullRequest) *gossip.ObjectPullResponse {
		response := objectPullResponseFromState(getState(), req, time.Now())
		logObjectPullSnapshot(req, response)
		return response
	}
}

func tryObjectPullTCP(state *stateFile, config *syncConfigFile, peerID string, path zone.ZonePath) (*gossip.ZoneSnapshot, error) {
	return tryObjectPullTCPUntil(state, config, peerID, path, time.Time{})
}

func derivePeerStatus(state *stateFile, peerID string, peerZone zone.ZonePath, now time.Time, cfg inspect.PeerLifecycleConfig) inspect.PeerStatusInfo {
	if state == nil {
		return inspect.BuildPeerLifecycleStatus(inspect.PeerLifecycleInput{PeerID: peerID, PeerZone: peerZone, StateAvailable: false, Now: now, Config: cfg})
	}
	return inspect.BuildPeerLifecycleStatus(peerLifecycleInputFromState(state, peerID, peerZone, now, cfg, false))
}

func peerLifecycleCleanupZones(state *stateFile, now time.Time, cfg inspect.PeerLifecycleConfig) []zone.ZonePath {
	if state == nil {
		return nil
	}
	peers := derivePeerStatuses(state, now, inspect.NormalizePeerLifecycleConfig(cfg), hasIPsecConfig(state))
	seen := make(map[zone.ZonePath]bool)
	var out []zone.ZonePath
	for _, peer := range peers {
		if inspect.PeerStatusRequiresCleanup(peer) && !seen[peer.Zone] {
			seen[peer.Zone] = true
			out = append(out, peer.Zone)
		}
	}
	slices.Sort(out)
	return out
}

func UpdateRevocationLayerStatus(impact *inspect.RevocationImpact, layer string, status, reason, errStr string, now time.Time) {
	if impact == nil || impact.Layers == nil {
		return
	}
	entry := impact.Layers[layer]
	if entry == nil {
		entry = &inspect.RevocationLayerStatus{}
		impact.Layers[layer] = entry
	}
	entry.Status, entry.Reason, entry.Error, entry.UnixTime = status, reason, errStr, now.Unix()
}

func publishSOCKS5ServiceWithRuntime(rt *Runtime, region, address string, port uint16) error {
	return publishSOCKS5EndpointsWithRuntime(rt, []photonservice.SOCKS5Endpoint{{Region: region, Address: address, Port: port}})
}

func (d *DaemonService) executeSyncActions(ctx context.Context, session *SyncSession, actions []SyncAction) bool {
	return d.executeSyncActionsWithMutations(ctx, session, actions, nil)
}

func recordPeerSync(state *stateFile, peerID string, err error) {
	recordPeerSyncAt(state, peerID, err, timeNow())
}

func formatLastSuccess(peerState syncPeerState) string {
	if peerState.LastSyncUnix == 0 {
		return "never"
	}
	return formatUnixTime(peerState.LastSyncUnix)
}
