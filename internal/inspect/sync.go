package inspect

import (
	"encoding/hex"
	"fmt"
	"sort"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	"github.com/HiggsNet/photon/pkg/core/observability"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

// SyncStatusOptions contains query and transport configuration which is not
// part of the persisted common owner view.
type SyncStatusOptions struct {
	PeerID           string
	ListenAddr       string
	Bootstrap        []PeerBootstrap
	MaxDatagramBytes int
	MaxSyncZones     int
	MaxSyncRecords   int
	Now              time.Time
	Verbose          bool
}

type SyncStatusView struct {
	PeerID          string
	ListenAddr      string
	KnownPeers      int
	KnownZones      int
	LocalRootHex    string
	Limits          SyncLimitsView
	Verbose         bool
	AllowlistSource string
	BootstrapPeers  int
	DiscoveredPeers int
	Bootstrap       []SyncVerbosePeerView
	Discovered      []SyncVerbosePeerView
	Peers           []SyncPeerSummaryView
	Zones           []SyncZoneSummaryView
}

type SyncLimitsView struct {
	MaxDatagramBytes int
	MaxSyncZones     int
	MaxSyncRecords   int
	WireVersion      int
	WireCodec        string
}

type SyncVerbosePeerView struct {
	PeerDebugView
	Addr string
}

type SyncPeerSummaryView struct {
	PeerID      string
	Addr        string
	Status      string
	LastSync    string
	KnownZones  int
	LastFailure *FailureView
	NextRetry   string
}

type SyncZoneSummaryView struct {
	Zone        string
	RootHex     string
	Records     int
	History     int
	Delegations int
	Revocations int
}

// BuildSyncStatus is the single projection from common/checkpoint owners to
// the canonical view shared by control, CLI text and HTTP presenters.
func BuildSyncStatus(common corestate.View, options SyncStatusOptions) SyncStatusView {
	var network *zone.NetworkState
	if common.State != nil {
		network = common.State.Network
	}
	digests := corestate.ZoneDigests(network)
	view := SyncStatusView{
		PeerID:       options.PeerID,
		ListenAddr:   options.ListenAddr,
		KnownPeers:   len(options.Bootstrap),
		KnownZones:   len(digests),
		LocalRootHex: hex.EncodeToString(zonesGlobalRoot(digests)),
		Limits: SyncLimitsView{
			MaxDatagramBytes: options.MaxDatagramBytes,
			MaxSyncZones:     options.MaxSyncZones,
			MaxSyncRecords:   options.MaxSyncRecords,
			WireVersion:      gossip.WireVersion,
			WireCodec:        "msgpack",
		},
		Verbose: options.Verbose,
	}

	discovered := gossip.ExtractPeerEndpoints(network)
	bootstrap := make(map[string]struct{}, len(options.Bootstrap))
	for _, peer := range options.Bootstrap {
		bootstrap[peer.PeerID] = struct{}{}
	}
	if options.Verbose {
		view.AllowlistSource = "bootstrap+discovery"
		view.BootstrapPeers = len(options.Bootstrap)
		for peerID := range discovered {
			if _, ok := bootstrap[peerID]; !ok {
				view.DiscoveredPeers++
			}
		}
		for _, peer := range options.Bootstrap {
			resolved := peer.ResolvedAddr
			if resolved == "" {
				resolved = "-"
			}
			view.Bootstrap = append(view.Bootstrap, buildSyncVerbosePeer(
				peer.PeerID, peer.Addr, resolved, "", syncPeerCheckpoint(common.Gossip, peer.PeerID), options.Now,
			))
		}
		for peerID, entries := range discovered {
			if _, ok := bootstrap[peerID]; ok {
				continue
			}
			addr := "-"
			if len(entries) > 0 {
				addr = fmt.Sprintf("%s:%d", entries[0].Address, entries[0].Port)
			}
			view.Discovered = append(view.Discovered, buildSyncVerbosePeer(
				peerID, "", "", addr, syncPeerCheckpoint(common.Gossip, peerID), options.Now,
			))
		}
	}

	for _, peer := range options.Bootstrap {
		checkpoint := syncPeerCheckpoint(common.Gossip, peer.PeerID)
		peerDebug := buildPeerDebugFromCheckpoint(peer.PeerID, "", peer.Addr, "", checkpoint, observability.PeerDiagnostics{}, options.Now)
		view.Peers = append(view.Peers, SyncPeerSummaryView{
			PeerID: peer.PeerID, Addr: peer.Addr, Status: peerDebug.Status,
			LastSync: peerDebug.LastSuccess, KnownZones: len(digests),
			LastFailure: peerFailureView(checkpoint.LastFailure), NextRetry: peerDebug.NextRetry,
		})
	}
	if network != nil {
		for _, digest := range digests {
			zs := network.Zones[digest.Zone]
			view.Zones = append(view.Zones, SyncZoneSummaryView{
				Zone: string(digest.Zone), RootHex: hex.EncodeToString(digest.RootHash),
				Records: len(zs.Records), History: ZoneHistoryCount(zs),
				Delegations: len(zs.Delegations), Revocations: len(zs.Revocations),
			})
		}
	}

	sort.SliceStable(view.Bootstrap, func(i, j int) bool { return ZonePathLess(view.Bootstrap[i].PeerID, view.Bootstrap[j].PeerID) })
	sort.SliceStable(view.Discovered, func(i, j int) bool { return ZonePathLess(view.Discovered[i].PeerID, view.Discovered[j].PeerID) })
	sort.SliceStable(view.Peers, func(i, j int) bool { return ZonePathLess(view.Peers[i].PeerID, view.Peers[j].PeerID) })
	sort.SliceStable(view.Zones, func(i, j int) bool { return ZonePathLess(view.Zones[i].Zone, view.Zones[j].Zone) })
	return view
}

func buildSyncVerbosePeer(peerID, configuredAddr, resolvedAddr, addr string, checkpoint corestate.PeerCheckpoint, now time.Time) SyncVerbosePeerView {
	return SyncVerbosePeerView{
		PeerDebugView: buildPeerDebugFromCheckpoint(peerID, "", configuredAddr, resolvedAddr, checkpoint, observability.PeerDiagnostics{}, now),
		Addr:          addr,
	}
}

func syncPeerCheckpoint(checkpoint *corestate.GossipCheckpoint, peerID string) corestate.PeerCheckpoint {
	if checkpoint == nil {
		return corestate.PeerCheckpoint{}
	}
	return checkpoint.Peers[peerID]
}
