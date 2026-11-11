// Package gossipview builds the platform-neutral Gossip query response.
package gossipview

import (
	"cmp"
	"encoding/hex"
	"encoding/json"
	"maps"
	"net"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corehost "github.com/HiggsNet/photon/pkg/core/host"
	"github.com/HiggsNet/photon/pkg/core/observability"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

type View struct {
	PeerID                  string                 `json:"peer_id"`
	ManagedZone             zone.ZonePath          `json:"managed_zone,omitempty"`
	LocalEndpoints          []gossip.EndpointEntry `json:"local_endpoints,omitempty"`
	LocalEndpointsTruncated bool                   `json:"local_endpoints_truncated,omitempty"`
	ListenAddr              string                 `json:"listen_addr"`
	CatalogRoot             string                 `json:"catalog_root"`
	ZoneCount               int                    `json:"zone_count"`
	MaxDatagramBytes        int                    `json:"max_datagram_bytes"`
	MaxSyncRecords          int                    `json:"max_sync_records"`
	WireVersion             int                    `json:"wire_version"`
	WireCodec               string                 `json:"wire_codec"`
	SampledAt               time.Time              `json:"sampled_at"`
	Peers                   []Peer                 `json:"peers"`
	PeersTruncated          bool                   `json:"peers_truncated,omitempty"`
}

type Peer struct {
	PeerID                string                                     `json:"peer_id"`
	Source                string                                     `json:"source"`
	Authorization         string                                     `json:"authorization"`
	SyncStatus            string                                     `json:"sync_status"`
	ConfiguredAddr        string                                     `json:"configured_addr,omitempty"`
	SelectedAddr          string                                     `json:"selected_addr,omitempty"`
	DiscoveredAddr        string                                     `json:"discovered_addr,omitempty"`
	Endpoints             []Endpoint                                 `json:"endpoints,omitempty"`
	LastSyncUnix          int64                                      `json:"last_sync_unix"`
	BackoffUntilUnix      int64                                      `json:"backoff_until_unix"`
	FailureCount          int                                        `json:"failure_count"`
	LastFailure           *corestate.PeerFailure                     `json:"last_failure,omitempty"`
	LastRelayUnix         int64                                      `json:"last_relay_unix,omitempty"`
	LastSuccessfulAddr    string                                     `json:"last_successful_endpoint,omitempty"`
	ObservedAddr          string                                     `json:"observed_addr,omitempty"`
	ObservedFirstSeenUnix int64                                      `json:"observed_first_seen_unix,omitempty"`
	ObservedLastSeenUnix  int64                                      `json:"observed_last_seen_unix,omitempty"`
	ObservedUntilUnix     int64                                      `json:"observed_until_unix,omitempty"`
	ObservedGraceAddrs    []corestate.ObservedGraceEndpoint          `json:"observed_grace_addrs,omitempty"`
	RejectedDigests       map[zone.ZonePath]corestate.RejectedObject `json:"rejected_digests,omitempty"`
	observability.PeerDiagnostics
}

type Endpoint struct {
	Addr string `json:"addr"`
	gossip.EndpointEntry
	Selected bool `json:"selected,omitempty"`
}

func (view View) Find(id string) (Peer, bool) {
	for _, peer := range view.Peers {
		if peer.PeerID == id {
			return peer, true
		}
	}
	return Peer{}, false
}

// LimitForIPC budgets each endpoint and peer list without changing included entries.
func (view *View) LimitForIPC(count, bytes int) {
	view.Peers, view.PeersTruncated = limitEntries(view.Peers, count, bytes)
	view.LocalEndpoints, view.LocalEndpointsTruncated = limitEntries(view.LocalEndpoints, count, bytes)
}

func limitEntries[T any](entries []T, count, bytes int) ([]T, bool) {
	used := 2
	for i, entry := range entries {
		data, err := json.Marshal(entry)
		if i == count || err != nil || used+len(data)+1 > bytes {
			return entries[:i:i], true
		}
		used += len(data) + 1
	}
	return entries, false
}

func Live(common corestate.View, driver *corehost.GossipDriver, now time.Time) View {
	if driver == nil {
		return Build(common, corehost.GossipDriverConfig{}, "", now)
	}
	var listen string
	if addr := driver.Transport().LocalAddr(); addr != nil {
		listen = addr.String()
	}
	return build(common, driver.GossipConfig(), listen, driver.Observability.Snapshots(now), driver.Gossip.SessionPeers(), now)
}

func Build(common corestate.View, config corehost.GossipDriverConfig, listen string, now time.Time) View {
	return build(common, config, listen, nil, nil, now)
}

func build(common corestate.View, config corehost.GossipDriverConfig, listen string, diagnostics map[string]observability.PeerDiagnostics, active map[string]bool, now time.Time) View {
	view := View{PeerID: config.PeerID, ListenAddr: listen, MaxDatagramBytes: config.MaxDatagramBytes,
		MaxSyncRecords: config.Limits.MaxRecords, WireVersion: gossip.WireVersion, WireCodec: "msgpack", SampledAt: now, Peers: []Peer{}}
	var network *zone.NetworkState
	if common.State != nil {
		network = common.State.Network
	}
	summary := corestate.CatalogSummaryForDigests(corestate.ZoneDigestsAt(network, now))
	view.CatalogRoot, view.ZoneCount = hex.EncodeToString(summary.CatalogRoot), summary.ZoneCount
	discovered := gossip.ExtractPeerEndpointsAt(network, now)
	if common.State != nil {
		view.ManagedZone = common.State.ManagedZone
		view.LocalEndpoints = discovered[view.ManagedZone.String()]
	}
	revoked := network.RevokedZones(now)
	ids := make(map[string]bool)
	for id := range discovered {
		ids[id] = true
	}
	for id := range diagnostics {
		ids[id] = true
	}
	for id := range active {
		ids[id] = true
	}
	if common.Gossip != nil {
		for id := range common.Gossip.Peers {
			ids[id] = true
		}
	}
	for id := range revoked {
		ids[id.String()] = true
	}
	bootstrap := make(map[string]bool)
	for _, id := range config.Discovery.BootstrapPeers {
		ids[id], bootstrap[id] = true, true
	}
	for id := range config.Discovery.Bootstrap {
		ids[id], bootstrap[id] = true, true
	}
	delete(ids, "")
	delete(ids, config.PeerID)
	if common.State != nil {
		delete(ids, common.State.ManagedZone.String())
	}
	for _, id := range slices.SortedFunc(maps.Keys(ids), zone.ComparePaths) {
		var checkpoint corestate.PeerCheckpoint
		if common.Gossip != nil {
			checkpoint = common.Gossip.Peers[id]
		}
		peer := projectPeer(id, checkpoint, diagnostics[id], active[id], network.IsZoneRevoked(zone.ZonePath(id), now), now)
		if peer.Authorization != "revoked" && network != nil && photoncrypto.VerifyChain(network, zone.ZonePath(id), now) == nil {
			peer.Authorization = "verified"
		}
		peer.Source = "discovered"
		addr := config.Discovery.Bootstrap[id]
		if bootstrap[id] {
			peer.Source = "bootstrap"
			if addr != nil {
				peer.ConfiguredAddr = addr.String()
			}
		} else if peer.ObservedAddr != "" {
			peer.Source = "observed"
		}
		if peer.Authorization != "revoked" {
			peer.setEndpoints(discovered[id], corehost.GossipDiscoveryAddresses(discovered[id], addr, config.Discovery.SourceOrder), now)
		}
		view.Peers = append(view.Peers, peer)
	}
	return view
}

func projectPeer(id string, checkpoint corestate.PeerCheckpoint, diagnostics observability.PeerDiagnostics, active, revoked bool, now time.Time) Peer {
	peer := Peer{PeerID: id, Authorization: "unverified", LastSyncUnix: checkpoint.LastSyncUnix, BackoffUntilUnix: checkpoint.BackoffUntilUnix,
		FailureCount: checkpoint.FailureCount, LastRelayUnix: checkpoint.LastRelayUnix, LastSuccessfulAddr: checkpoint.LastSuccessfulEndpoint,
		ObservedLastSeenUnix: checkpoint.ObservedLastSeenUnix, PeerDiagnostics: diagnostics}
	if checkpoint.ObservedUntilUnix > now.Unix() {
		peer.ObservedAddr = checkpoint.ObservedEndpoint
		peer.ObservedFirstSeenUnix = checkpoint.ObservedFirstSeenUnix
		peer.ObservedUntilUnix = checkpoint.ObservedUntilUnix
	}
	if revoked {
		peer.Authorization, peer.SyncStatus = "revoked", "revoked"
	} else {
		switch {
		case active:
			peer.SyncStatus = "syncing"
		case corehost.GossipBackoffRemaining(checkpoint, now) > 0:
			peer.SyncStatus = "backoff"
		case checkpoint.LastFailure != nil:
			peer.SyncStatus = "retry_pending"
		case checkpoint.LastSyncUnix != 0:
			peer.SyncStatus = "synced"
		default:
			peer.SyncStatus = "waiting"
		}
	}
	if failure := checkpoint.LastFailure; failure != nil {
		peer.LastFailure = &corestate.PeerFailure{Code: corestate.PeerFailureCode(bounded(string(failure.Code))), Message: bounded(failure.Message), AtUnix: failure.AtUnix}
	}
	for _, endpoint := range checkpoint.ObservedGraceEndpoints {
		if endpoint.UntilUnix > now.Unix() {
			peer.ObservedGraceAddrs = append(peer.ObservedGraceAddrs, endpoint)
		}
	}
	for path, rejected := range checkpoint.RejectedObjects {
		if rejected.UntilUnix > now.Unix() {
			if peer.RejectedDigests == nil {
				peer.RejectedDigests = make(map[zone.ZonePath]corestate.RejectedObject)
			}
			rejected.RootHash = slices.Clone(rejected.RootHash)
			peer.RejectedDigests[path] = rejected
		}
	}
	peer.ActivePullState, peer.ActivePullLastEvent = bounded(diagnostics.ActivePullState), bounded(diagnostics.ActivePullLastEvent)
	if stats := peer.ObjectPullStats; stats != nil {
		stats.LastZone = bounded(stats.LastZone)
		if stats.LastFailure != nil {
			stats.LastFailure.Message = bounded(stats.LastFailure.Message)
		}
	}
	return peer
}

func bounded(value string) string {
	if len(value) > 256 {
		value = value[:256]
		for !utf8.ValidString(value) {
			value = value[:len(value)-1]
		}
	}
	return value
}

func (peer *Peer) setEndpoints(signed []gossip.EndpointEntry, candidates []*net.UDPAddr, now time.Time) {
	if len(signed) > 0 && len(candidates) > 0 {
		peer.SelectedAddr = candidates[0].String()
	}
	if peer.SelectedAddr == "" && peer.ObservedUntilUnix > now.Unix() {
		peer.SelectedAddr = peer.ObservedAddr
	}
	if peer.SelectedAddr == "" {
		peer.SelectedAddr = peer.ConfiguredAddr
	}
	add := func(addr string, entry gossip.EndpointEntry) {
		if addr == "" {
			return
		}
		for _, existing := range peer.Endpoints {
			if existing.Addr == addr && existing.Source == entry.Source {
				return
			}
		}
		if entry.Protocol == "" {
			entry.Protocol = "udp"
		}
		peer.Endpoints = append(peer.Endpoints, Endpoint{Addr: addr, EndpointEntry: entry, Selected: addr == peer.SelectedAddr})
	}
	for _, entry := range signed {
		if addr, err := entry.UDPAddr(); err == nil {
			if peer.DiscoveredAddr == "" {
				peer.DiscoveredAddr = addr.String()
			}
			if entry.Source == "" {
				entry.Source = "signed"
			}
			add(addr.String(), entry)
		}
	}
	add(peer.ConfiguredAddr, gossip.EndpointEntry{Source: "bootstrap"})
	source := peer.ObservedSource
	if source == "" {
		source = "observed"
	}
	add(peer.ObservedAddr, gossip.EndpointEntry{Source: source})
	for _, endpoint := range peer.ObservedGraceAddrs {
		add(endpoint.Endpoint, gossip.EndpointEntry{Source: "observed_grace"})
	}
	slices.SortStableFunc(peer.Endpoints, func(a, b Endpoint) int {
		if a.Selected != b.Selected {
			if a.Selected {
				return -1
			}
			return 1
		}
		return cmp.Or(strings.Compare(a.Source, b.Source), strings.Compare(a.Addr, b.Addr))
	})
}

func FormatTime(unix int64) string {
	if unix == 0 {
		return "never"
	}
	return time.Unix(unix, 0).UTC().Format(time.RFC3339)
}
