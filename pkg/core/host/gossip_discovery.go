package host

import (
	"bytes"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

const (
	GossipObservedPathTTL            = 3 * time.Minute
	GossipObservedPathMigrationGrace = time.Minute
)

// GossipDiscoveryInput is the detached common/driver input used to rebuild
// the in-memory peer address book.
type GossipDiscoveryInput struct {
	LocalPeerID      string
	ManagedZone      zone.ZonePath
	Network          *zone.NetworkState
	Peers            map[string]corestate.PeerCheckpoint
	Bootstrap        map[string]*net.UDPAddr
	BootstrapPeers   []string
	SourceOrder      []string
	verifiedRevision corestate.VerifiedRevision
	observedVerifier *photoncrypto.Verifier
}

// GossipDiscoveryConfig contains the platform-neutral, fixed discovery policy
// selected by the composition root. Verified network and checkpoint data are
// always read from GossipDriver's Store and therefore do not appear here.
type GossipDiscoveryConfig struct {
	Bootstrap      map[string]*net.UDPAddr
	BootstrapPeers []string
	SourceOrder    []string
}

// GossipDiscoveryInput returns one detached discovery view built from the
// GossipDriver's committed common Store.
func (driver *GossipDriver) GossipDiscoveryInput() GossipDiscoveryInput {
	return driver.gossipDiscoveryInput("", true, "")
}

func (driver *GossipDriver) gossipDiscoveryInput(peerID string, records bool, recordPrefix string) GossipDiscoveryInput {
	var input GossipDiscoveryInput
	if driver == nil {
		return input
	}
	config := driver.GossipConfig()
	input.LocalPeerID = config.PeerID
	input.Bootstrap = config.Discovery.Bootstrap
	input.BootstrapPeers = config.Discovery.BootstrapPeers
	input.SourceOrder = config.Discovery.SourceOrder
	if driver.gossipState == nil {
		return input
	}
	var view *corestate.DiscoveryView
	if records {
		view = driver.gossipState.ReadDiscoveryRecords(peerID, recordPrefix)
	} else {
		view = driver.gossipState.ReadPeerAuthorization(peerID)
	}
	if view != nil {
		input.ManagedZone = view.ManagedZone
		input.Network = view.Network
		input.Peers = view.Peers
		input.verifiedRevision = view.Revision
	}
	return input
}

func cloneBootstrapPeers(input map[string]*net.UDPAddr) map[string]*net.UDPAddr {
	out := make(map[string]*net.UDPAddr, len(input))
	for peerID, addr := range input {
		if addr == nil {
			out[peerID] = nil
			continue
		}
		copyAddr := *addr
		copyAddr.IP = append(net.IP(nil), addr.IP...)
		out[peerID] = &copyAddr
	}
	return out
}

const GossipRelayMinInterval = time.Second

// GossipOutboundPeers returns every peer that common gossip may actively
// contact: bootstrap peers, signed endpoints, remembered endpoints and live
// observed paths. The result is detached and de-duplicated.
func GossipOutboundPeers(input GossipDiscoveryInput, now time.Time) []string {
	seen := make(map[string]bool)
	peers := make([]string, 0, len(input.Bootstrap)+len(input.Peers))
	add := func(peerID string) {
		if peerID == "" || peerID == input.LocalPeerID || peerID == input.ManagedZone.String() || seen[peerID] || input.Network.IsZoneRevoked(zone.ZonePath(peerID), now) {
			return
		}
		seen[peerID] = true
		peers = append(peers, peerID)
	}
	for _, peerID := range input.BootstrapPeers {
		add(peerID)
	}
	bootstrap := make([]string, 0, len(input.Bootstrap))
	for peerID := range input.Bootstrap {
		bootstrap = append(bootstrap, peerID)
	}
	sort.Strings(bootstrap)
	for _, peerID := range bootstrap {
		add(peerID)
	}
	discovered := gossip.ExtractPeerEndpointsAt(input.Network, now)
	discoveredIDs := make([]string, 0, len(discovered))
	for peerID := range discovered {
		discoveredIDs = append(discoveredIDs, peerID)
	}
	sort.Strings(discoveredIDs)
	for _, peerID := range discoveredIDs {
		add(peerID)
	}
	observed := make([]string, 0, len(input.Peers))
	for peerID, checkpoint := range input.Peers {
		if !seen[peerID] &&
			(discoveryObservedActive(checkpoint, now) || parseRememberedAddr(checkpoint.LastSuccessfulEndpoint) != nil) &&
			discoveryPeerVerified(input, peerID, now) {
			observed = append(observed, peerID)
		}
	}
	sort.Strings(observed)
	for _, peerID := range observed {
		add(peerID)
	}
	return peers
}

func GossipBackoffRemaining(peer corestate.PeerCheckpoint, now time.Time) time.Duration {
	until := time.Unix(peer.BackoffUntilUnix, 0)
	if peer.BackoffUntilUnix == 0 || !until.After(now) {
		return 0
	}
	return until.Sub(now)
}

// ShouldRelayGossipUpdate applies the common relay-loop and throttling policy.
func ShouldRelayGossipUpdate(peer corestate.PeerCheckpoint, peerID, sourcePeerID, catalogRoot string, now time.Time) (bool, string) {
	switch {
	case peerID == "":
		return false, "empty_peer_id"
	case peerID == sourcePeerID:
		return false, "source_peer"
	case GossipBackoffRemaining(peer, now) > 0:
		return false, "backoff"
	case catalogRoot != "" && peer.LastRelayCatalogRootHex == catalogRoot:
		return false, "relay_root_unchanged"
	case peer.LastRelayUnix != 0 && now.Sub(time.Unix(peer.LastRelayUnix, 0)) < GossipRelayMinInterval:
		return false, "relay_throttled"
	default:
		return true, ""
	}
}

type GossipPeerAddressUpdate struct {
	ObservedPaths  []gossip.ObservedPath
	PreferObserved bool
}

type GossipDiscoveryPlan struct {
	KnownPeerIDs []string
	Revoked      map[zone.ZonePath]bool
	Peers        map[string]GossipPeerAddressUpdate
	Addresses    map[string][]*net.UDPAddr
	Remembered   map[string]*net.UDPAddr
}

// PlanVerifiedObservedCheckpoint validates the peer against verified state
// and returns the loss-tolerant checkpoint update for one authenticated UDP
// source. Invalid or locally managed peers produce no patch.
func PlanVerifiedObservedCheckpoint(input GossipDiscoveryInput, peerID, endpoint string, now time.Time) (corestate.PeerCheckpointPatch, bool) {
	if peerID == "" || endpoint == "" || !discoveryPeerVerified(input, peerID, now) {
		return corestate.PeerCheckpointPatch{}, false
	}
	peer := input.Peers[peerID]
	firstSeen := peer.ObservedFirstSeenUnix
	grace := append([]corestate.ObservedGraceEndpoint(nil), peer.ObservedGraceEndpoints...)
	if peer.ObservedEndpoint != endpoint || firstSeen == 0 || !discoveryObservedActive(peer, now) {
		if discoveryObservedActive(peer, now) && peer.ObservedEndpoint != "" && peer.ObservedEndpoint != endpoint {
			grace = appendObservedGraceEndpoint(grace, peer.ObservedEndpoint, now.Add(GossipObservedPathMigrationGrace), now)
		}
		firstSeen = now.Unix()
	}
	grace = pruneObservedGraceEndpoints(grace, endpoint, now)
	return corestate.PeerCheckpointPatch{
		ObservedEndpoint:  corestate.PatchField[string]{Set: true, Value: endpoint},
		ObservedFirstUnix: corestate.PatchField[int64]{Set: true, Value: firstSeen},
		ObservedLastUnix:  corestate.PatchField[int64]{Set: true, Value: now.Unix()},
		ObservedUntilUnix: corestate.PatchField[int64]{Set: true, Value: now.Add(GossipObservedPathTTL).Unix()},
		ObservedGrace:     corestate.PatchField[[]corestate.ObservedGraceEndpoint]{Set: true, Value: grace},
	}, true
}

// FilterGossipCatalogPage removes the locally managed zone and temporarily
// rejected remote roots using only common verified/checkpoint state.
func FilterGossipCatalogPage(input GossipDiscoveryInput, peerID string, page *corestate.CatalogPage, now time.Time) ([]corestate.ZoneDigest, *corestate.CatalogPage) {
	return corestate.ZoneDigests(input.Network), filterGossipCatalogPage(input.ManagedZone, input.Peers[peerID], page, now)
}

func filterGossipCatalogPage(managedZone zone.ZonePath, peer corestate.PeerCheckpoint, page *corestate.CatalogPage, now time.Time) *corestate.CatalogPage {
	if page == nil || len(page.Entries) == 0 {
		return page
	}
	filtered := *page
	filtered.Entries = make([]corestate.ZoneDigest, 0, len(page.Entries))
	for _, entry := range page.Entries {
		if entry.Zone == managedZone {
			continue
		}
		rejected, ok := peer.RejectedObjects[entry.Zone]
		if ok && bytes.Equal(rejected.RootHash, entry.RootHash) && rejected.UntilUnix != 0 && now.Before(time.Unix(rejected.UntilUnix, 0)) {
			continue
		}
		filtered.Entries = append(filtered.Entries, entry)
	}
	return &filtered
}

// ResolveGossipObjectPullAddress returns the first TCP candidate for callers
// that only display an address. Outbound pulls use the complete candidate list.
func ResolveGossipObjectPullAddress(input GossipDiscoveryInput, peerID string, now time.Time) string {
	addresses := ResolveGossipObjectPullAddresses(input, peerID, now)
	if len(addresses) == 0 {
		return ""
	}
	return addresses[0]
}

// ResolveGossipObjectPullAddresses retains the verified observed paths,
// bootstrap and signed endpoints. TCP and UDP share the numeric endpoint port,
// but a working UDP path does not establish TCP reachability.
func ResolveGossipObjectPullAddresses(input GossipDiscoveryInput, peerID string, now time.Time) []string {
	if peerID == "" || input.Network.IsZoneRevoked(zone.ZonePath(peerID), now) {
		return nil
	}
	var addresses []string
	seen := make(map[string]bool)
	add := func(addr string) {
		if addr != "" && !seen[addr] {
			seen[addr] = true
			addresses = append(addresses, addr)
		}
	}
	peer := input.Peers[peerID]
	if paths, ok := discoveryObservedPaths(input, peerID, peer, now); ok {
		for _, path := range paths {
			add(discoveryTCPAddressFromUDP(path.Addr))
		}
	}
	add(discoveryTCPAddressFromUDP(input.Bootstrap[peerID]))
	for _, entry := range sortedDiscoveryEndpoints(gossip.ExtractPeerEndpointsAt(input.Network, now)[peerID]) {
		udp, err := entry.UDPAddr()
		if err != nil {
			continue
		}
		add(discoveryTCPAddressFromUDP(udp))
	}
	return addresses
}

func discoveryTCPAddressFromUDP(udp *net.UDPAddr) string {
	if udp == nil {
		return ""
	}
	return (&net.TCPAddr{IP: udp.IP, Port: udp.Port, Zone: udp.Zone}).String()
}

// RefreshGossipDiscovery rebuilds the transport's in-memory address book.
func (driver *GossipDriver) RefreshGossipDiscovery(now time.Time, transport *gossip.Transport) error {
	if !driver.gossipDiscoveryAvailable() {
		return ErrGossipDriverStopped
	}
	input := driver.gossipDiscoveryInput("", true, gossip.EndpointRecordKeyPrefix)
	ApplyGossipDiscoveryPlan(transport, PlanGossipDiscovery(input, now))
	return nil
}

// publishGossipObservedPath copies the current observed path into the
// transport address book after packet verification and the live update.
func (driver *GossipDriver) publishGossipObservedPath(peerID string, now time.Time, transport *gossip.Transport, verification gossipObservedVerification) error {
	if !driver.gossipDiscoveryAvailable() {
		return ErrGossipDriverStopped
	}
	if transport == nil || peerID == "" {
		return nil
	}
	input := driver.gossipDiscoveryInput(peerID, false, "")
	var paths []gossip.ObservedPath
	var ok bool
	if input.verifiedRevision != verification.revision {
		paths, ok = discoveryObservedPaths(input, peerID, input.Peers[peerID], now)
	} else if verification.valid && input.Network != nil {
		// Reuse authorization only within this packet's fixed time and
		// verified revision. Checkpoint fields still come from committed state.
		paths, ok = observedCheckpointPaths(input.Peers[peerID], now)
	}
	if !ok {
		transport.RemoveObservedPeerAddr(peerID)
		transport.SetRememberedPeerAddr(peerID, nil)
		return nil
	}
	transport.SetObservedPeerPaths(peerID, paths, preferGossipObserved(input.Peers[peerID], transport.PeerAddr(peerID)))
	if verification.confirmedChanged {
		transport.SetRememberedPeerAddr(peerID, parseRememberedAddr(input.Peers[peerID].LastSuccessfulEndpoint))
	}
	return nil
}

func (driver *GossipDriver) gossipDiscoveryAvailable() bool {
	if driver == nil {
		return false
	}
	driver.mu.RLock()
	defer driver.mu.RUnlock()
	return !driver.stopped
}

func PlanGossipDiscovery(input GossipDiscoveryInput, now time.Time) GossipDiscoveryPlan {
	plan := GossipDiscoveryPlan{
		Peers:     make(map[string]GossipPeerAddressUpdate),
		Addresses: make(map[string][]*net.UDPAddr), Remembered: make(map[string]*net.UDPAddr),
	}
	if input.Network == nil {
		return plan
	}
	plan.KnownPeerIDs = verifiedDiscoveryPeers(input, now)
	plan.Revoked = gossipDiscoveryRevocations(input, now)
	discovered := gossip.ExtractPeerEndpointsAt(input.Network, now)
	for peerID, bootstrap := range input.Bootstrap {
		if !plan.Revoked[zone.ZonePath(peerID)] {
			plan.Addresses[peerID] = GossipDiscoveryAddresses(discovered[peerID], bootstrap, input.SourceOrder)
		}
	}
	for peerID, entries := range discovered {
		if peerID != input.LocalPeerID && peerID != input.ManagedZone.String() && input.Bootstrap[peerID] == nil {
			plan.Addresses[peerID] = GossipDiscoveryAddresses(entries, nil, input.SourceOrder)
		}
	}

	for peerID, peer := range input.Peers {
		if plan.Revoked[zone.ZonePath(peerID)] {
			continue
		}
		var update GossipPeerAddressUpdate
		if addr := parseRememberedAddr(peer.LastSuccessfulEndpoint); addr != nil && discoveryPeerVerified(input, peerID, now) {
			plan.Remembered[peerID] = addr
		}
		if paths, ok := discoveryObservedPaths(input, peerID, peer, now); ok {
			update.ObservedPaths = paths
			var first *net.UDPAddr
			if addrs := plan.Addresses[peerID]; len(addrs) > 0 {
				first = addrs[0]
			}
			update.PreferObserved = preferGossipObserved(peer, first)
		}
		plan.Peers[peerID] = update
	}
	return plan
}

func gossipDiscoveryRevocations(input GossipDiscoveryInput, now time.Time) map[zone.ZonePath]bool {
	revoked := input.Network.RevokedZones(now)
	add := func(peerID string) {
		path := zone.ZonePath(peerID)
		if !revoked[path] && input.Network.IsZoneRevoked(path, now) {
			revoked[path] = true
		}
	}
	for peerID := range input.Peers {
		add(peerID)
	}
	for peerID := range input.Bootstrap {
		add(peerID)
	}
	for _, peerID := range input.BootstrapPeers {
		add(peerID)
	}
	return revoked
}

func ApplyGossipDiscoveryPlan(transport *gossip.Transport, plan GossipDiscoveryPlan) {
	if transport == nil {
		return
	}
	transport.ReplaceDiscoveryAddrs(plan.Addresses, plan.Remembered)
	for peerID := range plan.Addresses {
		transport.AddKnownPeerID(peerID)
	}
	for _, peerID := range plan.KnownPeerIDs {
		transport.AddKnownPeerID(peerID)
	}
	for path := range plan.Revoked {
		transport.RemovePeer(path.String())
	}
	for peerID, update := range plan.Peers {
		if len(update.ObservedPaths) == 0 {
			transport.RemoveObservedPeerAddr(peerID)
		} else {
			transport.SetObservedPeerPaths(peerID, update.ObservedPaths, update.PreferObserved)
		}
	}
}

func verifiedDiscoveryPeers(input GossipDiscoveryInput, now time.Time) []string {
	network := *input.Network
	network.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
	seen := make(map[string]bool)
	add := func(path zone.ZonePath) {
		id := string(path)
		if id != "" && id != input.LocalPeerID && id != string(input.ManagedZone) {
			seen[id] = true
		}
	}
	for parent, state := range network.Zones {
		if state == nil || photoncrypto.VerifyChain(&network, parent, now) != nil {
			continue
		}
		add(parent)
		for child := range state.Delegations {
			if !network.IsZoneRevoked(child, now) {
				add(child)
			}
		}
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func discoveryObservedPaths(input GossipDiscoveryInput, peerID string, peer corestate.PeerCheckpoint, now time.Time) ([]gossip.ObservedPath, bool) {
	if !discoveryObservedActive(peer, now) || !discoveryPeerVerified(input, peerID, now) {
		return nil, false
	}
	return observedCheckpointPaths(peer, now)
}

// observedCheckpointPaths builds addresses only after the caller has authorized
// this peer for the committed verified revision and the supplied time.
func observedCheckpointPaths(peer corestate.PeerCheckpoint, now time.Time) ([]gossip.ObservedPath, bool) {
	if !discoveryObservedActive(peer, now) {
		return nil, false
	}
	endpoint, err := netip.ParseAddrPort(peer.ObservedEndpoint)
	if err != nil {
		return nil, false
	}
	addr := net.UDPAddrFromAddrPort(endpoint)
	paths := []gossip.ObservedPath{{Addr: addr, Until: time.Unix(peer.ObservedUntilUnix, 0)}}
	seen := map[string]bool{peer.ObservedEndpoint: true}
	for _, entry := range peer.ObservedGraceEndpoints {
		if entry.Endpoint == "" || seen[entry.Endpoint] || entry.UntilUnix == 0 || !now.Before(time.Unix(entry.UntilUnix, 0)) {
			continue
		}
		grace, err := netip.ParseAddrPort(entry.Endpoint)
		if err != nil {
			continue
		}
		seen[entry.Endpoint] = true
		paths = append(paths, gossip.ObservedPath{Addr: net.UDPAddrFromAddrPort(grace), Until: time.Unix(entry.UntilUnix, 0)})
	}
	return paths, true
}

func preferGossipObserved(peer corestate.PeerCheckpoint, candidate *net.UDPAddr) bool {
	return peer.LastFailure != nil || candidate == nil || discoveryAddressPrivate(candidate.String())
}

func discoveryPeerVerified(input GossipDiscoveryInput, peerID string, now time.Time) bool {
	path := zone.ZonePath(peerID)
	if input.Network == nil || !path.Valid() || path == input.ManagedZone {
		return false
	}
	network := *input.Network
	network.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
	return input.observedVerifier.VerifyChain(&network, path, now) == nil
}

func discoveryObservedActive(peer corestate.PeerCheckpoint, now time.Time) bool {
	return peer.ObservedEndpoint != "" && peer.ObservedUntilUnix != 0 && now.Before(time.Unix(peer.ObservedUntilUnix, 0))
}

func appendObservedGraceEndpoint(grace []corestate.ObservedGraceEndpoint, endpoint string, until, now time.Time) []corestate.ObservedGraceEndpoint {
	if endpoint == "" || !now.Before(until) {
		return pruneObservedGraceEndpoints(grace, "", now)
	}
	out := pruneObservedGraceEndpoints(grace, endpoint, now)
	return append(out, corestate.ObservedGraceEndpoint{Endpoint: endpoint, UntilUnix: until.Unix()})
}

func pruneObservedGraceEndpoints(grace []corestate.ObservedGraceEndpoint, current string, now time.Time) []corestate.ObservedGraceEndpoint {
	if len(grace) == 0 {
		return nil
	}
	out := make([]corestate.ObservedGraceEndpoint, 0, len(grace))
	seen := make(map[string]bool, len(grace))
	for _, entry := range grace {
		if entry.Endpoint == "" || entry.Endpoint == current || seen[entry.Endpoint] || entry.UntilUnix == 0 || !now.Before(time.Unix(entry.UntilUnix, 0)) {
			continue
		}
		seen[entry.Endpoint] = true
		out = append(out, entry)
	}
	return out
}

func discoveryAddressPrivate(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	ip := net.ParseIP(host)
	return ip != nil && (ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast())
}

// GossipDiscoveryAddresses orders current signed and configured UDP candidates.
func GossipDiscoveryAddresses(entries []gossip.EndpointEntry, bootstrap *net.UDPAddr, order []string) []*net.UDPAddr {
	if len(order) == 0 {
		order = []string{"advertise", "bootstrap", "reflector", "interface"}
	}
	bySource := make(map[string][]*net.UDPAddr)
	for _, entry := range sortedDiscoveryEndpoints(entries) {
		addr, err := entry.UDPAddr()
		if err == nil {
			source, _, _ := strings.Cut(strings.ToLower(entry.Source), "+")
			if source == "" {
				source = "interface"
			}
			bySource[source] = appendDiscoveryAddress(bySource[source], addr)
		}
	}
	var out []*net.UDPAddr
	seen := make(map[string]bool)
	appendSource := func(source string) {
		if source == "bootstrap" && bootstrap != nil {
			if !seen[bootstrap.String()] {
				copied := *bootstrap
				out = append(out, &copied)
				seen[bootstrap.String()] = true
			}
			return
		}
		for _, addr := range bySource[source] {
			if !seen[addr.String()] {
				out = append(out, addr)
				seen[addr.String()] = true
			}
		}
	}
	for _, source := range order {
		appendSource(source)
	}
	for _, source := range []string{"bootstrap", "advertise", "reflector", "interface"} {
		appendSource(source)
	}
	// Source describes how an endpoint was learned, not whether it is valid.
	// Preserve endpoints from older/newer publishers with unfamiliar sources.
	var remaining []string
	for source := range bySource {
		remaining = append(remaining, source)
	}
	sort.Strings(remaining)
	for _, source := range remaining {
		appendSource(source)
	}
	return out
}

func parseRememberedAddr(endpoint string) *net.UDPAddr {
	addr, err := netip.ParseAddrPort(endpoint)
	if err != nil || addr.Port() == 0 || addr.Addr().IsUnspecified() || addr.Addr().IsMulticast() {
		return nil
	}
	return net.UDPAddrFromAddrPort(addr)
}

func appendDiscoveryAddress(out []*net.UDPAddr, addr *net.UDPAddr) []*net.UDPAddr {
	if addr == nil {
		return out
	}
	for _, current := range out {
		if current.IP.Equal(addr.IP) && current.Port == addr.Port {
			return out
		}
	}
	copied := *addr
	return append(out, &copied)
}

func sortedDiscoveryEndpoints(entries []gossip.EndpointEntry) []gossip.EndpointEntry {
	out := append([]gossip.EndpointEntry(nil), entries...)
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := discoveryEndpointRank(out[i]), discoveryEndpointRank(out[j])
		if ri != rj {
			return ri < rj
		}
		if out[i].Priority != out[j].Priority {
			return out[i].Priority > out[j].Priority
		}
		return out[i].LastObserved > out[j].LastObserved
	})
	return out
}

func discoveryEndpointRank(entry gossip.EndpointEntry) int {
	ip := net.ParseIP(entry.Address)
	if ip == nil {
		return 3
	}
	if ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return 2
	}
	return 0
}
