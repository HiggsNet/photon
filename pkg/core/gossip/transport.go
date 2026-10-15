package gossip

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	ErrUnknownPeer        = errors.New("unknown gossip peer")
	ErrAddrMismatch       = errors.New("gossip peer address mismatch")
	ErrMessageTooLarge    = errors.New("gossip message too large")
	ErrDatagramIORequired = errors.New("gossip datagram I/O is required")
)

type Clock func() time.Time

type Config struct {
	PeerID          string
	KnownPeers      map[string]*net.UDPAddr
	MaxMessageBytes int
	Replay          *ReplayWindow
	Quotas          *PeerQuotas
	Clock           Clock
	Log             func(Event)
}

// DatagramIO is the injected packet-socket capability used by Transport.
// Its implementation owns bind/read/write/deadline/close; Transport owns
// gossip wire encoding, validation and peer/address policy.
type DatagramIO interface {
	ReadDatagram(buffer []byte) (int, *net.UDPAddr, error)
	WriteDatagram(payload []byte, addr *net.UDPAddr) (int, error)
	LocalAddr() *net.UDPAddr
	SetReadDeadline(time.Time) error
	Close() error
}

type Transport struct {
	datagram        DatagramIO
	peerID          string
	knownPeers      map[string]struct{} // inbound allowlist
	knownMu         sync.RWMutex
	outboundAddrs   map[string][]*net.UDPAddr // addresses used for Send
	outboundMu      sync.RWMutex
	recentInbound   map[string]recentInboundPath // short-lived paths learned from accepted inbound packets
	recentInboundMu sync.Mutex
	observedPaths   map[string]observedPath // verified short-lived inbound UDP paths
	observedMu      sync.RWMutex
	addrStates      map[string]map[string]*addrState // per-peer per-address reachability state
	addrStateMu     sync.RWMutex
	lastSentAddr    map[string]string // per-peer last successfully-written address
	lastSentMu      sync.RWMutex
	maxMessageBytes int
	replay          *ReplayWindow
	quotas          *PeerQuotas
	clock           Clock
	log             func(Event)
}

type addrState struct {
	SuccessCount int
	FailureCount int
	LastSuccess  time.Time
	LastFailure  time.Time
	BackoffUntil time.Time
	LastAttempt  time.Time
}

type recentInboundPath struct {
	Addr  *net.UDPAddr
	Until time.Time
}

const (
	addrFailureBackoffThreshold = 2
	addrFailureBackoffBase      = 500 * time.Millisecond
	addrFailureBackoffMax       = 30 * time.Second
	addrSuccessResetAfter       = 2 * time.Minute
	recentInboundPathTTL        = time.Minute
)

type Packet struct {
	Message *Message
	Addr    *net.UDPAddr
	Bytes   int
}

type Event struct {
	Direction string
	PeerID    string
	Type      MessageType
	Addr      string
	Bytes     int
	Zones     int
	Records   int
	Duration  time.Duration
	Error     string
	Reason    string

	QuotaRequestedBytes     int64
	QuotaRequestedObjects   int64
	QuotaAvailableBytes     int64
	QuotaAvailableObjects   int64
	QuotaByteRate           int64
	QuotaByteBurst          int64
	QuotaObjectRate         int64
	QuotaObjectBurst        int64
	QuotaLastRefillUnixNano int64
}

type observedPath struct {
	Paths       []ObservedPath
	PreferFirst bool
}

// ObservedPath is a verified short-lived inbound UDP path for a peer.
type ObservedPath struct {
	Addr  *net.UDPAddr
	Until time.Time
}

func NewTransport(config Config, datagram DatagramIO) (*Transport, error) {
	if config.PeerID == "" {
		return nil, errors.New("local gossip peer id is empty")
	}
	if datagram == nil {
		return nil, ErrDatagramIORequired
	}
	maxMessageBytes := config.MaxMessageBytes
	if maxMessageBytes <= 0 {
		maxMessageBytes = DefaultMaxMessage
	}
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}
	replay := config.Replay
	if replay == nil {
		replay = NewReplayWindow(0)
	}
	t := &Transport{
		datagram:        datagram,
		peerID:          config.PeerID,
		maxMessageBytes: maxMessageBytes,
		replay:          replay,
		quotas:          config.Quotas,
		clock:           clock,
		log:             config.Log,
	}
	if len(config.KnownPeers) > 0 {
		t.SetPeers(config.KnownPeers)
	}
	return t, nil
}

// MaxMessageBytes returns the configured datagram size limit.
func (t *Transport) MaxMessageBytes() int {
	if t == nil {
		return DefaultDatagramBudget
	}
	return t.maxMessageBytes
}

// PeerID returns the local peer ID attached to outbound messages.
func (t *Transport) PeerID() string {
	if t == nil {
		return ""
	}
	return t.peerID
}

func (t *Transport) Close() error {
	if t == nil || t.datagram == nil {
		return nil
	}
	return t.datagram.Close()
}

func (t *Transport) LocalAddr() *net.UDPAddr {
	if t == nil || t.datagram == nil {
		return nil
	}
	return t.datagram.LocalAddr()
}

func (t *Transport) SetReadDeadline(deadline time.Time) error {
	if t == nil || t.datagram == nil {
		return nil
	}
	return t.datagram.SetReadDeadline(deadline)
}

func (t *Transport) Send(peerID string, message *Message) error {
	addrs := t.sendAddrsFor(peerID)
	if len(addrs) == 0 {
		start := t.now()
		event := Event{Direction: "send", PeerID: peerID}
		if message != nil {
			event.Type = message.Type
			event.Zones, event.Records = MessageObjectCounts(message)
		}
		t.logEvent(event, ErrUnknownPeer, start)
		return ErrUnknownPeer
	}
	return t.sendToAddrs(peerID, message, addrs)
}

// SendTo replies to a known peer at an explicit address. It is intended for
// request-scoped responses to an address that Transport.Receive has just
// validated and returned. It does not install addr as a durable outbound or
// observed path.
func (t *Transport) SendTo(peerID string, addr *net.UDPAddr, message *Message) error {
	if t == nil || addr == nil {
		return ErrUnknownPeer
	}
	if err := t.validatePeer(peerID); err != nil {
		start := t.now()
		event := Event{Direction: "send", PeerID: peerID, Addr: udpAddrString(addr)}
		if message != nil {
			event.Type = message.Type
			event.Zones, event.Records = MessageObjectCounts(message)
		}
		t.logEvent(event, err, start)
		return err
	}
	copied := *addr
	return t.sendToAddrs(peerID, message, []*net.UDPAddr{&copied})
}

func (t *Transport) sendToAddrs(peerID string, message *Message, addrs []*net.UDPAddr) error {
	start := t.now()
	event := Event{Direction: "send", PeerID: peerID}
	if message != nil {
		event.Type = message.Type
		event.Zones, event.Records = MessageObjectCounts(message)
	}

	if message == nil {
		err := errors.New("gossip message is nil")
		t.logEvent(event, err, start)
		return err
	}
	message.PeerID = t.peerID
	if message.Nonce == 0 {
		nonce, err := randomNonce()
		if err != nil {
			t.logEvent(event, err, start)
			return err
		}
		message.Nonce = nonce
	}
	if message.Timestamp == 0 {
		message.Timestamp = t.now().Unix()
	}
	data, err := MarshalMessage(message)
	if err != nil {
		t.logEvent(event, err, start)
		return err
	}
	event.Bytes = len(data)
	if len(data) > t.maxMessageBytes {
		t.logEvent(event, ErrMessageTooLarge, start)
		return ErrMessageTooLarge
	}
	if t.quotas != nil {
		if err := t.quotas.Allow(peerID, int64(len(data)), objectCost(message), t.now()); err != nil {
			t.logEvent(event, err, start)
			return err
		}
	}

	var lastErr error
	var sentAddr *net.UDPAddr
	for _, addr := range addrs {
		event.Addr = addr.String()
		t.recordAddrAttempt(peerID, addr.String())
		_, lastErr = t.datagram.WriteDatagram(data, addr)
		if lastErr == nil {
			sentAddr = addr
			break
		}
	}
	if sentAddr != nil {
		t.lastSentMu.Lock()
		if t.lastSentAddr == nil {
			t.lastSentAddr = make(map[string]string)
		}
		t.lastSentAddr[peerID] = sentAddr.String()
		t.lastSentMu.Unlock()
		t.logEvent(event, nil, start)
		return nil
	}
	t.logEvent(event, lastErr, start)
	return lastErr
}

// sendAddrsFor returns the candidate addresses for a peer ordered by
// reachability state. Successful and recently-attempted addresses come first;
// addresses in backoff are moved to the end. The ordering rotates so that a
// single unreachable address at the head does not permanently starve the rest.
func (t *Transport) sendAddrsFor(peerID string) []*net.UDPAddr {
	if t == nil || peerID == "" {
		return nil
	}

	var outbound, observed []*net.UDPAddr
	var preferObservedFirst bool

	t.outboundMu.RLock()
	outbound = appendUDPAddrCopies(nil, t.outboundAddrs[peerID]...)
	t.outboundMu.RUnlock()

	t.observedMu.RLock()
	if obs := t.activeObservedPath(peerID); len(obs.Paths) > 0 {
		observed = make([]*net.UDPAddr, 0, len(obs.Paths))
		for _, path := range obs.Paths {
			observed = append(observed, path.Addr)
		}
		preferObservedFirst = obs.PreferFirst
	}
	t.observedMu.RUnlock()

	recentInbound := t.activeRecentInboundPath(peerID)

	// A recently accepted packet is the strongest live reachability signal for
	// an active session, especially when the peer is behind NAT. Keep it ahead
	// of configured and checkpoint-derived candidates for a bounded period.
	addrs := appendUDPAddrCopies(nil, recentInbound)
	if preferObservedFirst {
		addrs = appendUDPAddrCopies(addrs, observed...)
		addrs = appendUDPAddrCopies(addrs, outbound...)
	} else {
		addrs = appendUDPAddrCopies(addrs, outbound...)
		addrs = appendUDPAddrCopies(addrs, observed...)
	}
	if len(addrs) == 0 {
		return nil
	}

	now := t.now()
	sort.SliceStable(addrs, func(i, j int) bool {
		return addrSendRank(addrs[i], peerID, t, now) < addrSendRank(addrs[j], peerID, t, now)
	})

	return addrs
}

func addrSendRank(addr *net.UDPAddr, peerID string, t *Transport, now time.Time) int {
	state := t.getAddrState(peerID, addr.String())
	if state == nil {
		return 1
	}
	if !state.BackoffUntil.IsZero() && now.Before(state.BackoffUntil) {
		return 3
	}
	if !state.LastSuccess.IsZero() && now.Sub(state.LastSuccess) < addrSuccessResetAfter {
		return 0
	}
	if state.FailureCount > 0 {
		return 2
	}
	return 1
}

func (t *Transport) Receive() (*Packet, error) {
	start := t.now()
	buf := make([]byte, t.maxMessageBytes+1)
	n, addr, err := t.datagram.ReadDatagram(buf)
	if err != nil {
		// Read deadlines are used by callers to poll for context cancellation
		// and timers; timeouts are routine and should not pollute debug logs.
		if !isNetworkTimeout(err) {
			t.logEvent(Event{Direction: "recv", Addr: udpAddrString(addr)}, err, start)
		}
		return nil, err
	}
	event := Event{Direction: "recv", Addr: udpAddrString(addr), Bytes: n}
	if n > t.maxMessageBytes {
		t.logEvent(event, ErrMessageTooLarge, start)
		return nil, ErrMessageTooLarge
	}
	message, err := UnmarshalMessage(buf[:n])
	if err != nil {
		t.logEvent(event, err, start)
		return nil, err
	}
	event.PeerID = message.PeerID
	event.Type = message.Type
	event.Zones, event.Records = MessageObjectCounts(message)
	if err := t.validatePeer(message.PeerID); err != nil {
		t.logEvent(event, err, start)
		return nil, err
	}
	if t.quotas != nil {
		if err := t.quotas.Allow(message.PeerID, int64(n), objectCost(message), t.now()); err != nil {
			t.logEvent(event, err, start)
			return nil, err
		}
	}
	if err := t.replay.Check(message.PeerID, message.Nonce, message.Timestamp, t.now()); err != nil {
		t.logEvent(event, err, start)
		return nil, err
	}
	t.recentInboundMu.Lock()
	if t.recentInbound == nil {
		t.recentInbound = make(map[string]recentInboundPath)
	}
	copied := *addr
	t.recentInbound[message.PeerID] = recentInboundPath{
		Addr:  &copied,
		Until: t.now().Add(recentInboundPathTTL),
	}
	t.recentInboundMu.Unlock()
	t.RecordAddrSuccess(message.PeerID, addr)
	t.logEvent(event, nil, start)
	return &Packet{Message: message, Addr: addr, Bytes: n}, nil
}

// validatePeer only checks whether the peer_id is known.
// Address binding has been removed; identity is established by upper-layer
// cryptographic verification (VerifyChain / VerifyRecord).
func (t *Transport) validatePeer(peerID string) error {
	t.knownMu.RLock()
	defer t.knownMu.RUnlock()
	if _, ok := t.knownPeers[peerID]; !ok {
		return ErrUnknownPeer
	}
	return nil
}

func (t *Transport) logEvent(event Event, err error, start time.Time) {
	if err != nil {
		var quotaErr *QuotaExceededError
		if errors.As(err, &quotaErr) {
			quotaErr.Direction = event.Direction
			quotaErr.MessageType = event.Type
		}
	}
	if t == nil || t.log == nil {
		return
	}
	event.Duration = t.now().Sub(start)
	if err != nil {
		event.Error = err.Error()
		event.Reason = RejectReason(err)
		ApplyQuotaDiagnostics(&event, err)
	}
	t.log(event)
}

func ApplyQuotaDiagnostics(event *Event, err error) {
	if event == nil || err == nil {
		return
	}
	var quotaErr *QuotaExceededError
	if !errors.As(err, &quotaErr) || quotaErr == nil {
		return
	}
	event.QuotaRequestedBytes = quotaErr.RequestedBytes
	event.QuotaRequestedObjects = quotaErr.RequestedObjects
	event.QuotaAvailableBytes = quotaErr.AvailableBytes
	event.QuotaAvailableObjects = quotaErr.AvailableObjects
	event.QuotaByteRate = quotaErr.ByteRate
	event.QuotaByteBurst = quotaErr.ByteBurst
	event.QuotaObjectRate = quotaErr.ObjectRate
	event.QuotaObjectBurst = quotaErr.ObjectBurst
	event.QuotaLastRefillUnixNano = quotaErr.LastRefillUnixNano
}

// isNetworkTimeout reports whether err is a network timeout from a
// SetReadDeadline/SetWriteDeadline expiry.
func isNetworkTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func udpAddrString(addr *net.UDPAddr) string {
	if addr == nil {
		return ""
	}
	return addr.String()
}

func RejectReason(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrUnknownPeer):
		return "unknown_peer"
	case errors.Is(err, ErrAddrMismatch):
		return "addr_mismatch"
	case errors.Is(err, ErrMessageTooLarge):
		return "message_too_large"
	case errors.Is(err, ErrQuotaExceeded):
		return "quota"
	case strings.Contains(err.Error(), "replay"):
		return "replay"
	case strings.Contains(err.Error(), "unsupported gossip wire version"):
		return "unsupported_wire_version"
	case errors.Is(err, ErrUnsupportedCodec):
		return "unsupported_codec"
	default:
		return "invalid_message"
	}
}

func MessageObjectCounts(message *Message) (zones int, records int) {
	switch {
	case message == nil:
		return 0, 0
	case message.Ping != nil:
		return 0, 0
	case message.Pong != nil:
		return 0, 0
	case message.FetchZone != nil:
		return 1, 0
	case message.FetchRecord != nil:
		return 1, 1
	case message.FetchCatalogPage != nil:
		return 1, 0
	case message.CatalogPage != nil:
		return len(message.CatalogPage.Entries), 0
	case message.Announce != nil:
		return len(message.Announce.Zones), 0
	case message.ObjectChunk != nil:
		if message.ObjectChunk.Object == ObjectPullRecord {
			return 0, 1
		}
		return 1, 0
	case message.ObjectChunkNACK != nil:
		return 0, 0
	default:
		return 0, 0
	}
}

func objectCost(message *Message) int64 {
	switch {
	case message == nil:
		return 0
	case message.Ping != nil:
		return 0
	case message.Pong != nil:
		return 0
	case message.FetchCatalogPage != nil:
		return 1
	case message.CatalogPage != nil:
		return int64(len(message.CatalogPage.Entries))
	case message.Announce != nil:
		return int64(len(message.Announce.Zones))
	case message.ObjectChunk != nil:
		return 1
	case message.ObjectChunkNACK != nil:
		// This is one bounded repair request. The actual retransmitted chunks
		// consume their own quota on the shared send/receive bucket.
		return 1
	case message.FetchZone != nil, message.FetchRecord != nil:
		return 1
	default:
		return 1
	}
}

// PeerAddr returns the preferred (first) outbound address for a peer.
func (t *Transport) PeerAddr(peerID string) *net.UDPAddr {
	t.outboundMu.RLock()
	defer t.outboundMu.RUnlock()
	addrs := t.outboundAddrs[peerID]
	if len(addrs) == 0 {
		return nil
	}
	copied := *addrs[0]
	return &copied
}

// SetObservedPeerAddr stores a verified, short-lived inbound UDP path for a
// peer. It does not change the inbound allowlist and is intended for NAT
// mappings observed after upper-layer verification.
func (t *Transport) SetObservedPeerAddr(peerID string, addr *net.UDPAddr, until time.Time, preferFirst bool) {
	t.SetObservedPeerPaths(peerID, []ObservedPath{{Addr: addr, Until: until}}, preferFirst)
}

// SetObservedPeerPaths stores verified short-lived inbound UDP paths for a
// peer. The first path is preferred; later paths are grace fallbacks retained
// across NAT rebinding or public-address changes.
func (t *Transport) SetObservedPeerPaths(peerID string, paths []ObservedPath, preferFirst bool) {
	if t == nil || peerID == "" {
		return
	}
	filtered := make([]ObservedPath, 0, len(paths))
	now := t.now()
	for _, path := range paths {
		if path.Addr == nil || (!path.Until.IsZero() && !now.Before(path.Until)) {
			continue
		}
		copied := *path.Addr
		filtered = append(filtered, ObservedPath{Addr: &copied, Until: path.Until})
	}
	if len(filtered) == 0 {
		return
	}
	t.observedMu.Lock()
	if t.observedPaths == nil {
		t.observedPaths = make(map[string]observedPath)
	}
	t.observedPaths[peerID] = observedPath{Paths: filtered, PreferFirst: preferFirst}
	t.observedMu.Unlock()
}

func (t *Transport) RemoveObservedPeerAddr(peerID string) {
	if t == nil || peerID == "" {
		return
	}
	t.observedMu.Lock()
	delete(t.observedPaths, peerID)
	t.observedMu.Unlock()
}

func (t *Transport) ObservedPeerAddr(peerID string) *net.UDPAddr {
	if t == nil || peerID == "" {
		return nil
	}
	t.observedMu.RLock()
	defer t.observedMu.RUnlock()
	observed := t.activeObservedPath(peerID)
	if len(observed.Paths) == 0 || observed.Paths[0].Addr == nil {
		return nil
	}
	copied := *observed.Paths[0].Addr
	return &copied
}

// ObservedPeerAddrs returns the active observed paths for a peer in send order.
func (t *Transport) ObservedPeerAddrs(peerID string) []*net.UDPAddr {
	if t == nil || peerID == "" {
		return nil
	}
	t.observedMu.RLock()
	defer t.observedMu.RUnlock()
	observed := t.activeObservedPath(peerID)
	out := make([]*net.UDPAddr, 0, len(observed.Paths))
	for _, path := range observed.Paths {
		out = appendUDPAddrCopies(out, path.Addr)
	}
	return out
}

func (t *Transport) activeObservedPath(peerID string) observedPath {
	observed := t.observedPaths[peerID]
	if len(observed.Paths) == 0 {
		return observedPath{}
	}
	now := t.now()
	active := observedPath{PreferFirst: observed.PreferFirst}
	for _, path := range observed.Paths {
		if path.Addr == nil || (!path.Until.IsZero() && !now.Before(path.Until)) {
			continue
		}
		copied := *path.Addr
		active.Paths = append(active.Paths, ObservedPath{Addr: &copied, Until: path.Until})
	}
	return active
}

// AddKnownPeerID adds a peer ID to the inbound allowlist without
// registering any outbound address. Used for zone-identity-based admission.
func (t *Transport) AddKnownPeerID(peerID string) {
	t.knownMu.Lock()
	if t.knownPeers == nil {
		t.knownPeers = make(map[string]struct{})
	}
	t.knownPeers[peerID] = struct{}{}
	t.knownMu.Unlock()
}

// AddPeer registers a peer in the inbound allowlist and adds an address
// to its outbound address book. Duplicate addresses are ignored.
func (t *Transport) AddPeer(peerID string, addr *net.UDPAddr) {
	if addr == nil {
		return
	}
	t.knownMu.Lock()
	if t.knownPeers == nil {
		t.knownPeers = make(map[string]struct{})
	}
	t.knownPeers[peerID] = struct{}{}
	t.knownMu.Unlock()

	t.outboundMu.Lock()
	if t.outboundAddrs == nil {
		t.outboundAddrs = make(map[string][]*net.UDPAddr)
	}
	for _, existing := range t.outboundAddrs[peerID] {
		if existing.IP.Equal(addr.IP) && existing.Port == addr.Port {
			t.outboundMu.Unlock()
			return
		}
	}
	copied := *addr
	t.outboundAddrs[peerID] = append(t.outboundAddrs[peerID], &copied)
	t.outboundMu.Unlock()
}

// SetPeerAddrs replaces the entire outbound address list for a peer.
func (t *Transport) SetPeerAddrs(peerID string, addrs []*net.UDPAddr) {
	if len(addrs) == 0 {
		return
	}
	t.knownMu.Lock()
	if t.knownPeers == nil {
		t.knownPeers = make(map[string]struct{})
	}
	t.knownPeers[peerID] = struct{}{}
	t.knownMu.Unlock()

	filtered := make([]*net.UDPAddr, 0, len(addrs))
	for _, a := range addrs {
		if a != nil {
			copied := *a
			filtered = append(filtered, &copied)
		}
	}
	t.outboundMu.Lock()
	if t.outboundAddrs == nil {
		t.outboundAddrs = make(map[string][]*net.UDPAddr)
	}
	t.outboundAddrs[peerID] = filtered
	t.outboundMu.Unlock()
}

// RemovePeerAddrs removes outbound addresses for a peer while leaving the
// inbound allowlist intact.
func (t *Transport) RemovePeerAddrs(peerID string) {
	t.outboundMu.Lock()
	delete(t.outboundAddrs, peerID)
	t.outboundMu.Unlock()
}

func (t *Transport) RemovePeer(peerID string) {
	t.knownMu.Lock()
	delete(t.knownPeers, peerID)
	t.knownMu.Unlock()

	t.outboundMu.Lock()
	delete(t.outboundAddrs, peerID)
	t.outboundMu.Unlock()

	t.observedMu.Lock()
	delete(t.observedPaths, peerID)
	t.observedMu.Unlock()

	t.recentInboundMu.Lock()
	delete(t.recentInbound, peerID)
	t.recentInboundMu.Unlock()

	t.addrStateMu.Lock()
	delete(t.addrStates, peerID)
	t.addrStateMu.Unlock()

	t.lastSentMu.Lock()
	delete(t.lastSentAddr, peerID)
	t.lastSentMu.Unlock()
}

func (t *Transport) activeRecentInboundPath(peerID string) *net.UDPAddr {
	if t == nil || peerID == "" {
		return nil
	}
	t.recentInboundMu.Lock()
	defer t.recentInboundMu.Unlock()
	path, ok := t.recentInbound[peerID]
	if !ok || path.Addr == nil {
		return nil
	}
	if !path.Until.IsZero() && !t.now().Before(path.Until) {
		delete(t.recentInbound, peerID)
		return nil
	}
	copied := *path.Addr
	return &copied
}

// SetPeers initializes both the inbound allowlist and the outbound address
// book from a single-address-per-peer map (used for bootstrap config).
func (t *Transport) SetPeers(peers map[string]*net.UDPAddr) {
	t.knownMu.Lock()
	t.knownPeers = make(map[string]struct{}, len(peers))
	for id := range peers {
		t.knownPeers[id] = struct{}{}
	}
	t.knownMu.Unlock()

	t.outboundMu.Lock()
	t.outboundAddrs = make(map[string][]*net.UDPAddr, len(peers))
	for id, addr := range peers {
		if addr == nil {
			continue
		}
		copied := *addr
		t.outboundAddrs[id] = []*net.UDPAddr{&copied}
	}
	t.outboundMu.Unlock()
}

func (t *Transport) KnownPeerIDs() []string {
	t.knownMu.RLock()
	defer t.knownMu.RUnlock()
	out := make([]string, 0, len(t.knownPeers))
	for id := range t.knownPeers {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// LastSendAddr returns the address that was most recently written
// successfully for the peer. It is used by the upper layer to mark an address
// as failing when no response is received.
func (t *Transport) LastSendAddr(peerID string) *net.UDPAddr {
	if t == nil || peerID == "" {
		return nil
	}
	t.lastSentMu.RLock()
	addrStr := t.lastSentAddr[peerID]
	t.lastSentMu.RUnlock()
	if addrStr == "" {
		return nil
	}
	addr, err := net.ResolveUDPAddr("udp", addrStr)
	if err != nil {
		return nil
	}
	return addr
}

func (t *Transport) now() time.Time {
	if t != nil && t.clock != nil {
		return t.clock()
	}
	return time.Now()
}

func (t *Transport) getAddrState(peerID, addr string) *addrState {
	if t == nil {
		return nil
	}
	t.addrStateMu.RLock()
	defer t.addrStateMu.RUnlock()
	if t.addrStates == nil {
		return nil
	}
	return t.addrStates[peerID][addr]
}

func (t *Transport) recordAddrAttempt(peerID, addr string) {
	if t == nil || peerID == "" || addr == "" {
		return
	}
	t.addrStateMu.Lock()
	defer t.addrStateMu.Unlock()
	if t.addrStates == nil {
		t.addrStates = make(map[string]map[string]*addrState)
	}
	if t.addrStates[peerID] == nil {
		t.addrStates[peerID] = make(map[string]*addrState)
	}
	state := t.addrStates[peerID][addr]
	if state == nil {
		state = &addrState{}
		t.addrStates[peerID][addr] = state
	}
	state.LastAttempt = t.now()
}

// RecordAddrSuccess marks an address as recently reachable for a peer.
func (t *Transport) RecordAddrSuccess(peerID string, addr *net.UDPAddr) {
	if t == nil || peerID == "" || addr == nil {
		return
	}
	addrStr := addr.String()
	t.addrStateMu.Lock()
	defer t.addrStateMu.Unlock()
	if t.addrStates == nil {
		t.addrStates = make(map[string]map[string]*addrState)
	}
	if t.addrStates[peerID] == nil {
		t.addrStates[peerID] = make(map[string]*addrState)
	}
	state := t.addrStates[peerID][addrStr]
	if state == nil {
		state = &addrState{}
		t.addrStates[peerID][addrStr] = state
	}
	now := t.now()
	state.SuccessCount++
	state.LastSuccess = now
	state.FailureCount = 0
	state.BackoffUntil = time.Time{}
}

// RecordAddrFailure marks an address as failing for a peer. After repeated
// failures the address enters a short backoff and is deprioritized by Send.
func (t *Transport) RecordAddrFailure(peerID string, addr *net.UDPAddr) {
	if t == nil || peerID == "" || addr == nil {
		return
	}
	addrStr := addr.String()
	t.addrStateMu.Lock()
	defer t.addrStateMu.Unlock()
	if t.addrStates == nil {
		t.addrStates = make(map[string]map[string]*addrState)
	}
	if t.addrStates[peerID] == nil {
		t.addrStates[peerID] = make(map[string]*addrState)
	}
	state := t.addrStates[peerID][addrStr]
	if state == nil {
		state = &addrState{}
		t.addrStates[peerID][addrStr] = state
	}
	now := t.now()
	state.FailureCount++
	state.LastFailure = now
	if state.FailureCount >= addrFailureBackoffThreshold {
		backoff := min(addrFailureBackoffBase*time.Duration(1<<minInt(state.FailureCount-addrFailureBackoffThreshold, 6)), addrFailureBackoffMax)
		state.BackoffUntil = now.Add(backoff)
	}
}

// AddrFailureCount returns the number of consecutive failures recorded for a
// peer address.
func (t *Transport) AddrFailureCount(peerID string, addr *net.UDPAddr) int {
	state := t.getAddrState(peerID, addrString(addr))
	if state == nil {
		return 0
	}
	return state.FailureCount
}

// AddrQuality is a read-only snapshot of the transport's reachability state
// for a single peer address.
type AddrQuality struct {
	SuccessCount int
	FailureCount int
	LastSuccess  time.Time
	LastFailure  time.Time
	BackoffUntil time.Time
	LastAttempt  time.Time
}

// PeerAddrStates returns a snapshot of all known address reachability states
// for a peer. The map keys are the address strings returned by net.UDPAddr.String.
func (t *Transport) PeerAddrStates(peerID string) map[string]AddrQuality {
	if t == nil {
		return nil
	}
	t.addrStateMu.RLock()
	defer t.addrStateMu.RUnlock()
	pm := t.addrStates[peerID]
	if len(pm) == 0 {
		return nil
	}
	out := make(map[string]AddrQuality, len(pm))
	for addr, s := range pm {
		if s == nil {
			continue
		}
		out[addr] = AddrQuality{
			SuccessCount: s.SuccessCount,
			FailureCount: s.FailureCount,
			LastSuccess:  s.LastSuccess,
			LastFailure:  s.LastFailure,
			BackoffUntil: s.BackoffUntil,
			LastAttempt:  s.LastAttempt,
		}
	}
	return out
}

func addrString(addr *net.UDPAddr) string {
	if addr == nil {
		return ""
	}
	return addr.String()
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func appendUDPAddrCopies(addrs []*net.UDPAddr, more ...*net.UDPAddr) []*net.UDPAddr {
	for _, addr := range more {
		if addr == nil {
			continue
		}
		duplicate := false
		for _, existing := range addrs {
			if existing != nil && existing.IP.Equal(addr.IP) && existing.Port == addr.Port {
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}
		copied := *addr
		addrs = append(addrs, &copied)
	}
	return addrs
}

func randomNonce() (uint64, error) {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, err
	}
	nonce := binary.BigEndian.Uint64(buf[:])
	if nonce == 0 {
		nonce = 1
	}
	return nonce, nil
}
