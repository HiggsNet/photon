package zone

import (
	"bytes"
	"crypto/ed25519"
	"net"
	"net/netip"
	"strings"
	"time"
)

// ZonePath is a fully-qualified zone name. The root zone is ".".
type ZonePath string

const RootZone ZonePath = "."

func (zp ZonePath) String() string {
	return string(zp)
}

func (zp ZonePath) IsRoot() bool {
	return zp == RootZone
}

func (zp ZonePath) Parent() ZonePath {
	if zp.IsRoot() {
		return RootZone
	}

	s := strings.TrimSuffix(string(zp), ".")
	if s == "" {
		return RootZone
	}

	parts := strings.Split(s, ".")
	if len(parts) <= 1 {
		return RootZone
	}

	return ZonePath(strings.Join(parts[1:], ".") + ".")
}

func (zp ZonePath) Valid() bool {
	if zp == RootZone {
		return true
	}

	s := string(zp)
	if !strings.HasSuffix(s, ".") || strings.Contains(s, "..") {
		return false
	}

	return strings.TrimSuffix(s, ".") != ""
}

// Ancestors returns zp followed by its parents up to the root.
func (zp ZonePath) Ancestors() []ZonePath {
	out := []ZonePath{zp}
	for !zp.IsRoot() {
		zp = zp.Parent()
		out = append(out, zp)
	}
	return out
}

type Permission string

const (
	PermWrite      Permission = "write"
	PermDelegate   Permission = "delegate"
	PermAllocateIP Permission = "allocate-ip"
)

type DelegationScope string

const (
	DelegationScopeDirectChild DelegationScope = "direct-child"
	DelegationScopeSubtree     DelegationScope = "subtree"
)

type Capability struct {
	Permissions []Permission
	KeyPrefix   string
}

type AuthorizedKey struct {
	Key          ed25519.PublicKey
	NotBefore    int64
	NotAfter     int64
	Capabilities []Capability
}

type ZoneAuthority struct {
	Zone      ZonePath
	Epoch     uint64
	Keys      []AuthorizedKey
	Threshold uint8
}

// HasPublicKey reports key membership only; it does not check capabilities or validity periods.
func (authority *ZoneAuthority) HasPublicKey(publicKey []byte) bool {
	if authority == nil {
		return false
	}
	for _, key := range authority.Keys {
		if bytes.Equal(key.Key, publicKey) {
			return true
		}
	}
	return false
}

type Delegation struct {
	ZoneName       ZonePath
	Scope          DelegationScope
	AuthorityEpoch uint64
	AuthorityHash  []byte
	Authority      ZoneAuthority
	ExpiresAt      *time.Time

	SignedBy  ed25519.PublicKey
	Signature []byte
}

type DelegationRevocation struct {
	ChildZone             ZonePath
	ParentZone            ZonePath
	RevokedAuthorityEpoch uint64
	RevokedAuthorityHash  []byte
	Reason                string
	RevokedAt             int64
	TTLSeconds            int64
	GraceSeconds          int64

	SignedBy  ed25519.PublicKey
	Signature []byte
}

type Record struct {
	Zone      ZonePath
	Key       string
	Type      string
	Value     []byte
	ValueHash []byte
	Version   uint64
	PrevHash  []byte
	Timestamp int64

	SignedBy  ed25519.PublicKey
	Signature []byte
}

type ZoneState struct {
	Path          ZonePath
	Authority     *ZoneAuthority
	ParentProof   []*Delegation
	Delegations   map[ZonePath]*Delegation
	Revocations   map[ZonePath]*DelegationRevocation
	Records       map[string]*Record
	RecordHistory map[string][]*Record
	MerkleRoot    []byte
}

func NewZoneState(path ZonePath, authority *ZoneAuthority) *ZoneState {
	return &ZoneState{
		Path:          path,
		Authority:     authority,
		Delegations:   make(map[ZonePath]*Delegation),
		Revocations:   make(map[ZonePath]*DelegationRevocation),
		Records:       make(map[string]*Record),
		RecordHistory: make(map[string][]*Record),
	}
}

type NetworkState struct {
	Zones          map[ZonePath]*ZoneState
	GlobalRoot     []byte
	RecordVerifier RecordVerifier `json:"-"`
	RecordHasher   RecordHasher   `json:"-"`
}

func NewNetworkState() *NetworkState {
	return &NetworkState{Zones: make(map[ZonePath]*ZoneState)}
}

type RecordVerifier func(record *Record, authority *ZoneAuthority, now time.Time) error
type RecordHasher func(record *Record) []byte

func (ns *NetworkState) ConfigureRecordValidation(verifier RecordVerifier, hasher RecordHasher) {
	ns.RecordVerifier = verifier
	ns.RecordHasher = hasher
}

type NodeIdentity struct {
	PrivateKey   ed25519.PrivateKey
	PublicKey    ed25519.PublicKey
	ManagedZones []ZonePath
}

type Endpoint struct {
	IP       net.IP
	Port     uint16
	Scope    string
	Priority int
}

type TransportLink struct {
	Type       string
	LocalPort  uint16
	RemotePort uint16
	Params     map[string]string
}

type LinkInstance struct {
	ID         string
	Peer       ZonePath
	Transport  string
	Interface  string
	LocalAddr  netip.Addr
	RemoteAddr netip.Addr
	Metric     uint32
	State      string
}

type PeerView struct {
	NodeID           []byte
	Zone             ZonePath
	PublicKey        []byte
	TunnelAllowedIPs []netip.Prefix
	AnnouncedRoutes  []netip.Prefix
	Endpoints        []Endpoint
	Links            []TransportLink
}
