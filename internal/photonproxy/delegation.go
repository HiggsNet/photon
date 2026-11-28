package photonproxy

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/netip"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/HiggsNet/photon/internal/trusttunnel"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

const (
	delegationHeader      = "Photon-Relay-Authorization"
	delegationTarget      = "Photon-Relay-Target"
	delegationHeaderLimit = 512
	delegationLifetime    = 30 * time.Second
	delegationReplayLimit = 16384
)

var delegationEncoding = base64.RawURLEncoding.Strict()

type delegationGrant struct {
	Source zone.ZonePath `json:"a"`
	KeyID  string        `json:"k"`
	Issued int64         `json:"t"`
	Nonce  string        `json:"n"`
	UDP    string        `json:"u,omitempty"`
}

// These fields come from the authenticated next-hop TLS identity, the exit's
// own configuration, and the actual CONNECT request, so the ticket need not
// repeat them. Only the destination endpoint can consume this grant.
type delegationBinding struct {
	relay, exit zone.ZonePath
	endpoint    string
	target      string
	route       string
}

func (binding delegationBinding) input(payload []byte) []byte {
	if binding.route != "" {
		return bytes.Join([][]byte{
			[]byte("photon.proxy.chain.v1"), []byte(binding.route), []byte(binding.target), payload,
		}, []byte{0})
	}
	return bytes.Join([][]byte{
		[]byte("photon.proxy.delegation.v1"), []byte(binding.relay), []byte(binding.exit),
		[]byte(binding.endpoint), []byte(binding.target), payload,
	}, []byte{0})
}

func delegationKeyID(public ed25519.PublicKey) string {
	sum := sha256.Sum256(public)
	return delegationEncoding.EncodeToString(sum[:8])
}

func issueDelegation(key ed25519.PrivateKey, source zone.ZonePath, binding delegationBinding, udp string, now time.Time) (string, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	public := key.Public().(ed25519.PublicKey)
	payload, err := json.Marshal(delegationGrant{
		Source: source, KeyID: delegationKeyID(public), Issued: now.UnixNano(), Nonce: delegationEncoding.EncodeToString(nonce[:]), UDP: udp,
	})
	if err != nil {
		return "", err
	}
	if delegationEncoding.EncodedLen(len(payload)+ed25519.SignatureSize) > delegationHeaderLimit {
		return "", errors.New("proxy delegation exceeds the 512-byte header budget")
	}
	signature := ed25519.Sign(key, binding.input(payload))
	return delegationEncoding.EncodeToString(append(payload, signature...)), nil
}

func decodeDelegation(header string) (delegationGrant, []byte, []byte, error) {
	var grant delegationGrant
	if len(header) == 0 || len(header) > delegationHeaderLimit {
		return grant, nil, nil, errDenied
	}
	encoded, err := delegationEncoding.DecodeString(header)
	if err != nil || len(encoded) <= ed25519.SignatureSize || delegationEncoding.EncodeToString(encoded) != header {
		return grant, nil, nil, errDenied
	}
	payload, signature := encoded[:len(encoded)-ed25519.SignatureSize], encoded[len(encoded)-ed25519.SignatureSize:]
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&grant); err != nil || !grant.Source.Valid() {
		return grant, nil, nil, errDenied
	}
	if err := decoder.Decode(new(json.RawMessage)); err != io.EOF {
		return grant, nil, nil, errDenied
	}
	nonce, err := delegationEncoding.DecodeString(grant.Nonce)
	if err != nil || len(nonce) != 16 || delegationEncoding.EncodeToString(nonce) != grant.Nonce {
		return grant, nil, nil, errDenied
	}
	return grant, payload, signature, nil
}

type delegationNonce struct {
	source zone.ZonePath
	id     string
}

type delegationVerifier struct {
	endpoint  string
	started   time.Time
	mu        sync.Mutex
	nextSweep time.Time
	used      map[delegationNonce]time.Time
}

func (v *delegationVerifier) verify(access *zoneAccess, via zone.ZonePath, target, header string, now time.Time) (proxyPeer, []netip.Prefix, error) {
	var none proxyPeer
	grant, payload, signature, err := decodeDelegation(header)
	if err != nil || !slices.Contains(access.allowed, grant.Source) || !slices.Contains(access.delegates, via) {
		return none, nil, errDenied
	}
	issued := time.Unix(0, grant.Issued)
	expires := issued.Add(delegationLifetime)
	if issued.Before(v.started) || issued.After(now) || !expires.After(now) {
		return none, nil, errDenied
	}
	exit := access.directory.managedZone()
	local, localOK := access.directory.peer(exit)
	remote, remoteOK := access.directory.peer(grant.Source)
	if !localOK || local.Relay || local.Address != v.endpoint || !remoteOK {
		return none, nil, errDenied
	}
	public, err := delegationEncoding.DecodeString(remote.DelegationKey)
	if err != nil || len(public) != ed25519.PublicKeySize || delegationKeyID(public) != grant.KeyID {
		return none, nil, errDenied
	}
	var scope []netip.Prefix
	if target == trusttunnel.UDPAuthority {
		scope, err = parseAllowed(grant.UDP)
	} else if grant.UDP != "" {
		err = errDenied
	} else {
		_, err = splitTarget(target)
	}
	if err != nil {
		return none, nil, errDenied
	}
	binding := delegationBinding{relay: via, exit: exit, endpoint: v.endpoint, target: target}
	if !ed25519.Verify(public, binding.input(payload), signature) ||
		!v.consume(delegationNonce{source: grant.Source, id: grant.Nonce}, now, expires) {
		return none, nil, errDenied
	}
	return proxyPeer{zone: grant.Source, pin: remote.SPKI, delegationKey: remote.DelegationKey}, scope, nil
}

func (v *delegationVerifier) consume(nonce delegationNonce, now, expires time.Time) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	if !now.Before(v.nextSweep) {
		for key, deadline := range v.used {
			if !deadline.After(now) {
				delete(v.used, key)
			}
		}
		v.nextSweep = now.Add(time.Second)
	}
	if _, exists := v.used[nonce]; exists || len(v.used) >= delegationReplayLimit {
		return false
	}
	if v.used == nil {
		v.used = make(map[delegationNonce]time.Time)
	}
	v.used[nonce] = expires
	return true
}

func readDelegationPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("expected a PEM Ed25519 public key")
	}
	value, err := x509.ParsePKIXPublicKey(block.Bytes)
	key, ok := value.(ed25519.PublicKey)
	if err != nil || !ok {
		return nil, errors.New("expected a PEM Ed25519 public key")
	}
	return key, nil
}

func readDelegationPrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("expected a PEM PKCS#8 Ed25519 private key")
	}
	value, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	key, ok := value.(ed25519.PrivateKey)
	if err != nil || !ok {
		return nil, errors.New("expected a PEM PKCS#8 Ed25519 private key")
	}
	return key, nil
}
