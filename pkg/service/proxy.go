package service

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

const (
	RecordKeyProxy         = "services/proxy"
	RecordTypeProxy        = "service.proxy.v1"
	ProxyTransport         = "trusttunnel+h2"
	ProxyDirectoryMaxBytes = 1 << 20
)

// ProxyCapability binds a data-plane identity to the Zone that signs the record.
// A record without an address can authenticate a client-only proxy.
type ProxyCapability struct {
	Active        bool              `json:"active"`
	ExpiresAt     time.Time         `json:"expires_at"`
	SPKI          string            `json:"tls_spki_sha256,omitempty"`
	Address       string            `json:"address,omitempty"`
	Transport     string            `json:"transport,omitempty"`
	Relay         bool              `json:"relay,omitempty"`
	DelegationKey string            `json:"delegation_key,omitempty"`
	Endpoints     map[string]string `json:"endpoints,omitempty"`
}

func ProxyPublicKeyID(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(hash[:])
}

func (r ProxyCapability) Validate() error {
	signingOnly := r.SPKI == "" && r.Address == "" && len(r.Endpoints) == 0 && r.DelegationKey != ""
	if raw, err := hex.DecodeString(r.SPKI); !signingOnly &&
		(err != nil || len(raw) != sha256.Size || strings.ToLower(r.SPKI) != r.SPKI) {
		return errors.New("proxy record requires a lowercase SHA-256 public key fingerprint")
	}
	if r.ExpiresAt.IsZero() {
		return errors.New("proxy record requires an expiration time")
	}
	if r.DelegationKey != "" {
		decoded, err := base64.RawURLEncoding.Strict().DecodeString(r.DelegationKey)
		if err != nil || len(decoded) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(decoded) != r.DelegationKey {
			return errors.New("invalid proxy delegation public key")
		}
	}
	if r.Address == "" && len(r.Endpoints) == 0 && r.Transport == "" {
		if r.Relay {
			return errors.New("proxy relay needs an endpoint")
		}
		return nil
	}
	if r.Transport != ProxyTransport {
		return errors.New("unsupported proxy transport")
	}
	for name, address := range r.Endpoints {
		if err := ValidateProxyEndpoint(name, address); err != nil {
			return err
		}
	}
	if r.Address == "" {
		if len(r.Endpoints) == 0 {
			return errors.New("proxy transport needs an endpoint")
		}
		return nil
	}
	return validateProxyAddress(r.Address)
}

func ProxyEndpointNameValid(name string) bool {
	return name == "public-v4" || name == "public-v6" || name == "photon"
}

func ValidateProxyEndpoint(name, address string) error {
	if !ProxyEndpointNameValid(name) {
		return errors.New("proxy endpoint name must be public-v4, public-v6 or photon")
	}
	if err := validateProxyAddress(address); err != nil {
		return err
	}
	host, _, _ := net.SplitHostPort(address)
	ip := net.ParseIP(host)
	switch name {
	case "public-v4":
		if ip != nil && ip.To4() == nil {
			return errors.New("public-v4 requires IPv4")
		}
	case "public-v6":
		if ip != nil && ip.To4() != nil {
			return errors.New("public-v6 requires IPv6")
		}
	case "photon":
		if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			return errors.New("photon requires a routable mesh IP literal")
		}
	}
	return nil
}

func validateProxyAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || strings.ContainsAny(host, "[]/%?#\\@,= \t\n\r\x00") || len(host) > 253 {
		return errors.New("invalid proxy endpoint host:port")
	}
	if ip := net.ParseIP(host); ip != nil && (ip.IsUnspecified() || ip.IsMulticast()) {
		return errors.New("proxy endpoint requires a unicast host address")
	}
	if number, err := strconv.ParseUint(port, 10, 16); err != nil || number == 0 {
		return errors.New("invalid proxy endpoint port")
	}
	return nil
}

func ParseProxyCapability(record *zone.Record) (ProxyCapability, error) {
	var value ProxyCapability
	if record == nil || record.Key != RecordKeyProxy || record.Type != RecordTypeProxy {
		return value, errors.New("expected Photon Proxy capability record")
	}
	decoder := json.NewDecoder(bytes.NewReader(record.Value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return value, err
	}
	if err := requireJSONEOF(decoder); err != nil {
		return value, err
	}
	return value, value.Validate()
}

// ProxyDirectory is a bounded-lifetime view built by the local proxy.
type ProxyDirectory struct {
	ManagedZone  zone.ZonePath                     `json:"managed_zone"`
	ValidUntil   time.Time                         `json:"valid_until"`
	Peers        map[zone.ZonePath]ProxyCapability `json:"peers"`
	V2           map[zone.ZonePath]ProxyV2Peer     `json:"v2,omitempty"`
	MeshPrefixes []string                          `json:"mesh_prefixes,omitempty"`
}

type ProxyMutation struct {
	Record          *ProxyCapability `json:"record,omitempty"`
	ExpectedVersion *uint64          `json:"expected_version,omitempty"`
	AnnouncePort    uint16           `json:"announce_port,omitempty"`
}
