package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/HiggsNet/photon/internal/trusttunnel"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/service"
)

const (
	v2Authority       = "_photon_relay_chain_v2"
	v2RouteHeader     = "Photon-Proxy-Route"
	v2TargetHeader    = "Photon-Proxy-Target"
	v2AuthHeader      = "Photon-Proxy-Auth"
	v2ErrorHeader     = "Photon-Proxy-Error"
	v2FailedHopHeader = "Photon-Proxy-Failed-Hop"
	v2Lifetime        = 120 * time.Second
	v2AuthSize        = 8 + 8 + 1 + 16
)

type v2Hop struct {
	Zone     zone.ZonePath
	Endpoint string
	Link     string
}

func v2Link(link string) (transport, via string) {
	switch link {
	case "h24":
		return "h2", "public-v4"
	case "h26":
		return "h2", "public-v6"
	case "h2p":
		return "h2", "photon"
	default:
		return "", ""
	}
}

func validV2ZoneName(value string) bool {
	if len(value) == 0 || len(value) > 253 {
		return false
	}
	for _, letter := range value {
		if (letter >= 'a' && letter <= 'z') || (letter >= 'A' && letter <= 'Z') ||
			(letter >= '0' && letter <= '9') || strings.ContainsRune("-_.", letter) {
			continue
		}
		return false
	}
	return !strings.Contains(value, "..") && value[0] != '.'
}

func v2Hops(value string, origin zone.ZonePath) ([]v2Hop, error) {
	if !origin.Valid() || !validV2ZoneName(origin.String()) || len(value) == 0 || len(value) > chainRouteLimit {
		return nil, errors.New("invalid proxy v2 route or origin")
	}
	parts := strings.Split(value, ",")
	if len(parts) > chainHopLimit {
		return nil, errors.New("proxy route has too many hops")
	}
	seen := map[zone.ZonePath]bool{origin: true}
	hops := make([]v2Hop, 0, len(parts))
	for i, part := range parts {
		name, link, ok := strings.Cut(part, "@")
		if transport, _ := v2Link(link); !ok || transport == "" {
			return nil, fmt.Errorf("invalid link in hop %q", part)
		}
		node, endpoint, explicit := strings.Cut(name, "/")
		if !validV2ZoneName(node) {
			return nil, fmt.Errorf("invalid Zone %q", node)
		}
		if !strings.HasSuffix(node, ".") {
			if parent := origin.Parent(); !parent.IsRoot() {
				node += "." + parent.String()
			} else {
				node += "."
			}
		}
		path := zone.ZonePath(node)
		if seen[path] || !validV2ZoneName(node) {
			return nil, fmt.Errorf("invalid or repeated Zone %q", path)
		}
		seen[path] = true
		if i < len(parts)-1 {
			if explicit {
				return nil, errors.New("middle hops use the Zone's single relay")
			}
			endpoint = "relay"
		} else if !explicit {
			endpoint = "exit"
		}
		if !service.ProxyV2ID(endpoint) || (i == len(parts)-1 && endpoint == "relay") {
			return nil, fmt.Errorf("invalid exit endpoint %q", endpoint)
		}
		hops = append(hops, v2Hop{Zone: path, Endpoint: endpoint, Link: link})
	}
	return hops, nil
}

type v2Target struct {
	protocol string
	address  string
	udpScope string
}

func parseV2Target(value string) (v2Target, error) {
	protocol, data, ok := strings.Cut(value, "=")
	if !ok || data == "" || len(value) > chainRouteLimit || strings.ContainsAny(data, " \t\r\n\x00") {
		return v2Target{}, errors.New("invalid proxy v2 target")
	}
	switch protocol {
	case "tcp":
		if _, err := splitTarget(data); err != nil {
			return v2Target{}, err
		}
		return v2Target{protocol: protocol, address: data}, nil
	case "udp":
		scope, err := normalizeUDPScope(data)
		if err != nil || scope == "" {
			return v2Target{}, errors.New("UDP requires an explicit prefix scope")
		}
		return v2Target{protocol: protocol, address: trusttunnel.UDPAuthority, udpScope: scope}, nil
	default:
		return v2Target{}, errors.New("invalid proxy v2 target protocol")
	}
}

type v2Grant struct {
	origin    zone.ZonePath
	issued    time.Time
	expires   time.Time
	nonce     string
	metadata  []byte
	signature []byte
}

func v2SigInput(origin, route, target string, metadata []byte) []byte {
	return bytes.Join([][]byte{[]byte("photon.proxy.chain.v2"), []byte(origin), []byte(route), []byte(target), metadata}, []byte{0})
}

func signV2Route(key ed25519.PrivateKey, origin zone.ZonePath, route, target string, now time.Time) (http.Header, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid route signing key")
	}
	if _, err := v2Hops(route, origin); err != nil {
		return nil, err
	}
	if _, err := parseV2Target(target); err != nil {
		return nil, err
	}
	var metadata [v2AuthSize]byte
	id := sha256.Sum256(key.Public().(ed25519.PublicKey))
	copy(metadata[:8], id[:8])
	binary.BigEndian.PutUint64(metadata[8:16], uint64(now.UnixMilli()))
	metadata[16] = byte(v2Lifetime / time.Second)
	if _, err := rand.Read(metadata[17:]); err != nil {
		return nil, err
	}
	sig := ed25519.Sign(key, v2SigInput(origin.String(), route, target, metadata[:]))
	return http.Header{
		v2RouteHeader:  {route},
		v2TargetHeader: {target},
		v2AuthHeader:   {origin.String() + "~" + delegationEncoding.EncodeToString(append(metadata[:], sig...))},
	}, nil
}

func parseV2Grant(value string) (v2Grant, error) {
	source, encoded, ok := strings.Cut(value, "~")
	if !ok || !validV2ZoneName(source) || !zone.ZonePath(source).Valid() ||
		len(encoded) != delegationEncoding.EncodedLen(v2AuthSize+ed25519.SignatureSize) {
		return v2Grant{}, errors.New("invalid proxy v2 authorization")
	}
	raw, err := delegationEncoding.DecodeString(encoded)
	if err != nil || len(raw) != v2AuthSize+ed25519.SignatureSize || raw[16] == 0 || time.Duration(raw[16])*time.Second > v2Lifetime {
		return v2Grant{}, errors.New("invalid proxy v2 authorization encoding")
	}
	issued := time.UnixMilli(int64(binary.BigEndian.Uint64(raw[8:16])))
	return v2Grant{origin: zone.ZonePath(source), issued: issued, expires: issued.Add(time.Duration(raw[16]) * time.Second),
		metadata: raw[:v2AuthSize], signature: raw[v2AuthSize:], nonce: string(raw[17:v2AuthSize])}, nil
}

func (g v2Grant) verifies(publicKey, route, target string, now, started time.Time) bool {
	if len(g.metadata) != v2AuthSize || g.issued.Before(started.Truncate(time.Millisecond)) || g.issued.After(now.Add(2*time.Second)) || !g.expires.After(now) {
		return false
	}
	raw, err := delegationEncoding.DecodeString(publicKey)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return false
	}
	id := sha256.Sum256(raw)
	return bytes.Equal(id[:8], g.metadata[:8]) &&
		ed25519.Verify(ed25519.PublicKey(raw), v2SigInput(g.origin.String(), route, target, g.metadata), g.signature)
}

func v2WriteError(w http.ResponseWriter, status int, code string, hop int) {
	w.Header().Set(v2ErrorHeader, code)
	if hop >= 0 {
		w.Header().Set(v2FailedHopHeader, strconv.Itoa(hop))
	}
	w.WriteHeader(status)
}
