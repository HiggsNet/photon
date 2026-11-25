package service

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

const (
	ProxyV2Prefix         = "services/proxy/v2/"
	ProxyV2IdentityType   = "service.proxy.identity.v2"
	ProxyV2EndpointType   = "service.proxy.endpoint.v2"
	ProxyV2TLSType        = "service.proxy.tls.v2"
	ProxyV2IdentityKey    = ProxyV2Prefix + "identity"
	ProxyV2EndpointPrefix = ProxyV2Prefix + "endpoints/"
	ProxyV2TLSPrefix      = ProxyV2Prefix + "tls/"
)

var proxyV2IDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

func ProxyV2ID(id string) bool { return proxyV2IDPattern.MatchString(id) }

// ProxyV2Lease belongs to a signed Zone record. Time is in Unix seconds.
type ProxyV2Lease struct {
	Active    bool  `json:"active"`
	ExpiresAt int64 `json:"expires_at"`
}

func (l ProxyV2Lease) ValidAt(now time.Time) bool { return l.Active && l.ExpiresAt > now.Unix() }

type ProxyV2Identity struct {
	ProxyV2Lease
	PublicKey string `json:"public_key"`
}

type ProxyV2TLS struct {
	ProxyV2Lease
	Pins []string `json:"spki_sha256"`
}

type ProxyV2Endpoint struct {
	ProxyV2Lease
	Role     string              `json:"role"`
	Bindings []ProxyV2Binding    `json:"bindings"`
	Relay    *ProxyV2RelayPolicy `json:"relay_policy,omitempty"`
	Exit     *ProxyV2ExitPolicy  `json:"exit_policy,omitempty"`
}

type ProxyV2Binding struct {
	Transport string                  `json:"transport" yaml:"transport"`
	TLSID     string                  `json:"tls_id" yaml:"tls_id"`
	Addresses []ProxyV2Address        `json:"addresses" yaml:"addresses"`
	PortSets  map[string]ProxyV2Ports `json:"port_sets" yaml:"-"`
	Protocols []string                `json:"protocols" yaml:"protocols"`
}

type ProxyV2Address struct {
	Host    string   `json:"host,omitempty" yaml:"host,omitempty"`
	Source  string   `json:"source,omitempty" yaml:"source,omitempty"`
	Via     []string `json:"via" yaml:"via"`
	PortSet string   `json:"port_set" yaml:"port_set"`
}

type ProxyV2Port struct {
	Generation uint64 `json:"generation"`
	Port       uint16 `json:"port"`
}

type ProxyV2Ports struct {
	Current  ProxyV2Port  `json:"current"`
	Previous *ProxyV2Port `json:"previous,omitempty"`
}

type ProxyV2ZonePolicy struct {
	AcceptFrom []string `json:"accept_from" yaml:"accept_from"`
	DenyFrom   []string `json:"deny_from" yaml:"deny_from"`
}

type ProxyV2RelayPolicy struct {
	ProxyV2ZonePolicy `yaml:",inline"`
	AcceptTo          []string `json:"accept_to" yaml:"accept_to"`
	DenyTo            []string `json:"deny_to" yaml:"deny_to"`
}

type ProxyV2ExitPolicy struct {
	ProxyV2ZonePolicy `yaml:",inline"`
	AcceptTo          []ProxyV2Destination `json:"accept_to" yaml:"accept_to"`
	DenyTo            []ProxyV2Destination `json:"deny_to" yaml:"deny_to"`
}

type ProxyV2Destination struct {
	CIDR      string   `json:"cidr,omitempty" yaml:"cidr,omitempty"`
	Scope     string   `json:"scope,omitempty" yaml:"scope,omitempty"`
	Protocols []string `json:"protocols,omitempty" yaml:"protocols,omitempty"`
	Ports     []uint16 `json:"ports,omitempty" yaml:"ports,omitempty"`
}

type ProxyV2Peer struct {
	Identity  *ProxyV2Identity           `json:"identity,omitempty"`
	Endpoints map[string]ProxyV2Endpoint `json:"endpoints,omitempty"`
	TLS       map[string]ProxyV2TLS      `json:"tls,omitempty"`
	Mesh      []string                   `json:"mesh,omitempty"`
	IPsec     []string                   `json:"ipsec,omitempty"`
}

type ProxyV2Publication struct {
	Records []ProxyV2Record `json:"records"`
	// Replace withdraws records omitted by the single local publisher.
	Replace bool `json:"replace,omitempty"`
}

type ProxyV2Record struct {
	Key   string          `json:"key"`
	Type  string          `json:"type"`
	Value json.RawMessage `json:"value"`
}

type ProxyV2PublicationResult struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

func ParseProxyV2Record(record ProxyV2Record) (any, ProxyV2Lease, error) {
	var lease ProxyV2Lease
	var body any
	switch {
	case record.Type == ProxyV2IdentityType && record.Key == ProxyV2IdentityKey:
		body = new(ProxyV2Identity)
	case record.Type == ProxyV2EndpointType &&
		strings.HasPrefix(record.Key, ProxyV2EndpointPrefix) &&
		ProxyV2ID(strings.TrimPrefix(record.Key, ProxyV2EndpointPrefix)):
		body = new(ProxyV2Endpoint)
	case record.Type == ProxyV2TLSType &&
		strings.HasPrefix(record.Key, ProxyV2TLSPrefix) &&
		ProxyV2ID(strings.TrimPrefix(record.Key, ProxyV2TLSPrefix)):
		body = new(ProxyV2TLS)
	default:
		return nil, lease, errors.New("invalid proxy v2 record type or key")
	}
	decoder := json.NewDecoder(bytes.NewReader(record.Value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(body); err != nil {
		return nil, lease, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, lease, errors.New("proxy record must have a single JSON value")
	}
	var err error
	switch value := body.(type) {
	case *ProxyV2Identity:
		lease = value.ProxyV2Lease
		if key, decodeErr := base64.RawURLEncoding.Strict().DecodeString(value.PublicKey); decodeErr != nil || len(key) != 32 {
			err = errors.New("invalid Ed25519 route signing key")
		}
	case *ProxyV2TLS:
		lease = value.ProxyV2Lease
		if len(value.Pins) < 1 || len(value.Pins) > 2 {
			err = errors.New("TLS identity requires one or two pins")
		}
		for _, pin := range value.Pins {
			if raw, decodeErr := hex.DecodeString(pin); decodeErr != nil || len(raw) != 32 || strings.ToLower(pin) != pin {
				err = errors.New("invalid TLS SPKI pin")
			}
		}
	case *ProxyV2Endpoint:
		lease = value.ProxyV2Lease
		err = value.Validate(strings.TrimPrefix(record.Key, ProxyV2EndpointPrefix))
	}
	if lease.ExpiresAt <= 0 {
		return nil, lease, errors.New("proxy record expiration is required")
	}
	return body, lease, err
}

func (e ProxyV2Endpoint) Validate(id string) error {
	switch e.Role {
	case "relay":
		if id != "relay" || e.Relay == nil || e.Exit != nil {
			return errors.New("the relay endpoint must be named relay and have a relay policy")
		}
		if _, err := CompileProxyV2Relay(*e.Relay); err != nil {
			return err
		}
	case "exit":
		if id == "relay" || e.Relay != nil {
			return errors.New("invalid exit endpoint")
		}
		if e.Exit != nil {
			if _, err := CompileProxyV2Exit(*e.Exit); err != nil {
				return err
			}
		}
	default:
		return errors.New("invalid proxy endpoint role")
	}
	if len(e.Bindings) == 0 || len(e.Bindings) > 8 {
		return errors.New("proxy endpoint needs one to eight bindings")
	}
	seen := make(map[string]bool)
	for _, binding := range e.Bindings {
		if !ProxyV2ID(binding.Transport) || seen[binding.Transport] || !ProxyV2ID(binding.TLSID) ||
			!validProxyV2Protocols(binding.Protocols) || len(binding.Protocols) == 0 ||
			len(binding.Addresses) == 0 || len(binding.Addresses) > 64 {
			return errors.New("invalid proxy binding")
		}
		seen[binding.Transport] = true
		for _, address := range binding.Addresses {
			ports, ok := binding.PortSets[address.PortSet]
			if !ok || !ProxyV2ID(address.PortSet) || !ports.valid() || len(address.Via) == 0 || len(address.Via) > 3 {
				return errors.New("invalid proxy address port set or dial mode")
			}
			if err := address.validate(); err != nil {
				return err
			}
		}
	}
	return nil
}

func (p ProxyV2Ports) valid() bool {
	return p.Current.Port != 0 && p.Current.Generation != 0 &&
		(p.Previous == nil || (p.Previous.Port != 0 && p.Previous.Port != p.Current.Port &&
			p.Previous.Generation > 0 && p.Previous.Generation < p.Current.Generation))
}

func (a ProxyV2Address) validate() error {
	if a.Source == "" && (a.Host == "" || len(a.Host) > 253 ||
		strings.ContainsAny(a.Host, "[]/%?#\\@,= \t\r\n\x00") ||
		strings.Contains(a.Host, ":") && !validProxyV2IP(a.Host)) {
		return errors.New("invalid proxy host")
	}
	if a.Source != "" && (a.Host != "" || a.Source != "ipsec" && a.Source != "route-local" && a.Source != "link-local") {
		return errors.New("proxy address source must be ipsec, route-local or link-local")
	}
	for _, via := range a.Via {
		switch via {
		case "photon":
			if a.Source != "route-local" {
				return errors.New("photon addresses must come from route-local")
			}
		case "public-v4", "public-v6":
			if a.Source == "route-local" || a.Source == "link-local" {
				return errors.New("public addresses must be static or come from IPsec announcements")
			}
			if address, err := netip.ParseAddr(a.Host); err == nil {
				if address.Unmap().Is4() != (via == "public-v4") {
					return errors.New("proxy address family and dial mode differ")
				}
			}
		case "link-local-v4", "link-local-v6":
			if a.Source != "link-local" {
				return errors.New("direct Photon addresses must come from link-local")
			}
		default:
			return fmt.Errorf("unknown proxy dial mode %q", via)
		}
	}
	return nil
}

func validProxyV2IP(host string) bool {
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.Zone() == ""
}

func validProxyV2Protocols(protocols []string) bool {
	for _, protocol := range protocols {
		if protocol != "tcp" && protocol != "udp" {
			return false
		}
	}
	return true
}

type proxyV2ZoneList []func(zone.ZonePath) bool

func compileProxyV2Zones(values []string) (proxyV2ZoneList, error) {
	if len(values) > 256 {
		return nil, errors.New("too many Zone expressions")
	}
	var matches proxyV2ZoneList
	for _, value := range values {
		if pattern, ok := strings.CutPrefix(value, "re:"); ok {
			if pattern == "" || len(pattern) > 512 {
				return nil, errors.New("invalid Zone regular expression length")
			}
			expression, err := regexp.Compile(`\A(?:` + pattern + `)\z`)
			if err != nil {
				return nil, fmt.Errorf("Zone expression %q: %w", value, err)
			}
			matches = append(matches, func(candidate zone.ZonePath) bool { return expression.MatchString(candidate.String()) })
			continue
		}
		selector, err := ParseZoneSelector(value)
		if err != nil {
			return nil, err
		}
		matches = append(matches, selector.Matches)
	}
	return matches, nil
}

func (list proxyV2ZoneList) matches(value zone.ZonePath) bool {
	return value.Valid() && !value.IsRoot() && slices.ContainsFunc(list, func(match func(zone.ZonePath) bool) bool { return match(value) })
}

type ProxyV2RelayACL struct{ from, denyFrom, to, denyTo proxyV2ZoneList }

func CompileProxyV2Relay(p ProxyV2RelayPolicy) (ProxyV2RelayACL, error) {
	var acl ProxyV2RelayACL
	for i, raw := range [][]string{p.AcceptFrom, p.DenyFrom, p.AcceptTo, p.DenyTo} {
		list, err := compileProxyV2Zones(raw)
		if err != nil {
			return acl, err
		}
		*[]*proxyV2ZoneList{&acl.from, &acl.denyFrom, &acl.to, &acl.denyTo}[i] = list
	}
	return acl, nil
}

func (a ProxyV2RelayACL) Allows(from, next zone.ZonePath) bool {
	return a.AllowsSource(from) && a.to.matches(next) && !a.denyTo.matches(next)
}

func (a ProxyV2RelayACL) AllowsSource(from zone.ZonePath) bool {
	return a.from.matches(from) && !a.denyFrom.matches(from)
}

type ProxyV2ExitACL struct {
	from, denyFrom proxyV2ZoneList
	to, denyTo     []proxyV2TargetMatcher
}

type proxyV2TargetMatcher struct {
	prefix    netip.Prefix
	public    bool
	protocols []string
	ports     []uint16
}

func CompileProxyV2Exit(p ProxyV2ExitPolicy) (ProxyV2ExitACL, error) {
	var acl ProxyV2ExitACL
	var err error
	if acl.from, err = compileProxyV2Zones(p.AcceptFrom); err != nil {
		return acl, err
	}
	if acl.denyFrom, err = compileProxyV2Zones(p.DenyFrom); err != nil {
		return acl, err
	}
	if acl.to, err = compileProxyV2Targets(p.AcceptTo); err != nil {
		return acl, err
	}
	acl.denyTo, err = compileProxyV2Targets(p.DenyTo)
	return acl, err
}

func compileProxyV2Targets(rules []ProxyV2Destination) ([]proxyV2TargetMatcher, error) {
	if len(rules) > 256 {
		return nil, errors.New("too many proxy destination rules")
	}
	out := make([]proxyV2TargetMatcher, 0, len(rules))
	for _, rule := range rules {
		m := proxyV2TargetMatcher{public: rule.Scope == "public", protocols: rule.Protocols, ports: rule.Ports}
		if !validProxyV2Protocols(rule.Protocols) || slices.Contains(rule.Ports, 0) {
			return nil, errors.New("invalid proxy destination protocols or ports")
		}
		if m.public && rule.CIDR == "" {
			out = append(out, m)
			continue
		}
		prefix, err := netip.ParsePrefix(rule.CIDR)
		if rule.Scope != "" || err != nil {
			return nil, errors.New("destination rule requires a CIDR or scope: public")
		}
		m.prefix = prefix.Masked()
		out = append(out, m)
	}
	return out, nil
}

func (a ProxyV2ExitACL) AllowsSource(from zone.ZonePath) bool {
	return a.from.matches(from) && !a.denyFrom.matches(from)
}

func (a ProxyV2ExitACL) AllowsTarget(protocol string, target netip.AddrPort) bool {
	return a.AllowsTargetWithPublicFilter(protocol, target, nil)
}

// AllowsTargetWithPublicFilter removes node-local and mesh addresses from the
// public scope without changing the interpretation of explicit CIDRs.
func (a ProxyV2ExitACL) AllowsTargetWithPublicFilter(protocol string, target netip.AddrPort, excludePublic func(netip.Addr) bool) bool {
	address := target.Addr().Unmap()
	if !address.IsValid() || address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() ||
		address.IsLinkLocalUnicast() || address == netip.MustParseAddr("255.255.255.255") || target.Port() == 0 {
		return false
	}
	match := func(m proxyV2TargetMatcher) bool {
		return (m.prefix.Contains(address) || m.public && ProxyV2PublicAddress(address)) &&
			(len(m.protocols) == 0 || slices.Contains(m.protocols, protocol)) &&
			(len(m.ports) == 0 || slices.Contains(m.ports, target.Port()))
	}
	return slices.ContainsFunc(a.to, func(m proxyV2TargetMatcher) bool {
		return match(m) && (!m.public || excludePublic == nil || !excludePublic(address))
	}) && !slices.ContainsFunc(a.denyTo, match)
}

var proxyV2NonPublic = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
}
var proxyV2GlobalIPv6 = netip.MustParsePrefix("2000::/3")

func ProxyV2PublicAddress(address netip.Addr) bool {
	address = address.Unmap()
	return address.IsGlobalUnicast() && address.Zone() == "" && !address.IsPrivate() &&
		(address.Is4() || proxyV2GlobalIPv6.Contains(address)) &&
		!slices.ContainsFunc(proxyV2NonPublic, func(prefix netip.Prefix) bool { return prefix.Contains(address) })
}
