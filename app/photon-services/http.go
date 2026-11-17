package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"

	service "github.com/HiggsNet/photon/pkg/service"
)

type httpConfig struct {
	Publish    publishConfig     `yaml:"publish"`
	Networks   map[string]string `yaml:"networks"`
	Port       uint16            `yaml:"port,omitempty"`
	AllowZones []string          `yaml:"allow_zones,omitempty"`
	Resolver   resolverConfig    `yaml:"resolver,omitempty"`
	Auth       proxyAuthConfig   `yaml:"auth,omitempty"`
}

func (c *httpConfig) configured() bool {
	return c != nil && (len(c.Publish) != 0 || len(c.Networks) != 0 || c.Port != 0 || len(c.AllowZones) != 0 || c.Resolver.Mode != "" || len(c.Resolver.Servers) != 0 || c.Auth != (proxyAuthConfig{}))
}

type resolvedHTTP struct {
	Port       uint16             `json:"port"`
	AllowZones []string           `json:"allow_zones,omitempty"`
	Resolver   resolverConfig     `json:"resolver"`
	Auth       proxyAuthConfig    `json:"-"`
	ConfigHash string             `json:"config_hash"`
	Endpoints  []resolvedEndpoint `json:"endpoints"`
}

func (c resolvedHTTP) configured() bool { return c.ConfigHash != "" }

func resolveHTTP(config httpConfig, networks map[string]resolvedNetwork) (resolvedHTTP, error) {
	var result resolvedHTTP
	if len(config.Publish) == 0 || len(config.Networks) == 0 {
		return result, fmt.Errorf("http.publish and http.networks are required")
	}
	if config.Port == 0 {
		config.Port = 3128
	}
	result.Port = config.Port
	resolver, err := normalizeResolver(config.Resolver)
	if err != nil {
		return result, fmt.Errorf("http.resolver: %w", err)
	}
	result.Resolver = resolver
	if config.Auth != (proxyAuthConfig{}) {
		auth, err := normalizeHTTPAuth(config.Auth)
		if err != nil {
			return result, fmt.Errorf("http.auth: %w", err)
		}
		result.Auth = auth
	}
	for _, raw := range config.AllowZones {
		selector, err := service.ParseZoneSelector(raw)
		if err != nil {
			return result, fmt.Errorf("http.allow_zones: %w", err)
		}
		result.AllowZones = append(result.AllowZones, selector.String())
	}
	for name, region := range config.Publish {
		if len("http-"+name) > 63 {
			return result, fmt.Errorf("http network name is too long")
		}
		network, ok := networks[name]
		if !ok {
			return result, fmt.Errorf("http: unknown network %q", name)
		}
		raw, ok := config.Networks[name]
		if !ok {
			return result, fmt.Errorf("http publish network %q is not attached", name)
		}
		address, ipam, err := resolveServiceBase(raw, network)
		if err != nil {
			return result, fmt.Errorf("http network %s: %w", name, err)
		}
		if _, err := resolveProxyAddresses(address, *ipam, false); err != nil {
			return result, fmt.Errorf("http network %s: %w", name, err)
		}
		if ipam.Assignment == "" {
			return result, fmt.Errorf("http requires an IPAM assignment")
		}
		prefix := netip.MustParsePrefix(ipam.Assignment)
		maxBits := 96
		if prefix.Addr().Is4() {
			maxBits = 28
		}
		if prefix.Bits() > maxBits {
			return result, fmt.Errorf("http assignment exceeds Babel /%d limit", maxBits)
		}
		result.Endpoints = append(result.Endpoints, resolvedEndpoint{Network: name, Region: region, Address: address.String(), Port: config.Port, Assignment: ipam.Assignment, Shared: ipam.Shared, AssignmentTag: ipam.Tag})
	}
	for name := range config.Networks {
		if _, ok := config.Publish[name]; !ok {
			return result, fmt.Errorf("http network %q is not published", name)
		}
	}
	var endpoints []service.SOCKS5Endpoint
	for _, e := range result.Endpoints {
		endpoints = append(endpoints, service.SOCKS5Endpoint{Region: e.Region, Address: e.Address, Port: e.Port})
	}
	if err := (service.SOCKS5Record{Type: service.TypeSOCKS5, Endpoints: endpoints}).Validate(); err != nil {
		return result, fmt.Errorf("http endpoints: %w", err)
	}
	sort.Slice(result.Endpoints, func(i, j int) bool { return result.Endpoints[i].Network < result.Endpoints[j].Network })
	encoded, err := json.Marshal(struct {
		Config   httpConfig
		Networks map[string]resolvedNetwork
	}{config, networks})
	if err != nil {
		return result, err
	}
	hash := sha256.Sum256(encoded)
	result.ConfigHash = hex.EncodeToString(hash[:])
	return result, nil
}

func validateProxyAddressConflicts(manifest resolvedManifest) error {
	addresses := map[string]string{}
	claim := func(address, kind string) error {
		if address == "" {
			return nil
		}
		if old, ok := addresses[address]; ok {
			return fmt.Errorf("%s address %s conflicts with %s container", kind, address, old)
		}
		addresses[address] = kind
		return nil
	}
	for _, role := range manifest.SOCKS5.Networks {
		if err := claim(role.SOCKS, "socks5"); err != nil {
			return err
		}
		if err := claim(role.H2, "legacy http"); err != nil {
			return err
		}
	}
	for _, e := range manifest.HTTP.Endpoints {
		if err := claim(e.Address, "http"); err != nil {
			return err
		}
	}
	for _, e := range manifest.TrustTunnel.Endpoints {
		if err := claim(e.Address, "trusttunnel"); err != nil {
			return err
		}
	}
	return nil
}
