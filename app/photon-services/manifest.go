package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"

	photonservice "github.com/HiggsNet/photon/pkg/service"
	"gopkg.in/yaml.v3"
)

const (
	defaultOutputDir = "/etc/photon/services"
	defaultGostImage = "gogost/gost:3.2.6"
	defaultHTTPUser  = "photon"
	defaultHTTPPass  = "2a0d"
)

type manifest struct {
	Version         int                      `yaml:"version"`
	OutputDir       string                   `yaml:"output_dir,omitempty"`
	Images          imageConfig              `yaml:"images,omitempty"`
	NetworkDefaults networkDefaults          `yaml:"network_defaults,omitempty"`
	Networks        map[string]networkConfig `yaml:"networks"`
	HTTP            *httpConfig              `yaml:"http,omitempty"`
	SOCKS5          socks5Config             `yaml:"socks5"`
	TrustTunnel     trustTunnelConfig        `yaml:"trusttunnel,omitempty"`
}

type imageConfig struct {
	Gost   string `yaml:"gost,omitempty"`
	Mihomo string `yaml:"mihomo,omitempty"`
}

type networkConfig struct {
	IPv4                  string   `yaml:"ipv4,omitempty"`
	IPv6                  string   `yaml:"ipv6,omitempty"`
	TrustedHostInterfaces []string `yaml:"trusted_host_interfaces,omitempty"`
}

type networkDefaults struct {
	TrustedHostInterfaces []string `yaml:"trusted_host_interfaces,omitempty"`
}

type socks5Config struct {
	Region     string            `yaml:"region,omitempty"` // legacy single-endpoint region
	Publish    publishConfig     `yaml:"publish"`
	Port       uint16            `yaml:"port,omitempty"`
	Networks   map[string]string `yaml:"networks"`
	AllowZones []string          `yaml:"allow_zones,omitempty"`
	Resolver   resolverConfig    `yaml:"resolver,omitempty"`
	HTTPAuth   proxyAuthConfig   `yaml:"http_auth,omitempty"`
}

// configured distinguishes an omitted/empty socks5 block from a partially
// configured service. The latter must still go through normal validation so a
// typo such as socks5.networks without socks5.publish does not silently turn
// the manifest into network-only mode.
func (c socks5Config) configured() bool {
	return c.Region != "" ||
		len(c.Publish) != 0 ||
		c.Port != 0 ||
		len(c.Networks) != 0 ||
		len(c.AllowZones) != 0 ||
		c.Resolver.Mode != "" ||
		len(c.Resolver.Servers) != 0 ||
		c.HTTPAuth.Username != "" ||
		c.HTTPAuth.Password != ""
}

type resolverConfig struct {
	Mode    string   `yaml:"mode,omitempty" json:"mode"`
	Servers []string `yaml:"servers,omitempty" json:"servers"`
}

type proxyAuthConfig struct {
	Username string `yaml:"username,omitempty"`
	Password string `yaml:"password,omitempty"`
}

type publishConfig map[string]string

func (p *publishConfig) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		var network string
		if err := node.Decode(&network); err != nil {
			return err
		}
		*p = publishConfig{network: ""}
		return nil
	case yaml.MappingNode:
		var value map[string]string
		if err := node.Decode(&value); err != nil {
			return err
		}
		*p = value
		return nil
	default:
		return fmt.Errorf("publish must be a network-to-region map")
	}
}

type runtimeAssignment struct {
	Prefix string `json:"prefix"`
	Source string `json:"source"`
	Shared bool   `json:"shared,omitempty"`
	Tag    string `json:"tag,omitempty"`
}

type runtimeIPAMReport struct {
	ManagedZone string              `json:"managed_zone"`
	Assignments []runtimeAssignment `json:"assignments"`
}

type assignmentCandidate struct {
	Prefix netip.Prefix
	Shared bool
	Tag    string
}

type resolvedManifest struct {
	ManagedZone string                     `json:"managed_zone"`
	OutputDir   string                     `json:"output_dir"`
	Images      imageConfig                `json:"images"`
	Networks    map[string]resolvedNetwork `json:"networks"`
	SOCKS5      resolvedSOCKS5             `json:"socks5"`
	HTTP        resolvedHTTP               `json:"http,omitempty"`
	TrustTunnel resolvedTrustTunnel        `json:"trusttunnel,omitempty"`
}

type resolvedNetwork struct {
	Name                  string        `json:"name"`
	TrustedHostInterfaces []string      `json:"trusted_host_interfaces,omitempty"`
	IPv4                  *resolvedIPAM `json:"ipv4,omitempty"`
	IPv6                  *resolvedIPAM `json:"ipv6,omitempty"`
}

type resolvedIPAM struct {
	Source     string `json:"source"`
	Assignment string `json:"assignment,omitempty"`
	Subnet     string `json:"subnet"`
	IPRange    string `json:"ip_range"`
	Gateway    string `json:"gateway"`
	Shared     bool   `json:"shared,omitempty"`
	Tag        string `json:"tag,omitempty"`
}

type resolvedSOCKS5 struct {
	Port       uint16                       `json:"port"`
	AllowZones []string                     `json:"allow_zones,omitempty"`
	Resolver   resolverConfig               `json:"resolver"`
	HTTPAuth   proxyAuthConfig              `json:"-"`
	Networks   map[string]resolvedRoleAddrs `json:"networks"`
	ConfigHash string                       `json:"config_hash"`
	Endpoints  []resolvedEndpoint           `json:"endpoints"`
}

func (s resolvedSOCKS5) configured() bool {
	return s.ConfigHash != "" || len(s.Networks) != 0 || len(s.Endpoints) != 0
}

type resolvedEndpoint struct {
	Network       string `json:"network"`
	Region        string `json:"region"`
	Address       string `json:"address"`
	Port          uint16 `json:"port"`
	Assignment    string `json:"assignment"`
	Shared        bool   `json:"shared,omitempty"`
	AssignmentTag string `json:"assignment_tag,omitempty"`
}

type resolvedRoleAddrs struct {
	SOCKS         string `json:"socks"`
	H2            string `json:"h2"`
	Assignment    string `json:"assignment,omitempty"`
	Shared        bool   `json:"shared,omitempty"`
	AssignmentTag string `json:"assignment_tag,omitempty"`
}

func loadManifest(path string) (manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return manifest{}, err
	}
	var value manifest
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&value); err != nil {
		return manifest{}, fmt.Errorf("decode %s: %w", path, err)
	}
	if value.Version == 0 {
		value.Version = 1
	}
	if value.Version != 1 && value.Version != 2 {
		return manifest{}, fmt.Errorf("unsupported service manifest version %d", value.Version)
	}
	if value.OutputDir == "" {
		value.OutputDir = defaultOutputDir
	}
	if value.Images.Mihomo == "" {
		value.Images.Mihomo = defaultMihomoImage
	}
	if len(value.Networks) == 0 {
		return manifest{}, fmt.Errorf("networks is required")
	}
	return value, nil
}

func resolveManifest(value manifest, rawAssignments []runtimeAssignment) (resolvedManifest, error) {
	if value.Version >= 2 && value.Images.Gost != "" {
		return resolvedManifest{}, fmt.Errorf("images.gost is legacy; configure images.mihomo")
	}
	assignments := make([]assignmentCandidate, 0, len(rawAssignments))
	for _, raw := range rawAssignments {
		prefix, err := netip.ParsePrefix(raw.Prefix)
		if err != nil || prefix != prefix.Masked() {
			return resolvedManifest{}, fmt.Errorf("invalid runtime assignment %q", raw.Prefix)
		}
		assignments = append(assignments, assignmentCandidate{Prefix: prefix, Shared: raw.Shared, Tag: raw.Tag})
	}
	result := resolvedManifest{OutputDir: value.OutputDir, Images: value.Images, Networks: map[string]resolvedNetwork{}}
	for name, configured := range value.Networks {
		id, err := photonservice.NormalizeID(name)
		if err != nil {
			return resolvedManifest{}, fmt.Errorf("network name: %w", err)
		}
		if id != name {
			return resolvedManifest{}, fmt.Errorf("network name %q is not canonical; use %q", name, id)
		}
		trustedInterfaceConfig := configured.TrustedHostInterfaces
		if len(trustedInterfaceConfig) == 0 {
			trustedInterfaceConfig = value.NetworkDefaults.TrustedHostInterfaces
		}
		trustedInterfaces, err := normalizeTrustedHostInterfaces(trustedInterfaceConfig)
		if err != nil {
			return resolvedManifest{}, fmt.Errorf("network %s trusted_host_interfaces: %w", name, err)
		}
		network := resolvedNetwork{Name: "photon-" + id, TrustedHostInterfaces: trustedInterfaces}
		if configured.IPv4 != "" {
			resolved, err := resolveDescriptor(configured.IPv4, 4, assignments)
			if err != nil {
				return resolvedManifest{}, fmt.Errorf("network %s ipv4: %w", name, err)
			}
			network.IPv4 = &resolved
		}
		if configured.IPv6 != "" {
			resolved, err := resolveDescriptor(configured.IPv6, 6, assignments)
			if err != nil {
				return resolvedManifest{}, fmt.Errorf("network %s ipv6: %w", name, err)
			}
			network.IPv6 = &resolved
		}
		if network.IPv4 == nil && network.IPv6 == nil {
			return resolvedManifest{}, fmt.Errorf("network %s has no ipv4 or ipv6 plan", name)
		}
		for previousName, previous := range result.Networks {
			if network.IPv4 != nil && previous.IPv4 != nil && netip.MustParsePrefix(network.IPv4.Subnet).Overlaps(netip.MustParsePrefix(previous.IPv4.Subnet)) {
				return resolvedManifest{}, fmt.Errorf("network %s ipv4 subnet %s overlaps network %s subnet %s", name, network.IPv4.Subnet, previousName, previous.IPv4.Subnet)
			}
			if network.IPv6 != nil && previous.IPv6 != nil && netip.MustParsePrefix(network.IPv6.Subnet).Overlaps(netip.MustParsePrefix(previous.IPv6.Subnet)) {
				return resolvedManifest{}, fmt.Errorf("network %s ipv6 subnet %s overlaps network %s subnet %s", name, network.IPv6.Subnet, previousName, previous.IPv6.Subnet)
			}
		}
		result.Networks[name] = network
	}
	if value.TrustTunnel.configured() {
		service, err := resolveTrustTunnel(value.TrustTunnel, result.Networks)
		if err != nil {
			return resolvedManifest{}, err
		}
		result.TrustTunnel = service
	}
	if value.HTTP.configured() {
		service, err := resolveHTTP(*value.HTTP, result.Networks)
		if err != nil {
			return resolvedManifest{}, err
		}
		result.HTTP = service
	}
	if !value.SOCKS5.configured() {
		return result, validateProxyAddressConflicts(result)
	}
	legacyHTTP := value.Version < 2 && value.HTTP == nil
	configured := value.SOCKS5
	if !legacyHTTP && configured.HTTPAuth != (proxyAuthConfig{}) {
		return resolvedManifest{}, fmt.Errorf("socks5.http_auth is legacy; move credentials to http.auth")
	}
	if configured.Port == 0 {
		configured.Port = 3128
	}
	if len(configured.Publish) == 0 {
		return resolvedManifest{}, fmt.Errorf("socks5.publish is required")
	}
	if len(configured.Networks) == 0 {
		return resolvedManifest{}, fmt.Errorf("socks5.networks is required")
	}
	resolver, err := normalizeResolver(configured.Resolver)
	if err != nil {
		return resolvedManifest{}, fmt.Errorf("socks5.resolver: %w", err)
	}
	configured.Resolver = resolver
	if legacyHTTP {
		httpAuth, err := normalizeHTTPAuth(configured.HTTPAuth)
		if err != nil {
			return resolvedManifest{}, fmt.Errorf("socks5.http_auth: %w", err)
		}
		configured.HTTPAuth = httpAuth
	}
	service := resolvedSOCKS5{Port: configured.Port, Resolver: resolver, HTTPAuth: configured.HTTPAuth, Networks: map[string]resolvedRoleAddrs{}}
	for _, raw := range configured.AllowZones {
		selector, err := photonservice.ParseZoneSelector(raw)
		if err != nil {
			return resolvedManifest{}, fmt.Errorf("socks5.allow_zones: %w", err)
		}
		service.AllowZones = append(service.AllowZones, selector.String())
	}
	for networkName, baseText := range configured.Networks {
		network, ok := result.Networks[networkName]
		if !ok {
			return resolvedManifest{}, fmt.Errorf("socks5: unknown network %q", networkName)
		}
		base, familyIPAM, err := resolveServiceBase(baseText, network)
		if err != nil {
			return resolvedManifest{}, fmt.Errorf("socks5 network %s: %w", networkName, err)
		}
		roles, err := resolveProxyAddresses(base, *familyIPAM, legacyHTTP)
		if err != nil {
			return resolvedManifest{}, fmt.Errorf("socks5 network %s: %w", networkName, err)
		}
		roles.Assignment = familyIPAM.Assignment
		roles.Shared = familyIPAM.Shared
		roles.AssignmentTag = familyIPAM.Tag
		service.Networks[networkName] = roles
	}
	for networkName, region := range configured.Publish {
		if len(socks5ServiceName)+1+len(networkName) > 63 {
			return resolvedManifest{}, fmt.Errorf("socks5: publish network name %q is too long for its endpoint ACL name", networkName)
		}
		published, ok := service.Networks[networkName]
		if !ok {
			return resolvedManifest{}, fmt.Errorf("socks5: publish network %q is not attached", networkName)
		}
		if region == "" {
			region = configured.Region
		}
		if strings.TrimSpace(region) == "" {
			return resolvedManifest{}, fmt.Errorf("socks5.publish.%s region is required", networkName)
		}
		if published.Assignment == "" {
			return resolvedManifest{}, fmt.Errorf("socks5: publish network %q must come from an IPAM assignment", networkName)
		}
		assignment := netip.MustParsePrefix(published.Assignment)
		maxBits := 96
		if assignment.Addr().Is4() {
			maxBits = 28
		}
		if assignment.Bits() > maxBits {
			return resolvedManifest{}, fmt.Errorf("socks5: publish network %q assignment %s exceeds Babel /%d limit", networkName, assignment, maxBits)
		}
		service.Endpoints = append(service.Endpoints, resolvedEndpoint{Network: networkName, Region: region, Address: published.SOCKS, Port: service.Port, Assignment: published.Assignment, Shared: published.Shared, AssignmentTag: published.AssignmentTag})
	}
	sort.Slice(service.Endpoints, func(i, j int) bool { return service.Endpoints[i].Network < service.Endpoints[j].Network })
	hashInput, _ := json.Marshal(struct {
		Config     socks5Config
		Networks   map[string]resolvedNetwork
		LegacyHTTP bool
	}{configured, result.Networks, legacyHTTP})
	hash := sha256.Sum256(hashInput)
	service.ConfigHash = hex.EncodeToString(hash[:])
	result.SOCKS5 = service
	return result, validateProxyAddressConflicts(result)
}

func normalizeTrustedHostInterfaces(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || strings.ContainsAny(value, ":\t\n\r ") {
			return nil, fmt.Errorf("must contain non-empty interface names without whitespace or ':'")
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result, nil
}

func normalizeResolver(value resolverConfig) (resolverConfig, error) {
	if value.Mode == "" {
		value.Mode = "ipv4_first"
	}
	switch value.Mode {
	case "ipv4_first", "ipv6_first", "ipv4_only", "ipv6_only":
	default:
		return resolverConfig{}, fmt.Errorf("unsupported mode %q", value.Mode)
	}
	if len(value.Servers) == 0 {
		value.Servers = []string{"8.8.8.8", "1.1.1.1"}
	}
	seen := make(map[string]struct{}, len(value.Servers))
	servers := make([]string, 0, len(value.Servers))
	for _, server := range value.Servers {
		server = strings.TrimSpace(server)
		if server == "" || strings.ContainsAny(server, "\t\n\r") {
			return resolverConfig{}, fmt.Errorf("servers must contain non-empty single-line addresses")
		}
		if _, ok := seen[server]; ok {
			continue
		}
		seen[server] = struct{}{}
		servers = append(servers, server)
	}
	value.Servers = servers
	return value, nil
}

func normalizeHTTPAuth(value proxyAuthConfig) (proxyAuthConfig, error) {
	if value.Username == "" && value.Password == "" {
		return proxyAuthConfig{Username: defaultHTTPUser, Password: defaultHTTPPass}, nil
	}
	if strings.TrimSpace(value.Username) == "" || value.Password == "" {
		return proxyAuthConfig{}, fmt.Errorf("username and password must both be set")
	}
	if strings.ContainsAny(value.Username, "\t\n\r") || strings.ContainsAny(value.Password, "\n\r") {
		return proxyAuthConfig{}, fmt.Errorf("username and password must be single-line values")
	}
	return value, nil
}

func resolveDescriptor(raw string, family int, assignments []assignmentCandidate) (resolvedIPAM, error) {
	parts := strings.Split(raw, ";")
	if len(parts) != 4 {
		return resolvedIPAM{}, fmt.Errorf("expected source;subnet;dynamic-range;gateway")
	}
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	source := parts[0]
	var base netip.Prefix
	var selected *assignmentCandidate
	switch {
	case source == "local":
	case source == "auto":
		var matches []assignmentCandidate
		for _, assignment := range assignments {
			if !assignment.Shared && addressFamily(assignment.Prefix.Addr()) == family {
				matches = append(matches, assignment)
			}
		}
		if len(matches) != 1 {
			return resolvedIPAM{}, fmt.Errorf("auto requires exactly one non-shared IPv%d assignment, found %d", family, len(matches))
		}
		selected = &matches[0]
	case strings.HasPrefix(source, "assignment:"):
		wanted, err := parsePrefix(strings.TrimPrefix(source, "assignment:"), family)
		if err != nil {
			return resolvedIPAM{}, err
		}
		for _, assignment := range assignments {
			if assignment.Prefix == wanted {
				candidate := assignment
				selected = &candidate
				break
			}
		}
		if selected == nil {
			return resolvedIPAM{}, fmt.Errorf("assignment %s is not active for this node", wanted)
		}
	case strings.HasPrefix(source, "tag:"):
		tag := strings.TrimSpace(strings.TrimPrefix(source, "tag:"))
		var matches []assignmentCandidate
		for _, assignment := range assignments {
			if assignment.Shared && assignment.Tag == tag && addressFamily(assignment.Prefix.Addr()) == family {
				matches = append(matches, assignment)
			}
		}
		if len(matches) != 1 {
			return resolvedIPAM{}, fmt.Errorf("tag %q requires exactly one local shared IPv%d assignment, found %d", tag, family, len(matches))
		}
		selected = &matches[0]
	default:
		return resolvedIPAM{}, fmt.Errorf("unsupported source %q", source)
	}
	if selected != nil {
		base = selected.Prefix
	}
	subnet, err := resolvePrefix(parts[1], family, base)
	if err != nil {
		return resolvedIPAM{}, fmt.Errorf("subnet: %w", err)
	}
	ipRange, err := resolvePrefix(parts[2], family, base)
	if err != nil {
		return resolvedIPAM{}, fmt.Errorf("dynamic range: %w", err)
	}
	gateway, err := resolveAddr(parts[3], family, base)
	if err != nil {
		return resolvedIPAM{}, fmt.Errorf("gateway: %w", err)
	}
	if base.IsValid() && !containsPrefix(base, subnet) {
		return resolvedIPAM{}, fmt.Errorf("subnet %s is outside assignment %s", subnet, base)
	}
	if !containsPrefix(subnet, ipRange) {
		return resolvedIPAM{}, fmt.Errorf("dynamic range %s is outside subnet %s", ipRange, subnet)
	}
	if !subnet.Contains(gateway) || gateway == subnet.Addr() {
		return resolvedIPAM{}, fmt.Errorf("gateway %s is not usable in %s", gateway, subnet)
	}
	resolved := resolvedIPAM{Source: source, Subnet: subnet.String(), IPRange: ipRange.String(), Gateway: gateway.String()}
	if base.IsValid() {
		resolved.Assignment = base.String()
		resolved.Shared = selected.Shared
		resolved.Tag = selected.Tag
	}
	return resolved, nil
}

func resolveServiceBase(raw string, network resolvedNetwork) (netip.Addr, *resolvedIPAM, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return netip.Addr{}, nil, err
	}
	var ipam *resolvedIPAM
	if addr.Is4() {
		ipam = network.IPv4
	} else {
		ipam = network.IPv6
	}
	if ipam == nil {
		return netip.Addr{}, nil, fmt.Errorf("network has no matching address family")
	}
	subnet := netip.MustParsePrefix(ipam.Subnet)
	if addr.Is6() && strings.HasPrefix(strings.TrimSpace(raw), "::") {
		addr, err = addAddress(subnet.Addr(), addr)
		if err != nil {
			return netip.Addr{}, nil, err
		}
	}
	return addr, ipam, nil
}

func resolveRoleAddresses(base netip.Addr, ipam resolvedIPAM) (resolvedRoleAddrs, error) {
	return resolveProxyAddresses(base, ipam, true)
}

func resolveProxyAddresses(base netip.Addr, ipam resolvedIPAM, legacyHTTP bool) (resolvedRoleAddrs, error) {
	subnet, dynamic := netip.MustParsePrefix(ipam.Subnet), netip.MustParsePrefix(ipam.IPRange)
	gateway := netip.MustParseAddr(ipam.Gateway)
	count := 1
	if legacyHTTP {
		count = 2
	}
	values := make([]netip.Addr, count)
	for i := range values {
		addr, err := addSmallOffset(base, i)
		if err != nil {
			return resolvedRoleAddrs{}, err
		}
		if !subnet.Contains(addr) || addr == subnet.Addr() || (addr.Is4() && !subnet.Contains(addr.Next())) || addr == gateway || dynamic.Contains(addr) {
			return resolvedRoleAddrs{}, fmt.Errorf("role address %s conflicts with subnet, gateway or dynamic range", addr)
		}
		values[i] = addr
	}
	roles := resolvedRoleAddrs{SOCKS: values[0].String()}
	if legacyHTTP {
		roles.H2 = values[1].String()
	}
	return roles, nil
}

func resolvePrefix(raw string, family int, base netip.Prefix) (netip.Prefix, error) {
	prefix, err := parsePrefix(raw, family)
	if err != nil {
		return netip.Prefix{}, err
	}
	if base.IsValid() && family == 6 && strings.HasPrefix(raw, "::") {
		addr, err := addAddress(base.Addr(), prefix.Addr())
		if err != nil {
			return netip.Prefix{}, err
		}
		prefix = netip.PrefixFrom(addr, prefix.Bits()).Masked()
	}
	return prefix, nil
}

func resolveAddr(raw string, family int, base netip.Prefix) (netip.Addr, error) {
	addr, err := netip.ParseAddr(raw)
	if err != nil || addressFamily(addr) != family {
		return netip.Addr{}, fmt.Errorf("invalid IPv%d address %q", family, raw)
	}
	if base.IsValid() && family == 6 && strings.HasPrefix(raw, "::") {
		return addAddress(base.Addr(), addr)
	}
	return addr, nil
}

func parsePrefix(raw string, family int) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(raw)
	if err != nil || addressFamily(prefix.Addr()) != family {
		return netip.Prefix{}, fmt.Errorf("invalid IPv%d prefix %q", family, raw)
	}
	if prefix != prefix.Masked() {
		return netip.Prefix{}, fmt.Errorf("prefix %s is not canonical", prefix)
	}
	return prefix, nil
}

func addSmallOffset(addr netip.Addr, offset int) (netip.Addr, error) {
	if offset == 0 {
		return addr, nil
	}
	var raw netip.Addr
	if addr.Is4() {
		raw = netip.AddrFrom4([4]byte{0, 0, 0, byte(offset)})
	} else {
		var b [16]byte
		b[15] = byte(offset)
		raw = netip.AddrFrom16(b)
	}
	return addAddress(addr, raw)
}

func addAddress(base, offset netip.Addr) (netip.Addr, error) {
	if base.Is4() != offset.Is4() {
		return netip.Addr{}, fmt.Errorf("address families differ")
	}
	if base.Is4() {
		b, o := base.As4(), offset.As4()
		var out [4]byte
		carry := 0
		for i := 3; i >= 0; i-- {
			sum := int(b[i]) + int(o[i]) + carry
			out[i] = byte(sum)
			carry = sum >> 8
		}
		if carry != 0 {
			return netip.Addr{}, fmt.Errorf("IPv4 address overflow")
		}
		return netip.AddrFrom4(out), nil
	}
	b, o := base.As16(), offset.As16()
	var out [16]byte
	carry := 0
	for i := 15; i >= 0; i-- {
		sum := int(b[i]) + int(o[i]) + carry
		out[i] = byte(sum)
		carry = sum >> 8
	}
	if carry != 0 {
		return netip.Addr{}, fmt.Errorf("IPv6 address overflow")
	}
	return netip.AddrFrom16(out), nil
}

func containsPrefix(parent, child netip.Prefix) bool {
	return parent.IsValid() && child.IsValid() && parent.Bits() <= child.Bits() && parent.Contains(child.Addr())
}
func addressFamily(addr netip.Addr) int {
	if addr.Is4() {
		return 4
	}
	return 6
}

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
