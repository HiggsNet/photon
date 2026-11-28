package photonproxy

import (
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/service"
	"gopkg.in/yaml.v3"
)

type v2Config struct {
	DirectoryRefresh time.Duration           `yaml:"directory_refresh"`
	LinkNamespace    string                  `yaml:"link_namespace"`
	DirectorySocket  string                  `yaml:"directory_socket"`
	PublishSocket    string                  `yaml:"publish_socket"`
	StateDir         string                  `yaml:"state_dir"`
	PublicDevice     string                  `yaml:"public_device"`
	PhotonDevice     string                  `yaml:"photon_device"`
	Client           *v2ClientConfig         `yaml:"client"`
	Relay            *v2RelayConfig          `yaml:"relay"`
	Exits            map[string]v2ExitConfig `yaml:"exits"`
	PortGroups       map[string]v2PortConfig `yaml:"port_groups"`
	TLS              v2TLSConfig             `yaml:"tls"`
}

type v2TLSConfig struct {
	Lifetime    time.Duration `yaml:"lifetime"`
	RenewBefore time.Duration `yaml:"renew_before"`
	Overlap     time.Duration `yaml:"overlap"`
}

type v2ClientConfig struct {
	Routes         map[string]clientRoute `yaml:"routes"`
	AllowedSources []string               `yaml:"allowed_sources"`
	DefaultListen  string                 `yaml:"default_listen"`
	Admin          v2AdminConfig          `yaml:"admin"`
}

type v2AdminConfig struct {
	Listen      string `yaml:"listen"`
	Socket      string `yaml:"socket"`
	Token       string `yaml:"token"`
	DisableAuth bool   `yaml:"disable_auth"`
	Web         bool   `yaml:"web"`
}

type v2RelayConfig struct {
	Bindings                   []service.ProxyV2Binding `yaml:"bindings"`
	service.ProxyV2RelayPolicy `yaml:",inline"`
}

type v2ExitConfig struct {
	Bindings                  []service.ProxyV2Binding `yaml:"bindings"`
	AdvertisePolicy           bool                     `yaml:"advertise_policy"`
	service.ProxyV2ExitPolicy `yaml:",inline"`
}

type v2PortConfig struct {
	LinkLocal      bool          `yaml:"link_local"`
	Bind           []string      `yaml:"bind"`
	Port           uint16        `yaml:"port"`
	Range          []uint16      `yaml:"range"`
	RotateInterval time.Duration `yaml:"rotate_interval"`
}

func readV2Config(path string) (v2Config, error) {
	return readNodeConfig(path, false)
}

func readNodeConfig(path string, embedded bool) (v2Config, error) {
	var config v2Config
	input, err := os.Open(path)
	if err != nil {
		return config, err
	}
	defer input.Close()
	decoder := yaml.NewDecoder(input)
	decoder.KnownFields(true)
	if err := decoder.Decode(&config); err != nil {
		return config, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return config, errors.New("expected a single proxy YAML document")
	}
	if config.StateDir == "" {
		return config, errors.New("state_dir is required")
	}
	if !embedded && (config.DirectorySocket == "" || config.PublishSocket == "") {
		return config, errors.New("distinct directory_socket and publish_socket are required")
	}
	if embedded && (config.DirectorySocket != "" || config.PublishSocket != "" || config.LinkNamespace != "") {
		return config, errors.New("the embedded proxy supplies its directory, publication and direct link access")
	}
	if config.Client == nil && config.Relay == nil && len(config.Exits) == 0 {
		return config, errors.New("enable at least one proxy role")
	}
	absolute := func(p *string) {
		if *p != "" && !filepath.IsAbs(*p) {
			*p = filepath.Join(filepath.Dir(path), *p)
		}
		if *p != "" {
			*p = filepath.Clean(*p)
		}
	}
	for _, p := range []*string{&config.StateDir, &config.DirectorySocket, &config.PublishSocket} {
		absolute(p)
	}
	if !embedded && config.DirectorySocket == config.PublishSocket {
		return config, errors.New("directory_socket and publish_socket must be distinct")
	}
	if config.DirectoryRefresh == 0 {
		config.DirectoryRefresh = directoryRefresh
	}
	if config.DirectoryRefresh < time.Second {
		return config, errors.New("directory_refresh must be at least one second")
	}
	if config.Client != nil {
		client := config.Client
		if client.DefaultListen == "" {
			client.DefaultListen = "127.0.0.1:0"
		}
		address, err := netip.ParseAddrPort(client.DefaultListen)
		if err != nil || address.Port() != 0 || address.Addr().Zone() != "" {
			return config, errors.New("client.default_listen needs an IP with port zero")
		}
		if _, err := parseV2SourcePrefixes(client.AllowedSources); err != nil {
			return config, err
		}
		if client.Admin.Listen != "" {
			if _, err := netip.ParseAddrPort(client.Admin.Listen); err != nil {
				return config, fmt.Errorf("admin.listen: %w", err)
			}
			if !client.Admin.DisableAuth && client.Admin.Token == "" || strings.ContainsAny(client.Admin.Token, " \t\r\n") {
				return config, errors.New("admin.listen requires a token or explicit disable_auth")
			}
		}
		if !embedded {
			absolute(&client.Admin.Socket)
		}
	}
	if config.TLS.Lifetime == 0 {
		config.TLS.Lifetime = 365 * 24 * time.Hour
	}
	if config.TLS.RenewBefore == 0 {
		config.TLS.RenewBefore = 30 * 24 * time.Hour
	}
	if config.TLS.Overlap == 0 {
		config.TLS.Overlap = 24 * time.Hour
	}
	if config.TLS.Overlap < time.Minute || config.TLS.RenewBefore <= 0 ||
		config.TLS.RenewBefore >= config.TLS.Lifetime || config.TLS.Overlap >= config.TLS.RenewBefore {
		return config, errors.New("TLS durations require one minute <= overlap < renew_before < lifetime")
	}

	for name, ports := range config.PortGroups {
		if !service.ProxyV2ID(name) || !ports.LinkLocal && len(ports.Bind) == 0 || ports.LinkLocal && len(ports.Bind) != 0 {
			return config, errors.New("port groups require an ID and either bind IPs or link_local")
		}
		for _, address := range ports.Bind {
			if ip, err := netip.ParseAddr(address); err != nil || ip.Zone() != "" {
				return config, fmt.Errorf("port group %s has an invalid bind IP", name)
			}
		}
		if ports.Port != 0 {
			if len(ports.Range) != 0 || ports.RotateInterval != 0 {
				return config, fmt.Errorf("port group %s sets both fixed and rotating ports", name)
			}
		} else if len(ports.Range) != 2 || ports.Range[0] == 0 || int(ports.Range[1])-int(ports.Range[0]) < 2 || ports.RotateInterval < 0 {
			return config, fmt.Errorf("port group %s requires a range with three or more ports", name)
		}
	}
	return config, nil
}

func (c v2Config) directNamespace() (string, bool) {
	if c.LinkNamespace == "host" {
		return "", true
	}
	if c.LinkNamespace != "" {
		return c.LinkNamespace, true
	}
	for _, group := range c.PortGroups {
		if group.LinkLocal {
			return "", true
		}
	}
	return "", false
}

func parseV2SourcePrefixes(values []string) ([]netip.Prefix, error) {
	var prefixes []netip.Prefix
	for _, value := range values {
		if addr, err := netip.ParseAddr(value); err == nil {
			addr = addr.Unmap()
			prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
			continue
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, fmt.Errorf("client.allowed_sources: %w", err)
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	return prefixes, nil
}

func v2PrepareEntry(origin zone.ZonePath, allowExternal bool) func(string, clientRoute, bool) (clientEntry, error) {
	return func(name string, route clientRoute, auto bool) (clientEntry, error) {
		entry := clientEntry{name: name, v2Route: v2RouteString(route.Hops)}
		if strings.TrimSpace(name) == "" {
			return entry, errors.New("route name is required")
		}
		if _, err := v2Hops(entry.v2Route, origin); err != nil {
			return entry, err
		}
		address, err := netip.ParseAddrPort(route.Listen)
		if err != nil || address.Addr().Zone() != "" || (!auto && address.Port() == 0) {
			return entry, errors.New("route needs a valid listener IP and port")
		}
		if !allowExternal && !address.Addr().Unmap().IsLoopback() {
			return entry, errors.New("LAN SOCKS5 listeners require client.allowed_sources")
		}
		entry.listen = netip.AddrPortFrom(address.Addr().Unmap(), address.Port())
		if len(route.UDPPrefixes) != 0 {
			entry.udp, err = normalizeUDPScope(strings.Join(route.UDPPrefixes, ","))
		}
		return entry, err
	}
}

func (c v2Config) v2Endpoints(ports map[string]service.ProxyV2Ports) (map[string]service.ProxyV2Endpoint, map[string]v2EndpointACL, error) {
	endpoints := make(map[string]service.ProxyV2Endpoint)
	policies := make(map[string]v2EndpointACL)
	configure := func(id string, endpoint service.ProxyV2Endpoint, acl v2EndpointACL) error {
		acl.groups = make(map[string][]string)
		endpoint.Bindings = slices.Clone(endpoint.Bindings)
		for i := range endpoint.Bindings {
			binding := &endpoint.Bindings[i]
			switch binding.Transport {
			case "", "h2", "trusttunnel+h2":
				binding.Transport = "h2"
			default:
				return fmt.Errorf("endpoint %s: transport %q is not available", id, binding.Transport)
			}
			if binding.TLSID == "" {
				binding.TLSID = "node"
			}
			if binding.TLSID != "node" {
				return fmt.Errorf("endpoint %s: unknown local TLS identity %q", id, binding.TLSID)
			}
			if len(binding.Protocols) == 0 {
				binding.Protocols = []string{"tcp", "udp"}
			}
			binding.PortSets = make(map[string]service.ProxyV2Ports)
			for _, address := range binding.Addresses {
				set, ok := ports[address.PortSet]
				if !ok {
					return fmt.Errorf("endpoint %s: unknown port group %q", id, address.PortSet)
				}
				if c.PortGroups[address.PortSet].LinkLocal != (address.Source == "link-local") {
					return fmt.Errorf("endpoint %s: link-local addresses require a dedicated link-local port group", id)
				}
				binding.PortSets[address.PortSet] = set
				acl.groups[address.PortSet] = append(acl.groups[address.PortSet], address.Via...)
			}
		}
		if !service.ProxyV2ID(id) {
			return fmt.Errorf("invalid endpoint name %q", id)
		}
		if err := endpoint.Validate(id); err != nil {
			return fmt.Errorf("endpoint %s: %w", id, err)
		}
		endpoints[id], policies[id] = endpoint, acl
		return nil
	}
	if c.Relay != nil {
		policy := c.Relay.ProxyV2RelayPolicy
		acl, err := service.CompileProxyV2Relay(policy)
		if err != nil {
			return nil, nil, err
		}
		if err := configure("relay", service.ProxyV2Endpoint{Role: "relay", Bindings: c.Relay.Bindings, Relay: &policy}, v2EndpointACL{relay: acl}); err != nil {
			return nil, nil, err
		}
	}
	for _, id := range slices.Sorted(maps.Keys(c.Exits)) {
		exit := c.Exits[id]
		acl, err := service.CompileProxyV2Exit(exit.ProxyV2ExitPolicy)
		if err != nil {
			return nil, nil, err
		}
		endpoint := service.ProxyV2Endpoint{Role: "exit", Bindings: exit.Bindings}
		if exit.AdvertisePolicy {
			endpoint.Exit = &exit.ProxyV2ExitPolicy
		}
		if err := configure(id, endpoint, v2EndpointACL{exit: acl}); err != nil {
			return nil, nil, err
		}
	}
	used := make(map[string]bool)
	for _, acl := range policies {
		for group := range acl.groups {
			used[group] = true
		}
	}
	for group := range c.PortGroups {
		if !used[group] {
			return nil, nil, fmt.Errorf("port group %q is unused", group)
		}
	}
	return endpoints, policies, nil
}

func v2ProbeBindAddress(address net.Addr) string {
	bound := address.(*net.TCPAddr).AddrPort()
	if bound.Addr().IsUnspecified() {
		fallback := "::1"
		if bound.Addr().Is4() {
			fallback = "127.0.0.1"
		}
		bound = netip.AddrPortFrom(netip.MustParseAddr(fallback), bound.Port())
	}
	return bound.String()
}
