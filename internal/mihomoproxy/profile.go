// Package mihomoproxy manages an independent Mihomo client for Photon.
package mihomoproxy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/HiggsNet/photon/internal/photonwindows"
	"gopkg.in/yaml.v3"
)

const (
	providerName    = "photon-services"
	offlineName     = "Photon Offline"
	maxTemplateSize = 4 << 20
	healthURL       = "https://www.gstatic.com/generate_204"
)

var photonGroups = []string{"Photon", "Photon Auto", "Photon Balance"}
var reserved = append(slices.Clone(photonGroups), offlineName, "DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE", "GLOBAL")

// Template contains only the policy sections accepted by the FlClash Photon
// template. Listener, DNS, TUN and controller settings belong to the client.
type Template struct {
	proxies, groups                    []namedItem
	providers, ruleProviders, subRules map[string]any
	rules                              []string
}

type namedItem map[string]any

func ParseTemplate(content []byte) (Template, error) {
	if len(content) > maxTemplateSize {
		return Template{}, errors.New("Photon proxy template exceeds 4 MiB")
	}
	var src struct {
		Proxies       []namedItem    `yaml:"proxies"`
		Groups        []namedItem    `yaml:"proxy-groups"`
		Providers     map[string]any `yaml:"proxy-providers"`
		RuleProviders map[string]any `yaml:"rule-providers"`
		SubRules      map[string]any `yaml:"sub-rules"`
		Rules         []any          `yaml:"rules"`
	}
	decoder := yaml.NewDecoder(bytes.NewReader(content))
	if err := decoder.Decode(&src); err != nil {
		return Template{}, fmt.Errorf("read Photon proxy template: %w", err)
	}
	if err := decoder.Decode(new(yaml.Node)); err != io.EOF {
		return Template{}, errors.New("Photon proxy template must contain one YAML document")
	}
	if len(src.Rules) == 0 {
		return Template{}, errors.New("Photon proxy template needs non-empty rules")
	}
	rules := make([]string, 0, len(src.Rules))
	for _, value := range src.Rules {
		rule, ok := value.(string)
		if !ok || strings.TrimSpace(rule) == "" {
			return Template{}, errors.New("Photon proxy template rules must be non-empty strings")
		}
		rules = append(rules, rule)
	}
	seen := make(map[string]bool)
	for _, items := range [][]namedItem{src.Proxies, src.Groups} {
		for _, item := range items {
			name, ok := item["name"].(string)
			if !ok || strings.TrimSpace(name) == "" {
				return Template{}, errors.New("Photon proxy template has an unnamed proxy or group")
			}
			if seen[name] || slices.Contains(reserved, name) {
				return Template{}, fmt.Errorf("duplicate or reserved proxy name %q", name)
			}
			seen[name] = true
		}
	}
	if _, exists := src.Providers[providerName]; exists {
		return Template{}, fmt.Errorf("reserved proxy provider %q", providerName)
	}
	return Template{
		proxies: src.Proxies, groups: src.Groups, providers: src.Providers,
		ruleProviders: src.RuleProviders, subRules: src.SubRules, rules: rules,
	}, nil
}

type Listener struct {
	MixedPort      uint16
	ControllerPort uint16
	Secret         string
}

// Render always produces a fail-closed Photon group for an absent, expired
// or empty directory. The caller supplies only snapshots of the owned daemon.
func (t Template) Render(listener Listener, directory *photonwindows.ServiceDirectory, now time.Time) ([]byte, bool, error) {
	if listener.MixedPort == 0 || listener.ControllerPort == 0 ||
		listener.MixedPort == listener.ControllerPort || listener.Secret == "" {
		return nil, false, errors.New("invalid local Mihomo listener settings")
	}
	endpoints, guardRules, err := directoryConfig(directory, now)
	if err != nil {
		return nil, false, err
	}
	online := len(endpoints) > 0
	provider := map[string]any{"type": "inline", "payload": endpoints}
	groups := make([]namedItem, 0, len(t.groups)+len(photonGroups))
	for _, group := range t.groups {
		// A filter can exclude the offline placeholder. Prevent Mihomo's
		// implicit empty-group fallback from sending that traffic direct.
		_, hasFallback := group["empty-fallback"]
		if !hasFallback && usesPhotonProvider(group) {
			group = maps.Clone(group)
			group["empty-fallback"] = "REJECT"
		}
		groups = append(groups, group)
	}
	if online {
		provider["health-check"] = map[string]any{"enable": true, "url": healthURL, "interval": 300}
		groups = append(groups,
			namedItem{"name": "Photon", "type": "select", "use": []string{providerName}, "proxies": []string{"Photon Auto", "Photon Balance"}, "empty-fallback": "REJECT"},
			namedItem{"name": "Photon Auto", "type": "url-test", "use": []string{providerName}, "url": healthURL, "interval": 300, "tolerance": 80, "empty-fallback": "REJECT"},
			namedItem{"name": "Photon Balance", "type": "load-balance", "use": []string{providerName}, "strategy": "consistent-hashing", "url": healthURL, "interval": 300, "empty-fallback": "REJECT"},
		)
	} else {
		provider["payload"] = []namedItem{{"name": offlineName, "type": "reject"}}
		for _, name := range photonGroups {
			groups = append(groups, namedItem{"name": name, "type": "select", "proxies": []string{"REJECT"}})
		}
	}
	providers := make(map[string]any, len(t.providers)+1)
	for key, value := range t.providers {
		providers[key] = value
	}
	providers[providerName] = provider
	rules := t.rules
	if len(rules) == 0 {
		rules = []string{"MATCH,Photon"}
	}
	config := map[string]any{
		"mode": "rule", "ipv6": true,
		"mixed-port": listener.MixedPort, "allow-lan": false, "bind-address": "127.0.0.1",
		"external-controller": net.JoinHostPort("127.0.0.1", strconv.Itoa(int(listener.ControllerPort))),
		"secret":              listener.Secret, "log-level": "warning",
		"dns": map[string]any{"enable": false}, "tun": map[string]any{"enable": false},
		"proxies": t.proxies, "proxy-groups": groups, "proxy-providers": providers,
		"rules": append(guardRules, rules...),
	}
	if len(t.ruleProviders) > 0 {
		config["rule-providers"] = t.ruleProviders
	}
	if len(t.subRules) > 0 {
		config["sub-rules"] = t.subRules
	}
	encoded, err := yaml.Marshal(config)
	return encoded, online, err
}

func directoryConfig(directory *photonwindows.ServiceDirectory, now time.Time) ([]namedItem, []string, error) {
	if directory == nil || !now.Before(directory.ValidUntil) || directory.AdapterName == "" {
		return nil, nil, nil
	}
	lifetime := directory.ValidUntil.Sub(directory.ObservedAt)
	if lifetime <= 0 || lifetime > 5*time.Second || directory.ObservedAt.After(now.Add(5*time.Second)) {
		return nil, nil, errors.New("invalid Photon service directory lifetime")
	}
	prefixes := slices.Clone(directory.BypassPrefixes)
	var endpoints []namedItem
	seen := make(map[string]bool)
	for _, service := range directory.Services {
		if service.Status != "active" {
			continue
		}
		for _, endpoint := range service.Endpoints {
			address, err := netip.ParseAddr(endpoint.Address)
			if err != nil || address.Zone() != "" || address.IsUnspecified() || endpoint.Port == 0 ||
				service.Owner == "" || endpoint.Region == "" {
				return nil, nil, errors.New("invalid authorized Photon endpoint")
			}
			name := fmt.Sprintf("%s / %s / %s", strings.TrimSuffix(string(service.Owner), "."), endpoint.Region,
				net.JoinHostPort(address.String(), strconv.Itoa(int(endpoint.Port))))
			if seen[name] {
				continue
			}
			seen[name] = true
			endpoints = append(endpoints, namedItem{
				"name": name, "type": "socks5", "server": address.String(),
				"port": endpoint.Port, "udp": true, "interface-name": directory.AdapterName,
			})
			prefixes = append(prefixes, netip.PrefixFrom(address, address.BitLen()))
		}
	}
	slices.SortFunc(endpoints, func(a, b namedItem) int {
		return strings.Compare(a["name"].(string), b["name"].(string))
	})
	rules := make([]string, 0, len(prefixes)+len(directory.BypassDomains))
	for _, prefix := range prefixes {
		if !prefix.IsValid() {
			return nil, nil, errors.New("invalid Photon bypass prefix")
		}
		kind := "IP-CIDR"
		if prefix.Addr().Is6() {
			kind = "IP-CIDR6"
		}
		rules = append(rules, kind+","+prefix.Masked().String()+",DIRECT,no-resolve")
	}
	for _, domain := range directory.BypassDomains {
		if domain == "" || strings.ContainsAny(domain, ",\r\n") {
			return nil, nil, errors.New("invalid Photon bypass domain")
		}
		rules = append(rules, "DOMAIN,"+domain+",DIRECT")
	}
	slices.Sort(rules)
	return endpoints, slices.Compact(rules), nil
}

func usesPhotonProvider(group namedItem) bool {
	all, _ := group["include-all"].(bool)
	allProviders, _ := group["include-all-providers"].(bool)
	if all || allProviders {
		return true
	}
	providers, _ := group["use"].([]any)
	return slices.ContainsFunc(providers, func(value any) bool {
		name, _ := value.(string)
		return name == providerName
	})
}
