package main

import (
	"fmt"
	"net/netip"

	"github.com/HiggsNet/photon/pkg/firewall"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

// forwardingYAML is the raw forwarding policy nested under a netns entry.
type forwardingYAML struct {
	Transit       *bool    `yaml:"transit"`
	AllowPrefixes []string `yaml:"allow_prefixes"`
	DenyPrefixes  []string `yaml:"deny_prefixes"`
	AllowPeers    []string `yaml:"allow_peers"`
	DenyPeers     []string `yaml:"deny_peers"`
	MetricHint    uint     `yaml:"metric_hint"`
}

func parseForwardingPolicy(raw *forwardingYAML) (firewall.ForwardingPolicy, error) {
	if raw == nil {
		return firewall.ForwardingPolicy{}, nil
	}
	allowPrefixes, err := parsePrefixList(raw.AllowPrefixes)
	if err != nil {
		return firewall.ForwardingPolicy{}, fmt.Errorf("allow_prefixes: %w", err)
	}
	denyPrefixes, err := parsePrefixList(raw.DenyPrefixes)
	if err != nil {
		return firewall.ForwardingPolicy{}, fmt.Errorf("deny_prefixes: %w", err)
	}
	// The forwarding section is an opt-in: declaring it enables transit unless
	// the user explicitly overrides that with transit: false.
	transit := true
	if raw.Transit != nil {
		transit = *raw.Transit
	}
	return firewall.BuildForwardingPolicy(transit, allowPrefixes, denyPrefixes, raw.AllowPeers, raw.DenyPeers, raw.MetricHint), nil
}

// addNetnsForwarding registers a policy under both the configuration key and
// the resolved namespace target, so routing and firewall consumers converge on
// the same policy regardless of which form they use.
func addNetnsForwarding(cfg *netnsConfig, name string, spec ipsec.NetNSSpec, raw *forwardingYAML) error {
	if raw == nil {
		return nil
	}
	policy, err := parseForwardingPolicy(raw)
	if err != nil {
		return fmt.Errorf("forwarding: %w", err)
	}
	if cfg.Forwarding == nil {
		cfg.Forwarding = make(map[string]firewall.ForwardingPolicy)
	}
	cfg.Forwarding[name] = policy
	if spec.Target() != "" {
		cfg.Forwarding[spec.Target()] = policy
	}
	return nil
}

// netnsForwardingPolicy returns the policy owned by the named network
// namespace. An absent policy has the safe non-transit zero value.
func netnsForwardingPolicy(config *appConfig, netnsName string) firewall.ForwardingPolicy {
	if config == nil {
		return firewall.ForwardingPolicy{}
	}
	if policy, ok := config.Netns.Forwarding[netnsName]; ok {
		return policy
	}
	if spec, ok := config.Netns.Names[netnsName]; ok {
		return config.Netns.Forwarding[spec.Target()]
	}
	return firewall.ForwardingPolicy{}
}

// filterAuthorizedByPolicy applies a namespace forwarding policy to the
// authorized route set consumed by BIRD export generation.
func filterAuthorizedByPolicy(prefixes []netip.Prefix, policy firewall.ForwardingPolicy) []netip.Prefix {
	var out []netip.Prefix
	for _, prefix := range prefixes {
		if firewall.IsTransitPrefixAllowed(policy, prefix) {
			out = append(out, prefix)
		}
	}
	return out
}

func parsePrefixList(items []string) ([]netip.Prefix, error) {
	if len(items) == 0 {
		return nil, nil
	}
	var out []netip.Prefix
	for _, s := range items {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("invalid prefix %q: %w", s, err)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}
