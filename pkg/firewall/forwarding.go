package firewall

import (
	"net/netip"
)

// BuildForwardingPolicy derives the shared forwarding/transit policy from local
// configuration and verified state. BIRD and the firewall planner both consume
// the same policy so that BIRD does not announce a transit path the firewall
// blocks, and the firewall does not block a path BIRD announces.
//
// In the first version, transit is a local config decision. Future versions may
// source it from a signed routing/forwarding record.
func BuildForwardingPolicy(transit bool, allowPrefixes, denyPrefixes []netip.Prefix, allowPeers, denyPeers []string, metricHint uint) ForwardingPolicy {
	return ForwardingPolicy{
		Transit:       transit,
		AllowPrefixes: canonicalPrefixes(allowPrefixes),
		DenyPrefixes:  canonicalPrefixes(denyPrefixes),
		AllowPeers:    allowPeers,
		DenyPeers:     denyPeers,
		MetricHint:    metricHint,
	}
}

// IsTransitPrefixAllowed reports whether a prefix is allowed by the forwarding policy.
func IsTransitPrefixAllowed(policy ForwardingPolicy, prefix netip.Prefix) bool {
	for _, denied := range policy.DenyPrefixes {
		if denied == prefix {
			return false
		}
		if denied.Contains(prefix.Addr()) {
			return false
		}
	}
	if len(policy.AllowPrefixes) == 0 {
		return true
	}
	for _, allowed := range policy.AllowPrefixes {
		if allowed == prefix {
			return true
		}
		if allowed.Contains(prefix.Addr()) {
			return true
		}
	}
	return false
}

func canonicalPrefixes(prefixes []netip.Prefix) []netip.Prefix {
	if len(prefixes) == 0 {
		return nil
	}
	seen := make(map[string]bool)
	var out []netip.Prefix
	for _, p := range prefixes {
		key := p.Masked().String()
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, p.Masked())
	}
	return out
}

// filterTransitPrefixes applies the shared allow/deny semantics to the
// authorized IPv4 and IPv6 prefix sets used by the firewall planner.
func filterTransitPrefixes(v4, v6 []netip.Prefix, policy ForwardingPolicy) []netip.Prefix {
	all := append(append([]netip.Prefix{}, v4...), v6...)
	var filtered []netip.Prefix
	for _, p := range all {
		if IsTransitPrefixAllowed(policy, p) {
			filtered = append(filtered, p)
		}
	}
	return filtered
}

// FilterAuthorizedByPolicy applies a namespace forwarding policy to the
// authorized route set consumed by BIRD export generation.
func FilterAuthorizedByPolicy(prefixes []netip.Prefix, policy ForwardingPolicy) []netip.Prefix {
	var out []netip.Prefix
	for _, prefix := range prefixes {
		if IsTransitPrefixAllowed(policy, prefix) {
			out = append(out, prefix)
		}
	}
	return out
}
