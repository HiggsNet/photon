package ipsec

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

const (
	RuleFamilyDual = "dual"
)

type MeshPolicyRule struct {
	Raw         string
	Provider    string
	ZonePattern string
	Role        string
	Tag         string
	PeerRole    string
	Family      string
	Sources     []string
	PathMode    string
	MaxPeers    int
}

func ParseMeshPolicyRule(raw string) (MeshPolicyRule, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return MeshPolicyRule{}, fmt.Errorf("mesh policy rule is empty")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return MeshPolicyRule{}, fmt.Errorf("parse mesh policy rule %q: %w", raw, err)
	}
	rule := MeshPolicyRule{
		Raw:      raw,
		Provider: parsed.Scheme,
		MaxPeers: -1,
	}
	if rule.Provider == "" {
		return MeshPolicyRule{}, fmt.Errorf("mesh policy rule %q missing provider scheme", raw)
	}
	if rule.Provider != ProviderStrongSwan {
		return MeshPolicyRule{}, fmt.Errorf("unsupported mesh policy provider %q", rule.Provider)
	}
	target := parsed.Host
	if target == "" && strings.Trim(parsed.Path, "/") != "" {
		target = strings.Trim(parsed.Path, "/")
	}
	if target == "" {
		return MeshPolicyRule{}, fmt.Errorf("mesh policy rule %q missing target", raw)
	}
	if key, value, ok := strings.Cut(target, "="); ok {
		switch key {
		case "role":
			rule.Role = value
		case "tag":
			rule.Tag = value
		default:
			return MeshPolicyRule{}, fmt.Errorf("unsupported mesh policy target %q", target)
		}
		if value == "" {
			return MeshPolicyRule{}, fmt.Errorf("mesh policy target %q has empty value", key)
		}
	} else {
		rule.ZonePattern = target
		if err := zone.ValidatePattern(rule.ZonePattern); err != nil {
			return MeshPolicyRule{}, err
		}
	}
	query := parsed.Query()
	rule.PeerRole = firstQuery(query, "role")
	rule.Family = firstQuery(query, "family")
	rule.PathMode = firstQuery(query, "mode")
	if firstQuery(query, "direction") != "" {
		return MeshPolicyRule{}, fmt.Errorf("mesh policy rule %q uses deprecated direction query; use ipsec.role instead", raw)
	}
	if firstQuery(query, "accept") != "" {
		return MeshPolicyRule{}, fmt.Errorf("mesh policy rule %q uses deprecated accept query; use role instead", raw)
	}
	if rawSources := firstQuery(query, "source"); rawSources != "" {
		for source := range strings.SplitSeq(rawSources, ",") {
			source = strings.TrimSpace(source)
			if source == "" {
				continue
			}
			rule.Sources = append(rule.Sources, source)
		}
	}
	if rawMaxPeers := firstQuery(query, "max_peers"); rawMaxPeers != "" {
		value, err := strconv.Atoi(rawMaxPeers)
		if err != nil || value < 0 {
			return MeshPolicyRule{}, fmt.Errorf("invalid max_peers %q", rawMaxPeers)
		}
		rule.MaxPeers = value
	}
	if err := rule.Validate(); err != nil {
		return MeshPolicyRule{}, err
	}
	return rule, nil
}

func ParseMeshPolicyRules(raw []string) ([]MeshPolicyRule, error) {
	rules := make([]MeshPolicyRule, 0, len(raw))
	for i, item := range raw {
		rule, err := ParseMeshPolicyRule(item)
		if err != nil {
			return nil, fmt.Errorf("rule[%d]: %w", i, err)
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func (r MeshPolicyRule) Validate() error {
	if r.Provider != ProviderStrongSwan {
		return fmt.Errorf("unsupported mesh policy provider %q", r.Provider)
	}
	if r.ZonePattern == "" && r.Role == "" && r.Tag == "" {
		return fmt.Errorf("mesh policy rule must target zone, role, or tag")
	}
	if r.PeerRole != "" && !oneOf(r.PeerRole, RoleOut, RoleIn, RoleBoth) {
		return fmt.Errorf("unsupported mesh policy role %q", r.PeerRole)
	}
	if r.Family != "" && !oneOf(r.Family, RuleFamilyDual, FamilyIPv4, FamilyIPv6) {
		return fmt.Errorf("unsupported mesh policy family %q", r.Family)
	}
	if r.PathMode != "" && !oneOf(r.PathMode, PathModeFamilyRedundant, PathModeExhaustive) {
		return fmt.Errorf("unsupported mesh policy mode %q", r.PathMode)
	}
	for _, source := range r.Sources {
		if !oneOf(source, SourceManualAddress, SourceManualDNS, SourceDiscovery, SourceReflector, SourceLocal) {
			return fmt.Errorf("unsupported mesh policy source %q", source)
		}
	}
	if r.MaxPeers < -1 {
		return fmt.Errorf("max peers must be non-negative")
	}
	return nil
}

func (r MeshPolicyRule) MatchesZone(peer zone.ZonePath) bool {
	return zone.MatchesPattern(r.ZonePattern, peer)
}

func firstQuery(values url.Values, key string) string {
	if got := values.Get(key); got != "" {
		return strings.TrimSpace(got)
	}
	return ""
}
