package photonlinux

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/HiggsNet/photon/pkg/transport/ipsec"
	"gopkg.in/yaml.v3"
)

// OverlayConfigYAML is a raw entry in the overlays configuration section.
type OverlayConfigYAML struct {
	ID                 string                  `yaml:"id"`
	Name               string                  `yaml:"name"`
	Provider           string                  `yaml:"provider"`
	NetNS              netnsRefYAML            `yaml:"netns"`
	DefaultPathMode    string                  `yaml:"default_path_mode"`
	Direction          string                  `yaml:"direction"`
	AddressSourceOrder configStringList        `yaml:"address_source_order"`
	MaxPeers           *int                    `yaml:"max_peers"`
	MaxLinksPerPeer    *int                    `yaml:"max_links_per_peer"`
	TunnelAddressPool  string                  `yaml:"tunnel_address_pool"`
	TunnelAddress      tunnelAddressConfigYAML `yaml:"tunnel_address"`
	Reconcile          overlayReconcileYAML    `yaml:"reconcile"`
	Connect            configStringList        `yaml:"connect"`
	Deny               configStringList        `yaml:"deny"`
}

type overlayReconcileYAML struct {
	Interval        string             `yaml:"interval"`
	RotateRetention string             `yaml:"rotate_retention"`
	Backoff         overlayBackoffYAML `yaml:"backoff"`
}

type overlayBackoffYAML struct {
	Initial string `yaml:"initial"`
	Max     string `yaml:"max"`
}

type netnsRefYAML struct {
	Ref        string
	Spec       ipsec.NetNSSpec
	InlineSpec bool
}

func (n *netnsRefYAML) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		n.Ref = strings.TrimSpace(node.Value)
		return nil
	case yaml.MappingNode:
		var spec ipsec.NetNSSpec
		if err := node.Decode(&spec); err != nil {
			return err
		}
		n.Spec = spec
		n.InlineSpec = true
		return nil
	default:
		return fmt.Errorf("netns must be a reference string or netns spec object")
	}
}

// ParseOverlayConfigs resolves namespaces and validates overlay link policy.
func ParseOverlayConfigs(overlays []OverlayConfigYAML, netnsCfg NetNSConfig, defaultNetNS ipsec.NetNSSpec) ([]ipsec.LinkGroupSpec, error) {
	groups := make([]ipsec.LinkGroupSpec, 0, len(overlays))
	for i, overlay := range overlays {
		group, err := parseOverlayConfig(overlay, netnsCfg, defaultNetNS)
		if err != nil {
			return nil, fmt.Errorf("overlays[%d]: %w", i, err)
		}
		groups = append(groups, group)
	}
	return groups, nil
}

func parseOverlayConfig(overlay OverlayConfigYAML, netnsCfg NetNSConfig, defaultNetNS ipsec.NetNSSpec) (ipsec.LinkGroupSpec, error) {
	netns, err := resolveNetNSRef(overlay.NetNS, netnsCfg, defaultNetNS)
	if err != nil {
		return ipsec.LinkGroupSpec{}, fmt.Errorf("netns: %w", err)
	}
	if overlay.Direction != "" {
		return ipsec.LinkGroupSpec{}, fmt.Errorf("overlays[].direction is deprecated; use ipsec.role instead")
	}
	group := ipsec.LinkGroupSpec{
		ID:                 overlay.ID,
		Name:               overlay.Name,
		Provider:           overlay.Provider,
		NetNS:              netns,
		DefaultPathMode:    overlay.DefaultPathMode,
		AddressSourceOrder: append([]string(nil), overlay.AddressSourceOrder...),
		ConnectRules:       append([]string(nil), overlay.Connect...),
		DenyRules:          append([]string(nil), overlay.Deny...),
	}
	if group.ID == "" {
		group.ID = group.Name
	}
	if overlay.MaxPeers != nil {
		group.MaxPeers = *overlay.MaxPeers
	}
	if overlay.MaxLinksPerPeer != nil {
		group.MaxLinksPerPeer = *overlay.MaxLinksPerPeer
	}
	legacyPoolSet := overlay.TunnelAddressPool != ""
	newBlockSet := overlay.TunnelAddress.Mode != "" || overlay.TunnelAddress.Family != "" || overlay.TunnelAddress.Pool != ""
	if legacyPoolSet && newBlockSet {
		return ipsec.LinkGroupSpec{}, fmt.Errorf("cannot mix tunnel_address_pool with tunnel_address")
	}
	if legacyPoolSet {
		prefix, err := netip.ParsePrefix(overlay.TunnelAddressPool)
		if err != nil {
			return ipsec.LinkGroupSpec{}, fmt.Errorf("invalid tunnel_address_pool %q: %w", overlay.TunnelAddressPool, err)
		}
		group.TunnelAddressPool = prefix
	}
	if newBlockSet {
		spec, err := overlay.TunnelAddress.parse()
		if err != nil {
			return ipsec.LinkGroupSpec{}, err
		}
		group.TunnelAddressSpec = spec
	}
	for _, field := range []struct {
		raw, name string
		target    *int
	}{
		{overlay.Reconcile.Interval, "reconcile.interval", &group.Reconcile.IntervalSeconds},
		{overlay.Reconcile.RotateRetention, "reconcile.rotate_retention", &group.Reconcile.RotateRetentionSeconds},
		{overlay.Reconcile.Backoff.Initial, "reconcile.backoff.initial", &group.Reconcile.Backoff.InitialSeconds},
		{overlay.Reconcile.Backoff.Max, "reconcile.backoff.max", &group.Reconcile.Backoff.MaxSeconds},
	} {
		if field.raw == "" {
			continue
		}
		d, err := time.ParseDuration(field.raw)
		if err != nil {
			return ipsec.LinkGroupSpec{}, fmt.Errorf("invalid %s: %q", field.name, field.raw)
		}
		*field.target = durationSeconds(d)
	}
	if err := group.Validate(); err != nil {
		return ipsec.LinkGroupSpec{}, err
	}
	if _, err := ipsec.ParseMeshPolicyRules(group.ConnectRules); err != nil {
		return ipsec.LinkGroupSpec{}, fmt.Errorf("connect: %w", err)
	}
	if _, err := ipsec.ParseMeshPolicyRules(group.DenyRules); err != nil {
		return ipsec.LinkGroupSpec{}, fmt.Errorf("deny: %w", err)
	}
	return group.Normalized(), nil
}

func resolveNetNSRef(ref netnsRefYAML, netnsCfg NetNSConfig, fallback ipsec.NetNSSpec) (ipsec.NetNSSpec, error) {
	if ref.Ref != "" {
		spec, ok := netnsCfg.Names[ref.Ref]
		if !ok {
			return ipsec.NetNSSpec{}, fmt.Errorf("unknown netns %q", ref.Ref)
		}
		return spec, nil
	}
	if ref.InlineSpec {
		spec := ref.Spec.Normalized()
		if err := spec.Validate(); err != nil {
			return ipsec.NetNSSpec{}, err
		}
		return spec, nil
	}
	key := netnsCfg.Default
	if key == "" {
		key = "default"
	}
	if spec, ok := netnsCfg.Names[key]; ok {
		return spec, nil
	}
	spec := fallback.Normalized()
	if err := spec.Validate(); err != nil {
		return ipsec.NetNSSpec{}, err
	}
	return spec, nil
}

func durationSeconds(d time.Duration) int {
	if d <= 0 {
		return 0
	}
	return int(d.Round(time.Second) / time.Second)
}

// configStringList accepts both supported list forms in Linux configuration YAML.
type configStringList []string

func (list *configStringList) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.SequenceNode {
		var values []string
		if err := node.Decode(&values); err != nil {
			return err
		}
		*list = append((*list)[:0], values...)
		return nil
	}
	var value string
	if err := node.Decode(&value); err != nil {
		return err
	}
	*list = (*list)[:0]
	for v := range strings.SplitSeq(value, ",") {
		if v = strings.TrimSpace(v); v != "" {
			*list = append(*list, v)
		}
	}
	return nil
}
