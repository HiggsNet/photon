package photonlinux

import (
	"fmt"
	"net/netip"
	"strings"

	"gopkg.in/yaml.v3"
)

const DefaultIPsecAnnouncePriority = 100

type IPsecAnnounceAddress struct {
	Address  string `yaml:"address"`
	Priority int    `yaml:"priority"`
}

type IPsecAnnounceDNS struct {
	Host     string `yaml:"host"`
	Priority int    `yaml:"priority"`
}

// Filters apply to automatic addresses. Explicit IPs and DNS remain operator intent.
type IPsecAnnounceFilter struct {
	IPv4    *bool          `yaml:"ipv4"`
	IPv6    *bool          `yaml:"ipv6"`
	Include []netip.Prefix `yaml:"include"`
	Exclude []netip.Prefix `yaml:"exclude"`
}

type IPsecAnnounceInterface struct {
	Name                string `yaml:"name"`
	Priority            int    `yaml:"priority"`
	IPsecAnnounceFilter `yaml:",inline"`
}

// String and comma-separated forms remain supported alongside object entries.
type ipsecAnnounceAddresses []IPsecAnnounceAddress
type ipsecAnnounceDNSNames []IPsecAnnounceDNS

func announceNodes(node *yaml.Node) ([]*yaml.Node, error) {
	if node.Kind == yaml.SequenceNode {
		return node.Content, nil
	}
	if node.Kind != yaml.ScalarNode || node.Tag != "!!str" {
		return nil, fmt.Errorf("announce entries must be a string or list")
	}
	var nodes []*yaml.Node
	for _, value := range strings.Split(node.Value, ",") {
		if value = strings.TrimSpace(value); value != "" {
			nodes = append(nodes, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value})
		}
	}
	return nodes, nil
}

func decodeAnnounceEntry(node *yaml.Node, key string) (string, int, error) {
	if node.Kind == yaml.ScalarNode && node.Tag == "!!str" {
		return strings.TrimSpace(node.Value), DefaultIPsecAnnouncePriority, nil
	}
	if node.Kind != yaml.MappingNode {
		return "", 0, fmt.Errorf("announce entry must be a string or object")
	}
	value, priority := "", DefaultIPsecAnnouncePriority
	seen := map[string]bool{}
	for i := 0; i < len(node.Content); i += 2 {
		field, raw := node.Content[i].Value, node.Content[i+1]
		if seen[field] {
			return "", 0, fmt.Errorf("duplicate announce field %q", field)
		}
		seen[field] = true
		switch field {
		case key:
			if err := raw.Decode(&value); err != nil {
				return "", 0, err
			}
		case "priority":
			if err := raw.Decode(&priority); err != nil {
				return "", 0, err
			}
		default:
			return "", 0, fmt.Errorf("unknown announce field %q", field)
		}
	}
	if strings.TrimSpace(value) == "" {
		return "", 0, fmt.Errorf("announce %s is required", key)
	}
	return strings.TrimSpace(value), priority, nil
}

func (list *ipsecAnnounceAddresses) UnmarshalYAML(node *yaml.Node) error {
	nodes, err := announceNodes(node)
	if err != nil {
		return err
	}
	*list = nil
	for _, node := range nodes {
		value, priority, err := decodeAnnounceEntry(node, "address")
		if err != nil {
			return err
		}
		*list = append(*list, IPsecAnnounceAddress{Address: value, Priority: priority})
	}
	return nil
}

func (list *ipsecAnnounceDNSNames) UnmarshalYAML(node *yaml.Node) error {
	nodes, err := announceNodes(node)
	if err != nil {
		return err
	}
	*list = nil
	for _, node := range nodes {
		value, priority, err := decodeAnnounceEntry(node, "host")
		if err != nil {
			return err
		}
		*list = append(*list, IPsecAnnounceDNS{Host: value, Priority: priority})
	}
	return nil
}

func (entry *IPsecAnnounceInterface) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("announce interface must be an object with a name")
	}
	// Decode through a method-free type; defaults preserve an explicit priority of zero.
	type plain IPsecAnnounceInterface
	value := plain{Priority: DefaultIPsecAnnouncePriority}
	for i := 0; i < len(node.Content); i += 2 {
		switch node.Content[i].Value {
		case "name", "priority", "ipv4", "ipv6", "include", "exclude":
		default:
			return fmt.Errorf("unknown announce interface field %q", node.Content[i].Value)
		}
	}
	if err := node.Decode(&value); err != nil {
		return err
	}
	*entry = IPsecAnnounceInterface(value)
	return nil
}

func (filter IPsecAnnounceFilter) Allows(address netip.Addr) bool {
	if address.Is4() && filter.IPv4 != nil && !*filter.IPv4 || address.Is6() && filter.IPv6 != nil && !*filter.IPv6 {
		return false
	}
	for _, prefix := range filter.Exclude {
		if prefix.Contains(address) {
			return false
		}
	}
	if len(filter.Include) == 0 {
		return true
	}
	for _, prefix := range filter.Include {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func (filter IPsecAnnounceFilter) Validate() error {
	for _, list := range [][]netip.Prefix{filter.Include, filter.Exclude} {
		for _, prefix := range list {
			if !prefix.IsValid() || prefix.Addr().Is4In6() {
				return fmt.Errorf("invalid announce filter prefix %s", prefix)
			}
		}
	}
	return nil
}

func (config IPsecConfig) AnnounceDNSHosts() []string {
	var hosts []string
	for _, entry := range config.AnnounceDNS {
		hosts = append(hosts, entry.Host)
	}
	return hosts
}
