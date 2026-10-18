package photonopenwrt

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the opt-in OpenWrt integration intent. YAML remains its only
// configuration owner; a nil block or both flags false enables no integration.
// Keep this type available on every platform so shared application config can
// decode it without importing a Linux-only package.
type Config struct {
	WANNetworks   []string `yaml:"wan_networks" json:"wan_networks"`
	AnnounceIPsec bool     `yaml:"announce_ipsec" json:"announce_ipsec"`
	AutoFirewall  bool     `yaml:"auto_firewall" json:"auto_firewall"`
}

func (c Config) Enabled() bool { return c.AnnounceIPsec || c.AutoFirewall }

var logicalNetworkName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$`)

func (c Config) Validate() error {
	if c.Enabled() && len(c.WANNetworks) == 0 {
		return errors.New("OpenWrt integration requires explicitly selected WAN logical networks")
	}
	seen := make(map[string]bool, len(c.WANNetworks))
	for _, name := range c.WANNetworks {
		if !logicalNetworkName.MatchString(name) {
			return fmt.Errorf("invalid OpenWrt logical network name %q", name)
		}
		if seen[name] {
			return fmt.Errorf("duplicate OpenWrt logical network %q", name)
		}
		seen[name] = true
	}
	return nil
}

func integrationDocument(content string) (*yaml.Node, error) {
	decoder := yaml.NewDecoder(strings.NewReader(content))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return nil, err
	}
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("configuration must be a YAML mapping")
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("configuration must contain exactly one YAML document")
	}
	// Decode also rejects duplicate mapping keys, including duplicate openwrt.
	var mapping map[string]any
	if err := document.Decode(&mapping); err != nil {
		return nil, err
	}
	return &document, nil
}

func integrationConfigFromYAML(content string) (Config, error) {
	document, err := integrationDocument(content)
	if err != nil {
		return Config{}, err
	}
	config := Config{WANNetworks: []string{}}
	root := document.Content[0]
	for i := 0; i < len(root.Content); i += 2 {
		if root.Content[i].Value != "openwrt" {
			continue
		}
		value := root.Content[i+1]
		if value.Tag == "!!null" {
			break
		}
		if err := value.Decode(&config); err != nil {
			return Config{}, fmt.Errorf("decode OpenWrt settings: %w", err)
		}
		break
	}
	if config.WANNetworks == nil {
		config.WANNetworks = []string{}
	}
	return config, config.Validate()
}

func updateIntegrationConfig(content string, config Config) (string, error) {
	if err := config.Validate(); err != nil {
		return "", err
	}
	document, err := integrationDocument(content)
	if err != nil {
		return "", err
	}
	root := document.Content[0]
	var existing *yaml.Node
	for i := 0; i < len(root.Content); i += 2 {
		if root.Content[i].Value == "openwrt" {
			existing = root.Content[i+1]
			break
		}
	}
	if existing == nil {
		existing = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		root.Content = append(root.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "openwrt"}, existing)
	} else if existing.Kind != yaml.MappingNode {
		// Replace this reference, never mutate an alias target used elsewhere.
		*existing = yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", HeadComment: existing.HeadComment, LineComment: existing.LineComment}
	}
	var desired yaml.Node
	if err := desired.Encode(config); err != nil {
		return "", err
	}
	for i := 0; i < len(desired.Content); i += 2 {
		key, value := desired.Content[i], desired.Content[i+1]
		found := false
		for j := 0; j < len(existing.Content); j += 2 {
			if existing.Content[j].Value != key.Value {
				continue
			}
			value.HeadComment, value.LineComment, value.FootComment = existing.Content[j+1].HeadComment, existing.Content[j+1].LineComment, existing.Content[j+1].FootComment
			existing.Content[j+1], found = value, true
			break
		}
		if !found {
			existing.Content = append(existing.Content, key, value)
		}
	}
	var output bytes.Buffer
	encoder := yaml.NewEncoder(&output)
	encoder.SetIndent(2)
	if err := encoder.Encode(document); err != nil {
		return "", err
	}
	if err := encoder.Close(); err != nil {
		return "", err
	}
	return output.String(), nil
}
