package main

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type composeFile struct {
	Name     string                    `yaml:"name"`
	Services map[string]composeService `yaml:"services,omitempty"`
	Networks map[string]composeNetwork `yaml:"networks"`
}

type composeNetwork struct {
	Name       string              `yaml:"name"`
	External   bool                `yaml:"external,omitempty"`
	Driver     string              `yaml:"driver,omitempty"`
	DriverOpts map[string]string   `yaml:"driver_opts,omitempty"`
	EnableIPv6 bool                `yaml:"enable_ipv6,omitempty"`
	IPAM       *composeNetworkIPAM `yaml:"ipam,omitempty"`
}

type composeNetworkIPAM struct {
	Driver string                     `yaml:"driver"`
	Config []composeNetworkIPAMConfig `yaml:"config"`
}

type composeNetworkIPAMConfig struct {
	Subnet  string `yaml:"subnet"`
	IPRange string `yaml:"ip_range"`
	Gateway string `yaml:"gateway"`
}

type composeService struct {
	Image    string                              `yaml:"image"`
	Restart  string                              `yaml:"restart,omitempty"`
	Scale    *int                                `yaml:"scale,omitempty"`
	Networks map[string]composeServiceAttachment `yaml:"networks"`
	Command  []string                            `yaml:"command,omitempty"`
	Volumes  []string                            `yaml:"volumes,omitempty"`
	Labels   map[string]string                   `yaml:"labels,omitempty"`
}

type composeServiceAttachment struct {
	IPv4Address string `yaml:"ipv4_address,omitempty"`
	IPv6Address string `yaml:"ipv6_address,omitempty"`
}

func renderArtifacts(manifest resolvedManifest) error {
	if err := renderNetworkCompose(manifest); err != nil {
		return err
	}
	if manifest.SOCKS5.configured() {
		if err := renderSOCKS5Compose(manifest, manifest.SOCKS5); err != nil {
			return err
		}
	}
	if manifest.TrustTunnel.configured() {
		if err := renderTrustTunnel(manifest); err != nil {
			return err
		}
	}
	if manifest.HTTP.configured() {
		if err := renderHTTP(manifest); err != nil {
			return err
		}
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(manifest.OutputDir, "resolved.json"), append(data, '\n'), 0o644)
}

func renderNetworkCompose(manifest resolvedManifest) error {
	scaleZero := 0
	// Compose rejects projects without a selected service before creating their
	// networks. A scale-zero owner keeps the networks under an independent
	// Compose lifecycle without leaving a placeholder container running.
	file := composeFile{
		Name:     "photon-networks",
		Networks: map[string]composeNetwork{},
		Services: map[string]composeService{
			"owner": {
				Image:    mihomoImage(manifest.Images),
				Scale:    &scaleZero,
				Networks: map[string]composeServiceAttachment{},
			},
		},
	}
	for _, id := range sortedKeys(manifest.Networks) {
		network := manifest.Networks[id]
		addresses := []string{publishedServiceAddress(manifest.SOCKS5, id)}
		for _, endpoint := range manifest.HTTP.Endpoints {
			if endpoint.Network == id {
				addresses = append(addresses, endpoint.Address)
			}
		}
		for _, endpoint := range manifest.TrustTunnel.Endpoints {
			if endpoint.Network == id {
				addresses = append(addresses, endpoint.Address)
			}
		}
		configs := make([]composeNetworkIPAMConfig, 0, 2)
		if network.IPv4 != nil {
			configs = append(configs, composeNetworkIPAMConfig{Subnet: network.IPv4.Subnet, IPRange: network.IPv4.IPRange, Gateway: network.IPv4.Gateway})
		}
		if network.IPv6 != nil {
			configs = append(configs, composeNetworkIPAMConfig{Subnet: network.IPv6.Subnet, IPRange: network.IPv6.IPRange, Gateway: network.IPv6.Gateway})
		}
		file.Networks[id] = composeNetwork{
			Name: network.Name, Driver: "bridge", EnableIPv6: network.IPv6 != nil,
			DriverOpts: composeBridgeDriverOpts(network.TrustedHostInterfaces, addresses...),
			IPAM:       &composeNetworkIPAM{Driver: "default", Config: configs},
		}
		file.Services["owner"].Networks[id] = composeServiceAttachment{}
	}
	return writeYAML(filepath.Join(manifest.OutputDir, "networks", "docker-compose.yml"), file)
}

func publishedServiceAddress(service resolvedSOCKS5, network string) string {
	for _, endpoint := range service.Endpoints {
		if endpoint.Network == network {
			return endpoint.Address
		}
	}
	return ""
}

func composeBridgeDriverOpts(interfaces []string, serviceAddresses ...string) map[string]string {
	options := map[string]string{}
	if len(interfaces) > 0 {
		options["com.docker.network.bridge.trusted_host_interfaces"] = strings.Join(interfaces, ":")
	}
	for _, serviceAddress := range serviceAddresses {
		if address, err := netip.ParseAddr(serviceAddress); err == nil {
			family := "ipv6"
			if address.Is4() {
				family = "ipv4"
			}
			options["com.docker.network.bridge.gateway_mode_"+family] = "nat-unprotected"
		}
	}
	if len(options) == 0 {
		return nil
	}
	return options
}

func attachmentForAddress(address string) composeServiceAttachment {
	if len(address) != 0 && address[0] != '[' && !containsColon(address) {
		return composeServiceAttachment{IPv4Address: address}
	}
	return composeServiceAttachment{IPv6Address: address}
}

func containsColon(value string) bool {
	for i := range value {
		if value[i] == ':' {
			return true
		}
	}
	return false
}

func writeYAML(path string, value any) error {
	return writeYAMLMode(path, value, 0o644)
}

func writeYAMLMode(path string, value any, mode os.FileMode) error {
	data, err := yaml.Marshal(value)
	if err != nil {
		return err
	}
	return atomicWrite(path, data, mode)
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".photon-services-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
