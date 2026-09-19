package photonlinux

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

// tunnelAddressConfigYAML is the tunnel_address block of an overlay.
type tunnelAddressConfigYAML struct {
	Mode   string `yaml:"mode"`
	Family string `yaml:"family"`
	Pool   string `yaml:"pool"`
}

// Parse validates the address family and pool and applies tunnel address defaults.
func (cfg tunnelAddressConfigYAML) parse() (ipsec.TunnelAddressSpec, error) {
	mode := ipsec.TunnelAddressMode(strings.ToLower(strings.TrimSpace(cfg.Mode)))
	switch mode {
	case "", ipsec.TunnelAddressDerivedLinkLocal, ipsec.TunnelAddressDerivedPool, ipsec.TunnelAddressSequentialPool, ipsec.TunnelAddressDisabled:
		// ok
	default:
		return ipsec.TunnelAddressSpec{}, fmt.Errorf("invalid tunnel_address.mode %q", cfg.Mode)
	}
	family := strings.ToLower(strings.TrimSpace(cfg.Family))
	switch family {
	case "", ipsec.FamilyIPv4, ipsec.FamilyIPv6:
		// ok
	default:
		return ipsec.TunnelAddressSpec{}, fmt.Errorf("invalid tunnel_address.family %q", cfg.Family)
	}
	var prefix netip.Prefix
	if cfg.Pool != "" {
		var err error
		prefix, err = netip.ParsePrefix(cfg.Pool)
		if err != nil {
			return ipsec.TunnelAddressSpec{}, fmt.Errorf("invalid tunnel_address.pool %q: %w", cfg.Pool, err)
		}
		if family == "" {
			if prefix.Addr().Is4() {
				family = ipsec.FamilyIPv4
			} else {
				family = ipsec.FamilyIPv6
			}
		}
		if prefix.Addr().Is4() && family != ipsec.FamilyIPv4 {
			return ipsec.TunnelAddressSpec{}, fmt.Errorf("tunnel_address.family %q does not match pool %q", cfg.Family, cfg.Pool)
		}
		if prefix.Addr().Is6() && family != ipsec.FamilyIPv6 {
			return ipsec.TunnelAddressSpec{}, fmt.Errorf("tunnel_address.family %q does not match pool %q", cfg.Family, cfg.Pool)
		}
	}
	if mode == "" {
		if family == ipsec.FamilyIPv4 {
			mode = ipsec.TunnelAddressDisabled
		} else {
			mode = ipsec.TunnelAddressDerivedLinkLocal
		}
	}
	if (mode == ipsec.TunnelAddressDerivedPool || mode == ipsec.TunnelAddressSequentialPool) && !prefix.IsValid() {
		return ipsec.TunnelAddressSpec{}, fmt.Errorf("tunnel_address.mode %q requires a pool", mode)
	}
	return ipsec.TunnelAddressSpec{
		Mode:   mode,
		Family: family,
		Pool:   prefix,
	}, nil
}

// ValidateIPsecRotateWindows keeps previous ports alive through overlay rotation.
func ValidateIPsecRotateWindows(groups []ipsec.LinkGroupSpec, portPreviousGrace time.Duration) error {
	maxRetention := time.Duration(0)
	for _, group := range groups {
		retention := group.Normalized().Reconcile.RotateRetentionSeconds
		if d := time.Duration(retention) * time.Second; d > maxRetention {
			maxRetention = d
		}
	}
	if maxRetention > 0 && portPreviousGrace < maxRetention {
		return fmt.Errorf("ipsec.port_previous_grace %s must be at least overlays[].reconcile.rotate_retention %s", portPreviousGrace, maxRetention)
	}
	return nil
}

const defaultIPsecPortPreviousGrace = 2 * time.Hour

// IPsecConfig is the effective Linux IPsec configuration.
type IPsecConfig struct {
	DefaultNetNS              ipsec.NetNSSpec
	LinkGroups                []ipsec.LinkGroupSpec
	Role                      string
	Driver                    string
	VICISocket                string
	PortMode                  string
	PortRange                 ipsec.PortRange
	PortRotateInterval        time.Duration
	PortPreviousGrace         time.Duration
	AnnounceAddrs             []string
	AnnounceDNS               []string
	AnnounceDNSReconnectAfter time.Duration
	AnnounceGossipEndpoints   bool
}

// IPsecConfigYAML is the top-level ipsec configuration block.
type IPsecConfigYAML struct {
	Role                      string           `yaml:"role"`
	DeprecatedAccept          string           `yaml:"accept"`
	Driver                    string           `yaml:"driver"`
	VICISocket                string           `yaml:"vici_socket"`
	PortMode                  string           `yaml:"port_mode"`
	PortRange                 ipsec.PortRange  `yaml:"port_range"`
	PortRotateInterval        string           `yaml:"port_rotate_interval"`
	PortPreviousGrace         string           `yaml:"port_previous_grace"`
	AnnounceAddrs             configStringList `yaml:"announce_addrs"`
	AnnounceDNS               configStringList `yaml:"announce_dns"`
	AnnounceDNSReconnectAfter string           `yaml:"announce_dns_reconnect_after"`
	AnnounceGossipEndpoints   *bool            `yaml:"announce_gossip_endpoints"`
}

// DefaultIPsecConfig supplies defaults before explicit YAML fields are applied.
func DefaultIPsecConfig() IPsecConfig {
	config := IPsecConfig{
		DefaultNetNS:              ipsec.NetNSSpec{}.Normalized(),
		AnnounceGossipEndpoints:   true,
		AnnounceDNSReconnectAfter: 5 * time.Minute,
	}
	config.Normalize()
	return config
}

// Normalize fills unset runtime defaults without overriding explicit announcement choices.
func (config *IPsecConfig) Normalize() {
	if config.Role == "" {
		config.Role = ipsec.RoleBoth
	}
	if config.Driver == "" {
		config.Driver = IPsecDriverStrongSwan
	}
	if config.PortMode == "" {
		config.PortMode = ipsec.PortModeFixed
	}
	if config.PortPreviousGrace <= 0 {
		config.PortPreviousGrace = defaultIPsecPortPreviousGrace
	}
}

// Apply applies YAML fields to an existing configuration, preserving omitted values.
func (raw IPsecConfigYAML) Apply(config *IPsecConfig) error {
	if raw.Driver != "" {
		driver, err := parseIPsecDriver(raw.Driver)
		if err != nil {
			return err
		}
		config.Driver = driver
	}
	if raw.Role != "" {
		role := strings.ToLower(strings.TrimSpace(raw.Role))
		switch role {
		case ipsec.RoleOut, ipsec.RoleIn, ipsec.RoleBoth:
			config.Role = role
		default:
			return fmt.Errorf("invalid ipsec.role %q", raw.Role)
		}
	}
	if raw.DeprecatedAccept != "" {
		return fmt.Errorf("ipsec.accept is deprecated; use ipsec.role")
	}
	if raw.VICISocket != "" {
		config.VICISocket = raw.VICISocket
	}
	if raw.PortMode != "" {
		mode := strings.ToLower(strings.TrimSpace(raw.PortMode))
		if !ipsec.ValidPortMode(mode) {
			return fmt.Errorf("invalid ipsec.port_mode %q", raw.PortMode)
		}
		config.PortMode = mode
	}
	if config.PortMode == ipsec.PortModeRange {
		if raw.PortRange.From == 0 || raw.PortRange.To == 0 || raw.PortRange.From > raw.PortRange.To {
			return fmt.Errorf("invalid ipsec.port_range %d-%d", raw.PortRange.From, raw.PortRange.To)
		}
		if uint32(raw.PortRange.To)-uint32(raw.PortRange.From)+1 < 4 {
			return fmt.Errorf("ipsec.port_range %d-%d must contain at least two IKE/NAT-T port pairs", raw.PortRange.From, raw.PortRange.To)
		}
		config.PortRange = raw.PortRange
	}
	if raw.PortRotateInterval != "" {
		d, err := parseIPsecDuration(raw.PortRotateInterval, "ipsec.port_rotate_interval")
		if err != nil {
			return err
		}
		config.PortRotateInterval = d
	}
	if raw.PortPreviousGrace != "" {
		d, err := parseIPsecDuration(raw.PortPreviousGrace, "ipsec.port_previous_grace")
		if err != nil {
			return err
		}
		config.PortPreviousGrace = d
	}
	for _, raw := range raw.AnnounceAddrs {
		candidate := strings.TrimSpace(raw)
		addr, err := netip.ParseAddr(candidate)
		if err != nil {
			return fmt.Errorf("invalid ipsec.announce_addrs entry %q: expected an IP address without a port", raw)
		}
		config.AnnounceAddrs = append(config.AnnounceAddrs, addr.String())
	}
	config.AnnounceDNS = append(config.AnnounceDNS, raw.AnnounceDNS...)
	if raw.AnnounceDNSReconnectAfter != "" {
		d, err := parseIPsecDuration(raw.AnnounceDNSReconnectAfter, "ipsec.announce_dns_reconnect_after")
		if err != nil {
			return err
		}
		if d < 0 {
			return fmt.Errorf("ipsec.announce_dns_reconnect_after must not be negative")
		}
		config.AnnounceDNSReconnectAfter = d
	}
	if raw.AnnounceGossipEndpoints != nil {
		config.AnnounceGossipEndpoints = *raw.AnnounceGossipEndpoints
	}
	return nil
}

const (
	IPsecDriverDryRun     = "dry-run"
	IPsecDriverStrongSwan = "strongswan"
)

func parseIPsecDriver(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", IPsecDriverDryRun:
		return IPsecDriverDryRun, nil
	case IPsecDriverStrongSwan, "system", "vici":
		return IPsecDriverStrongSwan, nil
	default:
		return "", fmt.Errorf("invalid ipsec.driver %q: expected dry-run or strongswan", value)
	}
}

func parseIPsecDuration(value, name string) (time.Duration, error) {
	d, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("invalid %s: %q", name, value)
	}
	return d, nil
}
