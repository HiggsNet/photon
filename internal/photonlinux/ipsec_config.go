package photonlinux

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

// TunnelAddressConfigYAML is the tunnel_address block of an overlay.
type TunnelAddressConfigYAML struct {
	Mode   string `yaml:"mode"`
	Family string `yaml:"family"`
	Pool   string `yaml:"pool"`
}

// Parse validates the address family and pool and applies tunnel address defaults.
func (cfg TunnelAddressConfigYAML) Parse() (ipsec.TunnelAddressSpec, error) {
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
