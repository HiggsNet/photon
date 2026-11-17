package main

import (
	"fmt"
	"strings"
)

func selectProxyServices(manifest *manifest, raw string) error {
	if raw == "" {
		return nil
	}
	selected := map[string]bool{}
	for _, kind := range strings.Split(raw, ",") {
		switch kind {
		case "http", "socks5", "trusttunnel", "none":
			selected[kind] = true
		default:
			return fmt.Errorf("unknown proxy protocol %q", kind)
		}
	}
	if selected["none"] && len(selected) != 1 {
		return fmt.Errorf("--only none cannot be combined with protocols")
	}
	// Removing an explicit HTTP block must not re-enable the v1 implicit one.
	if manifest.HTTP != nil {
		manifest.Version = 2
	}
	if !selected["http"] {
		manifest.HTTP = nil
	}
	if !selected["socks5"] {
		manifest.SOCKS5 = socks5Config{}
	}
	if !selected["trusttunnel"] {
		manifest.TrustTunnel = trustTunnelConfig{}
	}
	return nil
}

// Apply access policy before a deployment starts any listener. publish repeats
// this step after its data-plane checks and before making records visible.
func prepareProxyACLs(photon string, manifest resolvedManifest) error {
	apply := func(name, address string, zones []string) error {
		if len(zones) == 0 {
			return runPhoton(photon, "firewall", "endpoint", "remove", name)
		}
		args := []string{"firewall", "endpoint", "apply", name, "--destination", address, "--scope", "ip"}
		for _, zone := range zones {
			args = append(args, "--allow-zone", zone)
		}
		return runPhoton(photon, args...)
	}
	for _, e := range manifest.SOCKS5.Endpoints {
		if err := apply(endpointACLName(e.Network), e.Address, manifest.SOCKS5.AllowZones); err != nil {
			return err
		}
		if address := manifest.SOCKS5.Networks[e.Network].H2; address != "" {
			if err := apply(httpEndpointACLName(e.Network), address, manifest.SOCKS5.AllowZones); err != nil {
				return err
			}
		}
	}
	for _, e := range manifest.HTTP.Endpoints {
		if err := apply("http-"+e.Network, e.Address, manifest.HTTP.AllowZones); err != nil {
			return err
		}
	}
	for _, e := range manifest.TrustTunnel.Endpoints {
		if err := apply("trusttunnel-"+e.Network, e.Address, manifest.TrustTunnel.AllowZones); err != nil {
			return err
		}
	}
	return nil
}
