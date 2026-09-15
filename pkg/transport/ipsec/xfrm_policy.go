package ipsec

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// XFRMBackend selects how the SystemXFRMDriver materializes a per-link L3
// device and binds CHILD SAs to it.
type XFRMBackend string

const (
	// XFRMBackendInterface creates XFRM interfaces (phx*) and binds SAs via
	// if_id. This is the historical default and requires
	// CONFIG_XFRM_INTERFACE in the kernel.
	XFRMBackendInterface XFRMBackend = "interface"
	// XFRMBackendPolicy uses pure xfrm policies without any virtual device.
	// The local tunnel address is assigned to lo; charon installs xfrm
	// policies and states via VICI. This works on any kernel with xfrm
	// support, including the stock WSL2 kernel which is built without
	// CONFIG_XFRM_INTERFACE.
	XFRMBackendPolicy XFRMBackend = "policy"
)

// NormalizeXFRMBackend parses a config value into an XFRMBackend. The empty
// string selects the historical XFRM interface backend.
func NormalizeXFRMBackend(value string) (XFRMBackend, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", string(XFRMBackendInterface):
		return XFRMBackendInterface, nil
	case string(XFRMBackendPolicy):
		return XFRMBackendPolicy, nil
	default:
		return "", fmt.Errorf("invalid xfrm backend %q: expected interface or policy", value)
	}
}

func (d SystemXFRMDriver) policyBackend() bool {
	return d.Backend == XFRMBackendPolicy
}

// ensurePolicyRoute installs a route for the peer's tunnel address so the
// kernel routes matching packets through the xfrm framework. The route uses
// the same outer interface that reaches the peer's underlay address.
func (d SystemXFRMDriver) ensurePolicyRoute(ctx context.Context, netns NetNSSpec, spec TransportLinkSpec) error {
	if !spec.LocalTunnelAddr.IsValid() || !spec.PeerTunnelAddr.IsValid() {
		return nil
	}
	family, bits := "-4", 32
	want6 := spec.PeerTunnelAddr.Is6()
	if want6 {
		family, bits = "-6", 128
	}
	// Discover the outer interface by looking up the route to the peer's
	// underlay contact address of the same family.
	var peerUnderlay string
	for _, point := range spec.ContactPoints {
		addr := strings.TrimSpace(point.Address)
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		is6 := ip.To4() == nil
		if is6 != want6 {
			continue
		}
		peerUnderlay = addr
		break
	}
	dev := ""
	if peerUnderlay != "" {
		out, err := d.outputInNetNS(ctx, netns, family, "route", "get", peerUnderlay)
		if err == nil {
			dev = parseRouteDev(string(out))
		}
	}
	if dev == "" {
		out, err := d.outputInNetNS(ctx, netns, family, "route", "show", "default")
		if err == nil {
			dev = parseRouteDev(string(out))
		}
	}
	if dev == "" {
		return fmt.Errorf("cannot determine outer interface for policy route (link %s)", spec.LinkID)
	}
	prefix := netip.PrefixFrom(spec.PeerTunnelAddr, bits)
	return d.runInNetNS(ctx, netns, family, "route", "replace",
		prefix.String(), "dev", dev, "src", spec.LocalTunnelAddr.String())
}

// parseRouteDev extracts the "dev <name>" field from `ip route` output.
func parseRouteDev(out string) string {
	fields := strings.Fields(out)
	for i, field := range fields {
		if field == "dev" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
}
