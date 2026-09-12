package state

import (
	"net/netip"
	"strings"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

// LinkOutput is the provider-neutral, read-only view of one Babel-facing
// runtime link. Consumers must not use it to reconstruct provider actions or
// decide resource ownership/teardown.
type LinkOutput struct {
	ID             string        `json:"id"`
	GroupID        string        `json:"group_id,omitempty"`
	PeerZone       zone.ZonePath `json:"peer_zone,omitempty"`
	Provider       string        `json:"provider,omitempty"`
	PathKey        string        `json:"path_key,omitempty"`
	NetNS          string        `json:"netns,omitempty"`
	InterfaceName  string        `json:"interface_name,omitempty"`
	LocalAddr      netip.Addr    `json:"local_addr,omitempty"`
	PeerAddr       netip.Addr    `json:"peer_addr,omitempty"`
	MTU            uint32        `json:"mtu,omitempty"`
	BabelBaseCost  uint          `json:"babel_base_cost,omitempty"`
	Generation     uint64        `json:"generation,omitempty"`
	RuntimeRole    string        `json:"runtime_role,omitempty"`
	State          string        `json:"state,omitempty"`
	Readiness      LinkReadiness `json:"readiness,omitempty"`
	Endpoint       string        `json:"endpoint,omitempty"`
	LastTransition int64         `json:"last_transition,omitempty"`
}

type LinkReadiness struct {
	Session   string `json:"session,omitempty"`
	Interface string `json:"interface,omitempty"`
	Routing   string `json:"routing,omitempty"`
	Health    string `json:"health,omitempty"`
}

const (
	LinkRuntimeActive   = "active"
	LinkRuntimeStaged   = "staged"
	LinkRuntimeDraining = "draining"

	LinkReadyUnknown  = "unknown"
	LinkReadyReady    = "ready"
	LinkReadyNotReady = "not_ready"
)

// LinkPathFamily returns the IP family encoded in a link path key.
func LinkPathFamily(pathKey string) string {
	family, ok := strings.CutPrefix(pathKey, "family:")
	if !ok || (family != "ipv4" && family != "ipv6") {
		return ""
	}
	return family
}
