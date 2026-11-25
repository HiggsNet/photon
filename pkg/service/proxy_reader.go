package service

import (
	"net/netip"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

const (
	ProxyReadDirectory = "proxy-directory"
	ProxyReadLinks     = "ipsec-links"
	ProxyReadMaxBytes  = 8 << 20
)

type ProxyReadRequest struct {
	Kind     string `json:"kind"`
	Epoch    string `json:"epoch,omitempty"`
	Revision uint64 `json:"revision,omitempty"`
}

// ProxyReadResponse never includes private keys, history or Gossip checkpoints.
type ProxyReadResponse struct {
	Epoch       string             `json:"epoch"`
	Revision    uint64             `json:"revision"`
	ManagedZone zone.ZonePath      `json:"managed_zone,omitempty"`
	Network     *zone.NetworkState `json:"network,omitempty"`
	Links       []ProxyDirectLink  `json:"links,omitempty"`
}

type ProxyDirectLink struct {
	Peer       zone.ZonePath `json:"peer"`
	ID         string        `json:"id"`
	Generation uint64        `json:"generation"`
	Family     string        `json:"family"`
	NetNS      string        `json:"netns,omitempty"`
	Interface  string        `json:"interface"`
	Local      netip.Addr    `json:"local"`
	Remote     netip.Addr    `json:"remote"`
	Staged     bool          `json:"staged,omitempty"`
}
