package photonwindows

import (
	"encoding/json"
	"time"

	corehost "github.com/HiggsNet/photon/pkg/core/host"
)

// Connections reports actual independent peer lifetimes. The legacy summary
// describes one representative connection; it is never an exclusive gateway.
type ConnectionObservation struct {
	Peer        string         `json:"peer"`
	IKE         IKEObservation `json:"ike"`
	BabelLive   bool           `json:"babel_live"`
	TunnelReady bool           `json:"tunnel_ready"`
}

func (m *meshRuntime) observe(plan GatewayPlan, driver *corehost.GossipDriver) Observation {
	view, now := m.state.Store().ReadView(), time.Now()
	peers := m.ordered()
	var representative *meshPeer
	for _, p := range peers {
		ready := p.leaf.ready(&p.config, view, p.plan, now)
		if representative == nil || p.tunnel.phase > representative.tunnel.phase || ready {
			representative = p
		}
		if ready {
			break
		}
	}
	// Keep the previous detached observation contract even before discovery.
	if representative == nil {
		data := newSerialGatewayDataplane(m.ctx)
		defer data.close()
		representative = &meshPeer{config: *m.config, tunnel: &gatewayTunnel{socket: m.socket, data: data}, leaf: newLeafRuntime(nil)}
	}
	out := observeRuntime(&representative.config, view, representative.plan, now, m.socket, representative.tunnel, representative.leaf, driver)
	out.Gateway = observeGatewayPlan(plan, RevalidateGatewayPlan(m.config, view, plan, now))
	out.TunnelReady = false
	out.Babel.Routes = nil
	connectionBytes := 2
	for _, p := range peers {
		sample := observeRuntime(&p.config, view, p.plan, now, m.socket, p.tunnel, p.leaf, nil)
		out.TunnelReady = out.TunnelReady || sample.TunnelReady
		connection := ConnectionObservation{Peer: boundedObservationText(string(p.config.Gateway.AllowedZones[0])), IKE: sample.IKE, BabelLive: sample.Babel.Live, TunnelReady: sample.TunnelReady}
		encoded, _ := json.Marshal(connection)
		if len(out.Connections) < 256 && connectionBytes+len(encoded)+1 <= 128<<10 {
			out.Connections = append(out.Connections, connection)
			connectionBytes += len(encoded) + 1
		} else {
			out.ConnectionsTruncated = true
		}
		for _, route := range sample.Babel.Routes {
			if len(out.Babel.Routes) == 256 {
				out.RoutesTruncated = true
				break
			}
			route.Peer = string(p.config.Gateway.AllowedZones[0])
			out.Babel.Routes = append(out.Babel.Routes, route)
		}
	}
	return out
}
