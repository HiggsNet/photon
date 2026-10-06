package photonwindows

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"slices"
	"time"

	"github.com/HiggsNet/photon/internal/photonclient/babel"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

// packetDevice is the delivery half of a packet device. Its bounded reader is
// pumped by the same event loop through SubmitPacket; this owner starts no I/O
// goroutine and never lets control packets enter the host stack.
type packetDevice interface{ Write([]byte) error }

// gatewayBabelPipeline is an experimental, single-gateway packet owner. The
// caller supplies an immediately current view at each serial event, including
// crypto completion, and pins actual local addresses and both link-local ends.
// Rekey retains this owner; rebind, gateway replacement or revoked attachment
// permanently invalidates it. Production console activation still requires a
// local address intent and publication of the gateway's real full Babel ID.
type gatewayBabelPipeline struct {
	tunnel      *gatewayTunnel
	device      packetDevice
	leaf        *babel.Leaf
	local, peer netip.Addr
	addresses   []netip.Addr
	routerID    [8]byte
	generation  uint64
}

func newGatewayBabelPipeline(tunnel *gatewayTunnel, device packetDevice, local, peer netip.Addr, id [8]byte, addresses []netip.Addr) (*gatewayBabelPipeline, error) {
	if tunnel == nil || tunnel.socket == nil || device == nil || len(addresses) == 0 || len(addresses) > babel.MaxOrigins {
		return nil, errors.New("Babel pipeline: attachment or local addresses absent")
	}
	for _, a := range addresses {
		if !businessAddress(a) {
			return nil, errors.New("Babel pipeline: invalid local address")
		}
	}
	leaf, err := babel.NewLeaf(local, peer, id, 100)
	if err != nil {
		return nil, err
	}
	return &gatewayBabelPipeline{tunnel: tunnel, device: device, leaf: leaf, local: local, peer: peer, routerID: id, addresses: slices.Clone(addresses), generation: tunnel.generation}, nil
}

func (p *gatewayBabelPipeline) current(config *Config, view corestate.View, plan GatewayPlan, now time.Time) (GatewayPlan, bool) {
	t := p.tunnel
	if p.leaf == nil {
		return GatewayPlan{}, false
	}
	valid := config != nil && t.generation == p.generation && t.phase == 3 && t.failed == nil && t.session != nil && t.data != nil && now.Before(t.ikeExpiresAt) && now.Before(t.expiresAt)
	if valid {
		binding, err := localTransportAuthorization(config, view, now)
		valid = err == nil && binding == t.localAuthorization && currentBabelOrigins(config, view, now)[p.routerID] == config.ManagedZone
	}
	current := GatewayPlan{}
	if valid {
		current = revalidateActiveGateway(config, view, plan, now)
		valid = t.current(current) && t.data.current(t.generation, t.data.active, current)
	}
	if !valid {
		p.leaf = nil
	}
	return current, valid
}

func (p *gatewayBabelPipeline) localOrigins(config *Config, view corestate.View, now time.Time) []babel.Origin {
	var out []babel.Origin
	for _, permission := range authorizedGatewayRoutes(config, view, now) {
		if permission.Origin != config.ManagedZone {
			continue
		}
		for _, a := range p.addresses {
			if permission.Prefix.Contains(a) {
				out = append(out, babel.Origin{Prefix: permission.Prefix})
				break
			}
		}
	}
	return out
}

func (p *gatewayBabelPipeline) localAddress(address netip.Addr, origins []babel.Origin) bool {
	if !slices.Contains(p.addresses, address) {
		return false
	}
	for _, o := range origins {
		if o.Prefix.Contains(address) {
			return true
		}
	}
	return false
}

// authorize is evaluated both before crypto and immediately before delivery.
// Inbound business packets must have an authorized reverse route and terminate
// at an exact local address. This never forwards traffic between remote hosts.
func (p *gatewayBabelPipeline) authorize(config *Config, view corestate.View, plan GatewayPlan, now time.Time, packet []byte, outbound bool) bool {
	if _, ok := p.current(config, view, plan, now); !ok {
		return false
	}
	origins := p.localOrigins(config, view, now)
	endpoint, source := p.local, p.peer
	if outbound {
		endpoint, source = p.peer, p.local
	}
	if from, payload, err := babel.ParsePacket(packet, endpoint); err == nil && from == source {
		messages, err := babel.Decode(payload, from)
		if err != nil {
			return false
		}
		if outbound {
			for _, m := range messages {
				if m.Type != babel.TLVUpdate || m.Metric == babel.MetricInfinity {
					continue
				}
				if m.RouterID != p.routerID || m.SourcePrefix.IsValid() || !slices.Contains(origins, babel.Origin{Prefix: m.Prefix}) {
					return false
				}
			}
		}
		return true
	}
	src, dst, ok := businessEndpoints(packet)
	if !ok {
		return false
	}
	if !outbound {
		src, dst = dst, src
	}
	if !p.localAddress(src, origins) {
		return false
	}
	candidates := p.leaf.Candidates(now, currentBabelRouteAuthorizer(config, view, now))
	return len(p.tunnel.lookupBabelRoutes(config, view, plan, view.Revision, candidates, src, dst, now)) != 0
}

func (p *gatewayBabelPipeline) send(config *Config, view corestate.View, plan GatewayPlan, now time.Time, messages []babel.Message) {
	// Encode self-contained batches, including router/next-hop context. A full
	// origin set must fit the bounded crypto queue without starving its tail.
	for len(messages) > 0 {
		var payload []byte
		count := 0
		for count < len(messages) && count < babel.MaxMessages {
			candidate, err := babel.Encode(messages[:count+1])
			if err != nil || len(candidate) > 1200 {
				break
			}
			payload = candidate
			count++
		}
		if count == 0 {
			messages = messages[1:]
			continue
		}
		messages = messages[count:]
		packet, err := babel.BuildPacket(p.local, p.peer, payload)
		if err != nil {
			continue
		}
		p.tunnel.data.submitOutbound(p.generation, plan, packet, func(packet []byte, outbound bool) bool { return p.authorize(config, view, plan, now, packet, outbound) })
	}
}

func (p *gatewayBabelPipeline) Tick(config *Config, view corestate.View, plan GatewayPlan, now time.Time) {
	current, ok := p.current(config, view, plan, now)
	if !ok {
		return
	}
	messages, err := p.leaf.SetLocal(p.localOrigins(config, view, now))
	if err != nil {
		p.leaf = nil
		return
	}
	p.send(config, view, current, now, append(messages, p.leaf.Tick(now)...))
}

func (p *gatewayBabelPipeline) SubmitPacket(config *Config, view corestate.View, plan GatewayPlan, now time.Time, packet []byte) bool {
	// Host-originated Babel/control traffic is never accepted as daemon control.
	if _, _, ok := businessEndpoints(packet); !ok {
		return false
	}
	current, ok := p.current(config, view, plan, now)
	if !ok {
		return false
	}
	return p.tunnel.data.submitOutbound(p.generation, current, packet, func(packet []byte, outbound bool) bool { return p.authorize(config, view, plan, now, packet, outbound) })
}

func (p *gatewayBabelPipeline) Accept(config *Config, view corestate.View, plan GatewayPlan, now time.Time, completion dataplaneCompletion) (bool, error) {
	current, ok := p.current(config, view, plan, now)
	if !ok {
		return false, nil
	}
	packet, peer, outbound, ok := p.tunnel.data.accept(completion, current, func(packet []byte, outbound bool) bool { return p.authorize(config, view, plan, now, packet, outbound) })
	if !ok {
		return false, nil
	}
	if outbound {
		return true, p.tunnel.socket.WriteTunnel(p.generation, packet, peer)
	}
	if from, _, err := babel.ParsePacket(packet, p.local); err == nil && from == p.peer {
		updates, err := p.leaf.SetLocal(p.localOrigins(config, view, now))
		if err != nil {
			p.leaf = nil
			return false, err
		}
		messages, err := p.leaf.Receive(packet, now, currentBabelRouteAuthorizer(config, view, now))
		if err != nil {
			return false, err
		}
		p.send(config, view, current, now, append(updates, messages...))
		return true, nil
	}
	return true, p.device.Write(packet)
}

func businessAddress(a netip.Addr) bool {
	return a.IsGlobalUnicast() && a.Zone() == "" && !a.Is4In6() && !a.IsLoopback()
}

func businessEndpoints(packet []byte) (netip.Addr, netip.Addr, bool) {
	var src, dst netip.Addr
	if len(packet) >= 20 && packet[0]>>4 == 4 {
		ihl := int(packet[0]&15) * 4
		if ihl < 20 || ihl > len(packet) || int(binary.BigEndian.Uint16(packet[2:4])) != len(packet) {
			return src, dst, false
		}
		src, dst = netip.AddrFrom4([4]byte(packet[12:16])), netip.AddrFrom4([4]byte(packet[16:20]))
	} else if len(packet) >= 40 && packet[0]>>4 == 6 && int(binary.BigEndian.Uint16(packet[4:6]))+40 == len(packet) {
		src, dst = netip.AddrFrom16([16]byte(packet[8:24])), netip.AddrFrom16([16]byte(packet[24:40]))
	}
	return src, dst, businessAddress(src) && businessAddress(dst)
}
