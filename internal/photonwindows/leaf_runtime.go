package photonwindows

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/HiggsNet/photon/internal/photonclient/sadr"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

type leafAttachment struct {
	generation        uint64
	id                [8]byte
	local, peer       netip.Addr
	addresses, routes []netip.Prefix
}

func (a leafAttachment) equal(b leafAttachment) bool {
	return a.generation == b.generation && a.id == b.id && a.local == b.local && a.peer == b.peer && slices.Equal(a.addresses, b.addresses) && slices.Equal(a.routes, b.routes)
}

type leafOpenResult struct {
	request  uint64
	revision corestate.VerifiedRevision
	want     leafAttachment
	device   ownedPacketDevice
	err      error
}
type leafDevicePacket struct {
	generation uint64
	packet     []byte
	err        error
}

// leafRuntime belongs to the daemon event loop. Platform creation/DAD and the
// bounded device reader run outside it. Every asynchronous result is checked
// against current authorization before its first usable packet.
type leafRuntime struct {
	factory    packetDeviceFactory
	pipeline   *gatewayBabelPipeline
	device     ownedPacketDevice
	attachment leafAttachment
	opened     chan leafOpenResult
	packets    chan leafDevicePacket
	request    uint64
	pending    bool
	cancelOpen context.CancelFunc
	openWG     sync.WaitGroup
	cancelRead context.CancelFunc
	readWG     sync.WaitGroup
	retryAt    time.Time
}

func newLeafRuntime(factory packetDeviceFactory) *leafRuntime {
	return &leafRuntime{factory: factory, opened: make(chan leafOpenResult, 1), packets: make(chan leafDevicePacket, 64)}
}

func desiredLeafAttachment(config *Config, view corestate.View, plan GatewayPlan, tunnel *gatewayTunnel, id [8]byte, now time.Time) (leafAttachment, error) {
	want := leafAttachment{generation: tunnel.generation, id: id}
	if tunnel.phase != 3 || tunnel.failed != nil || tunnel.session == nil || tunnel.data == nil || !now.Before(tunnel.expiresAt) || !now.Before(tunnel.ikeExpiresAt) {
		return want, errors.New("leaf: authenticated SA unavailable")
	}
	binding, err := localTransportAuthorization(config, view, now)
	if err != nil || binding != tunnel.localAuthorization {
		return want, errors.New("leaf: local transport authorization changed")
	}
	current := revalidateActiveGateway(config, view, plan, now)
	if !tunnel.current(current) || !tunnel.data.current(tunnel.generation, tunnel.data.active, current) {
		return want, errors.New("leaf: current gateway unavailable")
	}
	if currentBabelOrigins(config, view, now)[id] != config.ManagedZone {
		return want, errors.New("leaf: local Babel identity unavailable")
	}
	want.addresses, want.routes = leafDeviceIntent(config, view, now)
	if len(want.addresses) == 0 {
		return want, errors.New("leaf: no authorized unicast host assignment and announcement")
	}
	want.local, want.peer, err = leafLinkLocalAddresses(config, view, current, now)
	return want, err
}

// stop is deny-first even if adapter cleanup fails. Pending platform work must
// close its own result after cancellation; its request can never be attached.
func (r *leafRuntime) stop() error {
	r.pipeline = nil
	r.request++
	if r.cancelOpen != nil {
		r.cancelOpen()
		r.cancelOpen = nil
	}
	r.pending = false
	if r.cancelRead != nil {
		r.cancelRead()
		r.cancelRead = nil
	}
	var err error
	if r.device != nil {
		err = r.device.Close()
		r.device = nil
	}
	r.readWG.Wait()
	for {
		select {
		case <-r.packets:
		default:
			return err
		}
	}
}
func (r *leafRuntime) close() error {
	err := r.stop()
	r.openWG.Wait()
	for {
		select {
		case result := <-r.opened:
			if result.device != nil {
				err = errors.Join(err, result.device.Close())
			}
		default:
			return err
		}
	}
}
func (r *leafRuntime) reconcile(ctx context.Context, config *Config, view corestate.View, plan GatewayPlan, tunnel *gatewayTunnel, id [8]byte, now time.Time) error {
	want, err := desiredLeafAttachment(config, view, plan, tunnel, id, now)
	if err != nil {
		return errors.Join(err, r.stop())
	}
	if r.pipeline != nil && r.pipeline.leaf != nil && r.attachment.equal(want) {
		return nil
	}
	if r.pending && r.attachment.equal(want) {
		return nil
	}
	if err := r.stop(); err != nil {
		return err
	}
	if now.Before(r.retryAt) {
		return nil
	}
	r.attachment = want
	r.pending = true
	openCtx, cancel := context.WithCancel(ctx)
	r.cancelOpen = cancel
	request := r.request
	r.openWG.Add(1)
	go func() {
		defer r.openWG.Done()
		device, err := r.factory(openCtx, config.Wintun.AdapterName, slices.Clone(want.addresses), slices.Clone(want.routes), uint32(config.Wintun.MTU), 100)
		result := leafOpenResult{request: request, revision: view.Revision, want: want, device: device, err: err}
		if openCtx.Err() != nil {
			if device != nil {
				_ = device.Close()
			}
			return
		}
		select {
		case r.opened <- result:
		case <-openCtx.Done():
			if device != nil {
				_ = device.Close()
			}
		}
	}()
	return nil
}

func (r *leafRuntime) complete(ctx context.Context, config *Config, view corestate.View, plan GatewayPlan, tunnel *gatewayTunnel, id [8]byte, now time.Time, result leafOpenResult) error {
	if result.request != r.request {
		if result.device != nil {
			return result.device.Close()
		}
		return nil
	}
	r.pending = false
	if result.err != nil {
		r.retryAt = now.Add(5 * time.Second)
		if result.device != nil {
			return errors.Join(result.err, result.device.Close())
		}
		return result.err
	}
	want, err := desiredLeafAttachment(config, view, plan, tunnel, id, now)
	if result.revision != view.Revision || err != nil || !want.equal(result.want) {
		if result.device != nil {
			return errors.Join(err, result.device.Close())
		}
		return err
	}
	if result.device == nil {
		return errors.New("leaf: device factory returned no device")
	}
	addresses := make([]netip.Addr, len(want.addresses))
	for i, p := range want.addresses {
		addresses[i] = p.Addr()
	}
	pipeline, err := newGatewayBabelPipeline(tunnel, result.device, want.local, want.peer, id, addresses)
	if err != nil {
		return errors.Join(err, result.device.Close())
	}
	r.device, r.pipeline, r.attachment = result.device, pipeline, want
	readCtx, cancel := context.WithCancel(ctx)
	r.cancelRead = cancel
	r.readWG.Add(1)
	go func() {
		defer r.readWG.Done()
		for {
			packet, err := result.device.Read(readCtx)
			if readCtx.Err() != nil {
				return
			}
			event := leafDevicePacket{generation: want.generation, packet: packet, err: err}
			if err != nil {
				select {
				case r.packets <- event:
				case <-readCtx.Done():
				}
				return
			}
			select {
			case r.packets <- event:
			default:
			}
		}
	}()
	return nil
}
func (r *leafRuntime) ready(config *Config, view corestate.View, plan GatewayPlan, now time.Time) bool {
	if r.pipeline == nil {
		return false
	}
	if _, ok := r.pipeline.current(config, view, plan, now); !ok {
		return false
	}
	origins := r.pipeline.localOrigins(config, view, now)
	for _, route := range r.pipeline.leaf.Candidates(now, currentBabelRouteAuthorizer(config, view, now)) {
		for _, origin := range origins {
			source := origin.Prefix.Addr()
			if source.BitLen() != route.Destination.Addr().BitLen() || route.Source.IsValid() && !route.Source.Contains(source) {
				continue
			}
			if len(r.pipeline.tunnel.lookupBabelRoutes(config, view, plan, view.Revision, []sadr.Route{route}, source, route.Destination.Addr(), now)) != 0 {
				return true
			}
		}
	}
	return false
}
