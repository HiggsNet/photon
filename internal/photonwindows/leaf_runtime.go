package photonwindows

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/HiggsNet/photon/internal/photonclient/sadr"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
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
	factory              packetDeviceFactory
	pipeline             *gatewayBabelPipeline
	device               ownedPacketDevice
	attachment           leafAttachment
	opened               chan leafOpenResult
	packets              chan leafDevicePacket
	request              uint64
	pending              bool
	cancelOpen           context.CancelFunc
	openWG               sync.WaitGroup
	cancelRead           context.CancelFunc
	readWG               sync.WaitGroup
	retryAt              time.Time
	nameRecoveryDeadline time.Time
}

func newLeafRuntime(factory packetDeviceFactory) *leafRuntime {
	return &leafRuntime{factory: factory, opened: make(chan leafOpenResult, 1), packets: make(chan leafDevicePacket, 64)}
}

func desiredLeafAttachment(config *Config, view corestate.View, plan GatewayPlan, tunnel *gatewayTunnel, id [8]byte, now time.Time) (leafAttachment, error) {
	return desiredLeafAttachmentWithVerifier(config, view, plan, tunnel, id, now, nil)
}

// An attached pipeline can share only its bounded signature-math memo here.
// Lifecycle intent and every authorization/time check are still reconstructed
// from the supplied current view, including for an arbitrary mutable View.
func desiredLeafAttachmentWithVerifier(config *Config, view corestate.View, plan GatewayPlan, tunnel *gatewayTunnel, id [8]byte, now time.Time, verifier *photoncrypto.Verifier) (leafAttachment, error) {
	want := leafAttachment{generation: tunnel.generation, id: id}
	if tunnel.phase != 3 || tunnel.failed != nil || tunnel.session == nil || tunnel.data == nil || !now.Before(tunnel.expiresAt) || !now.Before(tunnel.ikeExpiresAt) {
		return want, errors.New("leaf: authenticated SA unavailable")
	}
	binding, err := localTransportAuthorizationWithVerifier(config, view, now, verifier)
	if err != nil || binding != tunnel.localAuthorization {
		return want, errors.New("leaf: local transport authorization changed")
	}
	current := revalidateActiveGatewaySelection(config, view, plan, now, verifier)
	if !tunnel.current(current) || !tunnel.data.current(tunnel.generation, tunnel.data.active, current) {
		return want, errors.New("leaf: current gateway unavailable")
	}
	if currentBabelOriginsWithVerifier(config, view, now, verifier)[id] != config.ManagedZone {
		return want, errors.New("leaf: local Babel identity unavailable")
	}
	want.addresses, want.routes = leafDeviceIntentFromSet(config, currentAuthorizedRouteSetWithVerifier(config, view, now, verifier))
	if len(want.addresses) == 0 {
		return want, errors.New("leaf: no authorized unicast host assignment and announcement")
	}
	want.local, want.peer, err = leafLinkLocalAddressesWithVerifier(config, view, current, now, verifier)
	return want, err
}

// stop is deny-first even if adapter cleanup fails. Pending platform work must
// close its own result after cancellation; its request can never be attached.
func (r *leafRuntime) stop() error {
	r.nameRecoveryDeadline = time.Time{}
	return r.stopDevice()
}

// Retry cleanup does not cancel the current naming recovery episode. Explicit
// stop/revocation uses stop above and clears its budget.
func (r *leafRuntime) stopDevice() error {
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
	var verifier *photoncrypto.Verifier
	if r.pipeline != nil {
		verifier = r.pipeline.verifier
	}
	want, err := desiredLeafAttachmentWithVerifier(config, view, plan, tunnel, id, now, verifier)
	if err != nil {
		return errors.Join(err, r.stop())
	}
	if !r.attachment.equal(want) {
		r.nameRecoveryDeadline = time.Time{}
	}
	if !r.nameRecoveryDeadline.IsZero() && !now.Before(r.nameRecoveryDeadline) {
		return errors.Join(fmt.Errorf("%w: %q", errPacketDeviceRecoveryExpired, config.Wintun.AdapterName), r.stop())
	}
	if r.pipeline != nil && r.pipeline.leaf != nil && r.attachment.equal(want) {
		return nil
	}
	if r.pending && r.attachment.equal(want) {
		return nil
	}
	if err := r.stopDevice(); err != nil {
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
	want, err := desiredLeafAttachment(config, view, plan, tunnel, id, now)
	if result.revision != view.Revision || err != nil || !want.equal(result.want) {
		if result.device != nil {
			return errors.Join(err, result.device.Close())
		}
		return err
	}
	if !r.nameRecoveryDeadline.IsZero() && !now.Before(r.nameRecoveryDeadline) {
		err := fmt.Errorf("%w: %q", errPacketDeviceRecoveryExpired, config.Wintun.AdapterName)
		if result.device != nil {
			err = errors.Join(err, result.device.Close())
		}
		return err
	}
	if result.err != nil {
		if errors.Is(result.err, errPacketDeviceNamePending) && r.nameRecoveryDeadline.IsZero() {
			r.nameRecoveryDeadline = now.Add(30 * time.Second)
		}
		r.retryAt = now.Add(5 * time.Second)
		if result.device != nil {
			return errors.Join(result.err, result.device.Close())
		}
		return result.err
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
	r.nameRecoveryDeadline = time.Time{}
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

// readySnapshot is only for the daemon's immutable packetStateView. Readiness
// shares its current signed facts with packet delivery, but still reads the
// live neighbor/candidate table and requires a source on this actual device.
// Ordinary ready remains the entry point for IPC and arbitrary mutable Views.
func (r *leafRuntime) readySnapshot(config *Config, view corestate.View, plan GatewayPlan, now time.Time) bool {
	if r.pipeline == nil {
		return false
	}
	p := r.pipeline
	var facts packetAuthorization
	if !p.prepareSnapshotInto(config, view, plan, now, &facts) {
		return false
	}
	for _, route := range p.leaf.Candidates(now, facts.authorizeRoute) {
		for _, host := range facts.hosts {
			source := host.Addr()
			if !p.localAddress(source, facts.localOrigins) {
				continue
			}
			if sadr.HasRoute([]sadr.Route{route}, source, route.Destination.Addr(), now, facts.authorizeRoute) {
				return true
			}
		}
	}
	return false
}
