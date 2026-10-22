package photonwindows

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net/netip"
	"slices"
	"sync"

	"github.com/HiggsNet/photon/internal/photonclient/esp"
	"github.com/HiggsNet/photon/internal/photonclient/ike"
)

const dataplaneQueueSize = 64

// gatewayDataplane belongs to the daemon event loop. The daemon also owns all
// crypto, including queued control packets. Standalone asynchronous consumers
// may use workers; all owner methods serialize revocation and delivery.
// It holds negotiated SAs, never a second copy of verified network state.
type gatewayDataplane struct {
	ctx              context.Context
	cancel           context.CancelFunc
	workers          sync.WaitGroup
	jobs             chan dataplaneJob
	completed        chan dataplaneCompletion
	generation       uint64
	generationCtx    context.Context
	cancelGeneration context.CancelFunc
	sas              map[uint32]*dataplaneSA
	active           *dataplaneSA
	outboundScratch  []byte // Only the serial owned-business turn may borrow it.
}

type dataplaneSA struct {
	gateway       GatewaySelection
	endpoint      netip.AddrPort
	receiver      *esp.Receiver
	sender        *esp.Sender
	local, remote []ike.TrafficSelector
	spi           uint32
	keys          [2][32]byte
}

type dataplaneJob struct {
	ctx        context.Context
	generation uint64
	sa         *dataplaneSA
	packet     []byte
	outbound   bool
}

type dataplaneCompletion struct {
	timing fixturePacketTiming
	job    dataplaneJob
	packet []byte
	err    error
}

func newGatewayDataplane(ctx context.Context) *gatewayDataplane {
	d := newSerialGatewayDataplane(ctx)
	for range 2 {
		d.workers.Add(1)
		go d.work()
	}
	return d
}

// The daemon consumes jobs itself, so Babel cannot allocate an ESP sequence
// in a background worker and deliver it after the peer's replay window moved
// past it. Each owner turn finishes bounded AES, revalidates and sends before
// another packet can allocate a sequence. The existing control queue is bounded.
func newSerialGatewayDataplane(ctx context.Context) *gatewayDataplane {
	ctx, cancel := context.WithCancel(ctx)
	d := &gatewayDataplane{ctx: ctx, cancel: cancel, jobs: make(chan dataplaneJob, dataplaneQueueSize), completed: make(chan dataplaneCompletion, dataplaneQueueSize)}
	d.reset(0)
	return d
}

func (d *gatewayDataplane) close() {
	d.reset(d.generation + 1)
	d.cancel()
	d.workers.Wait()
}

// reset is deny-first: already running crypto may finish, but its result cannot
// be accepted, and queued jobs observe cancellation before doing more work.
func (d *gatewayDataplane) reset(generation uint64) {
	if d.cancelGeneration != nil {
		d.cancelGeneration()
	}
	d.generation = generation
	d.generationCtx, d.cancelGeneration = context.WithCancel(d.ctx)
	d.sas = make(map[uint32]*dataplaneSA)
	d.active = nil
	d.outboundScratch = nil
}

// install consumes fresh authenticated CHILD material exactly once. The owner
// must revalidate the plan and the AUTH generation before calling this method.
// Three SAs permit the old CHILD plus two simultaneous rekey candidates.
// The owner activates the winner; installation alone preserves an active SA.
func (d *gatewayDataplane) install(generation uint64, plan GatewayPlan, endpoint netip.AddrPort, child ike.ChildResult) error {
	if d.ctx.Err() != nil || generation != d.generation || plan.Rejected != "" || plan.Selected == nil || !dataplaneEndpoint(*plan.Selected, endpoint) {
		return errors.New("dataplane: stale or unauthorized CHILD")
	}
	if d.active != nil && !dataplaneGatewayEqual(d.active.gateway, *plan.Selected) {
		return errors.New("dataplane: reset required before changing gateway")
	}
	if len(d.sas) >= 3 || d.sas[child.InitiatorSPI] != nil {
		return errors.New("dataplane: overlapping CHILD limit or duplicate SPI")
	}
	keys := [2][32]byte{sha256.Sum256(child.Keys.InitiatorToResponder), sha256.Sum256(child.Keys.ResponderToInitiator)}
	if keys[0] == keys[1] {
		return errors.New("dataplane: directional key reuse")
	}
	for _, existing := range d.sas {
		for _, key := range existing.keys {
			if key == keys[0] || key == keys[1] {
				return errors.New("dataplane: overlapping CHILD key reuse")
			}
		}
	}
	if _, err := ike.EncodeTrafficSelectors(child.LocalSelectors); err != nil {
		return err
	}
	if _, err := ike.EncodeTrafficSelectors(child.RemoteSelectors); err != nil {
		return err
	}
	receiver, err := esp.NewReceiver(child.InitiatorSPI, child.Keys.ResponderToInitiator)
	if err != nil {
		return err
	}
	sender, err := esp.NewSender(child.ResponderSPI, child.Keys.InitiatorToResponder)
	if err != nil {
		return err
	}
	gateway := *plan.Selected
	gateway.PublicKey = bytes.Clone(gateway.PublicKey)
	sa := &dataplaneSA{gateway: gateway, endpoint: endpoint, receiver: receiver, sender: sender, local: slices.Clone(child.LocalSelectors), remote: slices.Clone(child.RemoteSelectors), spi: child.InitiatorSPI, keys: keys}
	d.sas[sa.spi] = sa
	if d.active == nil {
		d.active = sa
	}
	return nil
}

func (d *gatewayDataplane) activate(spi uint32) error {
	sa := d.sas[spi]
	if d.ctx.Err() != nil || sa == nil {
		return errors.New("dataplane: unknown CHILD")
	}
	d.active = sa
	return nil
}

func (d *gatewayDataplane) retire(spi uint32) {
	if d.active == d.sas[spi] {
		d.active = nil
	}
	delete(d.sas, spi)
}

func (d *gatewayDataplane) submitInbound(generation uint64, plan GatewayPlan, endpoint netip.AddrPort, packet []byte) bool {
	sa := d.inboundSA(generation, plan, endpoint, packet)
	return sa != nil && d.submit(sa, packet, false)
}

func (d *gatewayDataplane) inboundSA(generation uint64, plan GatewayPlan, endpoint netip.AddrPort, packet []byte) *dataplaneSA {
	if len(packet) < 36 || len(packet) > esp.MaxPacket {
		return nil
	}
	sa := d.sas[binary.BigEndian.Uint32(packet[:4])]
	if sa == nil || endpoint != sa.endpoint || !d.current(generation, sa, plan) {
		return nil
	}
	return sa
}

// authorize is the owner's current B4 route/control-packet verdict. A selected
// gateway and broad negotiated selectors alone never authorize user traffic.
// A nil verdict is deliberately deny-all until the B4 owner is connected.
func (d *gatewayDataplane) submitOutbound(generation uint64, plan GatewayPlan, packet []byte, authorize func([]byte, bool) bool) bool {
	sa := d.outboundSA(generation, plan, packet, authorize)
	return sa != nil && d.submit(sa, packet, true)
}

func (d *gatewayDataplane) outboundSA(generation uint64, plan GatewayPlan, packet []byte, authorize func([]byte, bool) bool) *dataplaneSA {
	sa := d.active
	if !d.current(generation, sa, plan) || !dataplaneSelectors(sa, packet, true) || authorize == nil || !authorize(packet, true) {
		return nil
	}
	return sa
}

// Direct processing shares queued preflight and AES, then requires fresh owner
// authorization at accept. Inbound borrows ciphertext only during synchronous
// Open, which returns detached plaintext; its completion retains no input.
// Outbound owns its plaintext for rechecking at accept. AES errors still reach
// observeData (including sequence exhaustion).
func (d *gatewayDataplane) processInbound(generation uint64, plan GatewayPlan, endpoint netip.AddrPort, packet []byte) (dataplaneCompletion, bool) {
	sa := d.inboundSA(generation, plan, endpoint, packet)
	if sa == nil || d.ctx.Err() != nil {
		return dataplaneCompletion{}, false
	}
	job := dataplaneJob{ctx: d.generationCtx, generation: d.generation, sa: sa, packet: packet}
	result := executeDataplaneJob(job)
	// The ciphertext is no longer needed on success, error or cancellation.
	result.job.packet = nil
	return result, true
}

// processOwnedInbound consumes one detached, exclusively owned UDP-demux
// packet in the serial daemon turn. A successful inner packet aliases that
// storage. On every error the result exposes no packet, and the input remains
// consumed: the caller must not retry it, clear it, or return it to a pool.
// Ordinary borrowed and asynchronous inputs retain processInbound/Open's
// detached-output contract. No completion retains the ciphertext as job input.
func (d *gatewayDataplane) processOwnedInbound(generation uint64, plan GatewayPlan, endpoint netip.AddrPort, packet []byte, timing fixturePacketTiming) (dataplaneCompletion, bool) {
	sa := d.inboundSA(generation, plan, endpoint, packet)
	if sa == nil || d.ctx.Err() != nil {
		return dataplaneCompletion{timing: timing}, false
	}
	result := dataplaneCompletion{timing: timing, job: dataplaneJob{ctx: d.generationCtx, generation: d.generation, sa: sa}}
	if err := result.job.ctx.Err(); err != nil {
		result.err = err
		return result, true
	}
	result.timing.MarkAESBegin()
	result.packet, result.err = sa.receiver.OpenOwned(packet)
	result.timing.MarkAESEnd()
	if result.err == nil && result.timing.Sampled() {
		if _, _, business := businessEndpoints(result.packet); business {
			result.timing.Classify(fixturePacketTimingBusiness)
		}
	}
	return result, true
}

func (d *gatewayDataplane) processOutbound(generation uint64, plan GatewayPlan, packet []byte, authorize func([]byte, bool) bool) (dataplaneCompletion, bool) {
	return d.process(d.outboundSA(generation, plan, packet, authorize), packet, true)
}

// processOwnedOutbound is only for an exclusively owned leaf packet in the
// serial daemon turn. Its completion owns that plaintext through the fresh
// delivery gate: the caller must not reuse or mutate it until completePacket
// finishes. The ESP output borrows this owner's single bounded workspace until
// synchronous delivery or drop completes; the next owned outbound call may
// overwrite it. Do not retain the completion beyond that turn or reenter this
// method during authorization/delivery. It never enters either asynchronous
// queue; queued control and other callers retain independent Seal outputs.
func (d *gatewayDataplane) processOwnedOutbound(generation uint64, plan GatewayPlan, packet []byte, authorize func([]byte, bool) bool, timing fixturePacketTiming) (dataplaneCompletion, bool) {
	sa := d.outboundSA(generation, plan, packet, authorize)
	if sa == nil || d.ctx.Err() != nil {
		return dataplaneCompletion{timing: timing}, false
	}
	job := dataplaneJob{ctx: d.generationCtx, generation: d.generation, sa: sa, packet: packet, outbound: true}
	result := dataplaneCompletion{timing: timing, job: job}
	if err := job.ctx.Err(); err != nil {
		result.err = err
		return result, true
	}
	if d.outboundScratch == nil {
		d.outboundScratch = make([]byte, esp.MaxPacket)
	}
	result.timing.MarkAESBegin()
	result.packet, result.err = sa.sender.SealInto(d.outboundScratch[:0], packet)
	result.timing.MarkAESEnd()
	return result, true
}

func (d *gatewayDataplane) process(sa *dataplaneSA, packet []byte, outbound bool) (dataplaneCompletion, bool) {
	job, ok := d.newJob(sa, packet, outbound)
	if !ok {
		return dataplaneCompletion{}, false
	}
	return executeDataplaneJob(job), true
}

func (d *gatewayDataplane) newJob(sa *dataplaneSA, packet []byte, outbound bool) (dataplaneJob, bool) {
	if sa == nil || d.ctx.Err() != nil {
		return dataplaneJob{}, false
	}
	return dataplaneJob{ctx: d.generationCtx, generation: d.generation, sa: sa, packet: bytes.Clone(packet), outbound: outbound}, true
}

func (d *gatewayDataplane) submit(sa *dataplaneSA, packet []byte, outbound bool) bool {
	job, ok := d.newJob(sa, packet, outbound)
	if !ok {
		return false
	}
	select {
	case d.jobs <- job:
		return true
	default:
		return false
	}
}

func executeDataplaneJob(job dataplaneJob) dataplaneCompletion {
	result := dataplaneCompletion{job: job}
	if err := job.ctx.Err(); err != nil {
		result.err = err
		return result
	}
	if job.outbound {
		result.packet, result.err = job.sa.sender.Seal(job.packet)
	} else {
		result.packet, result.err = job.sa.receiver.Open(job.packet)
	}
	return result
}

// accept must run immediately before delivery in the same owner turn as its
// fresh authorization verdict. Rejected/stale crypto completions expose no data.
func (d *gatewayDataplane) accept(result dataplaneCompletion, plan GatewayPlan, authorize func([]byte, bool) bool) ([]byte, netip.AddrPort, bool, bool) {
	job := result.job
	if result.err != nil || job.ctx.Err() != nil || !d.current(job.generation, job.sa, plan) || (job.outbound && job.sa != d.active) {
		return nil, netip.AddrPort{}, false, false
	}
	inner := result.packet
	if job.outbound {
		inner = job.packet
	}
	if !dataplaneSelectors(job.sa, inner, job.outbound) || authorize == nil || !authorize(inner, job.outbound) {
		return nil, netip.AddrPort{}, false, false
	}
	return result.packet, job.sa.endpoint, job.outbound, true
}

func (d *gatewayDataplane) current(generation uint64, sa *dataplaneSA, plan GatewayPlan) bool {
	return d.ctx.Err() == nil && sa != nil && generation == d.generation && d.sas[sa.spi] == sa && plan.Rejected == "" && plan.Selected != nil && dataplaneGatewayEqual(sa.gateway, *plan.Selected) && dataplaneEndpoint(*plan.Selected, sa.endpoint)
}

func (d *gatewayDataplane) work() {
	defer d.workers.Done()
	for {
		select {
		case <-d.ctx.Done():
			return
		case job := <-d.jobs:
			if job.ctx.Err() != nil {
				continue
			}
			result := executeDataplaneJob(job)
			select {
			case <-d.ctx.Done():
				return
			case <-job.ctx.Done():
			case d.completed <- result:
			}
		}
	}
}

func dataplaneGatewayEqual(a, b GatewaySelection) bool {
	return a.Zone == b.Zone && a.Identity == b.Identity && a.Fingerprint == b.Fingerprint && bytes.Equal(a.PublicKey, b.PublicKey) && a.Contact.Address == b.Contact.Address && a.Contact.IKEPort == b.Contact.IKEPort && a.Contact.NATTPort == b.Contact.NATTPort && a.Contact.Generation == b.Contact.Generation
}

func dataplaneEndpoint(gateway GatewaySelection, endpoint netip.AddrPort) bool {
	address, err := netip.ParseAddr(gateway.Contact.Address)
	return err == nil && endpoint.IsValid() && endpoint.Addr() == address.Unmap() && endpoint.Port() != 0 && (endpoint.Port() == gateway.Contact.IKEPort || endpoint.Port() == gateway.Contact.NATTPort)
}
