package photonwindows

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/HiggsNet/photon/internal/photonclient/esp"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

// The same worker seals and submits business and Babel packets. Assigning ESP
// sequence numbers here keeps their submission order on each CHILD SA.
func (m *meshRuntime) runTX(ctx context.Context) {
	writer := m.socket.newMeshPacketWriter()
	defer writer.close()
	for ctx.Err() == nil {
		select {
		case job := <-m.jobs:
			m.sendTXJob(writer, job)
			continue
		default:
		}
		source := m.device.source.Load()
		if source == nil {
			select {
			case <-ctx.Done():
			case <-m.txWake.ready:
			}
			continue
		}
		reader, batchable := source.device.(readyPacketDevice)
		if batchable {
			packet, ok, err := reader.TryRead()
			if ok || err != nil {
				m.handleHostBatch(ctx, writer, meshHostEvent(source.generation, packet, err), reader)
				continue
			}
		}
		waitCtx, finishWait := m.txWake.waitContext(ctx)
		if batchable {
			err := reader.WaitReadable(waitCtx)
			interrupted := waitCtx.Err() != nil
			finishWait()
			if !interrupted && err != nil {
				m.handleHostBatch(ctx, writer, meshHostEvent(source.generation, nil, err), nil)
			}
			continue
		}
		packet, err := source.device.Read(waitCtx)
		interrupted := waitCtx.Err() != nil
		finishWait()
		if err == nil || !interrupted {
			m.handleHostBatch(ctx, writer, meshHostEvent(source.generation, packet, err), nil)
		}
	}
}

type readyPacketDevice interface {
	TryRead() ([]byte, bool, error)
	WaitReadable(context.Context) error
}

func meshHostEvent(generation uint64, packet []byte, err error) leafDevicePacket {
	event := leafDevicePacket{generation: generation, packet: packet, err: err}
	if err == nil {
		event.timing = beginFixturePacketTimingQueue(fixturePacketTimingOutbound)
	}
	return event
}

// wake carries no packets. It interrupts an idle device wait when the adapter
// changes or the existing Babel control queue has work.
type meshTXWake struct {
	mu     sync.Mutex
	cancel context.CancelFunc
	ready  chan struct{}
}

func (w *meshTXWake) signal() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.cancel != nil {
		w.cancel()
	}
	select {
	case w.ready <- struct{}{}:
	default:
	}
}

func (w *meshTXWake) waitContext(ctx context.Context) (context.Context, func()) {
	wait, cancel := context.WithCancel(ctx)
	w.mu.Lock()
	select {
	case <-w.ready:
		cancel()
	default:
	}
	w.cancel = cancel
	w.mu.Unlock()
	return wait, func() {
		w.mu.Lock()
		w.cancel = nil
		w.mu.Unlock()
		cancel()
	}
}

func (m *meshRuntime) sealHost(event leafDevicePacket) (meshHostCompletion, bool) {
	m.stateMu.Lock()
	completion, ok := m.prepareHost(event)
	m.stateMu.Unlock()
	if !ok {
		return completion, false
	}
	job := completion.job
	if job.ctx.Err() != nil {
		completion.timing.Finish(fixturePacketTimingCanceled)
		return completion, false
	}
	if m.outboundScratch == nil {
		m.outboundScratch = make([]byte, 0, esp.MaxPacket)
	}
	completion.timing.MarkAESBegin()
	completion.packet, completion.err = job.sa.sender.SealInto(m.outboundScratch[:0], job.packet)
	completion.timing.MarkAESEnd()
	if completion.err != nil {
		completion.timing.Finish(fixturePacketTimingCryptoError)
		if errors.Is(completion.err, esp.ErrSequenceExhausted) {
			m.observeTX(completion.dataplaneCompletion)
		}
		return completion, false
	}
	return completion, true
}

func (m *meshRuntime) observeTX(completion dataplaneCompletion) {
	m.stateMu.Lock()
	defer m.stateMu.Unlock()
	now := time.Now()
	p := m.byData[completion.job.owner]
	var facts packetAuthorization
	if p != nil && m.packetFacts(p, corestate.View{}, now, &facts) {
		p.tunnel.observeData(completion, facts.plan, now)
	}
}

func (m *meshRuntime) sendTXJob(writer *meshPacketWriter, job dataplaneJob) {
	if job.ctx.Err() != nil {
		return
	}
	completion := executeDataplaneJob(job)
	m.stateMu.Lock()
	var facts packetAuthorization
	p := m.prepareCompletion(&completion, time.Now(), &facts)
	if p == nil {
		m.stateMu.Unlock()
		return
	}
	pipeline := p.leaf.pipeline
	packet, peer, outbound, ok := pipeline.authorizeCompletion(&facts, &completion)
	m.stateMu.Unlock()
	if ok && outbound && job.ctx.Err() == nil {
		completion.timing.MarkDeliveryBegin()
		err := writer.writeTunnel(job.generation, packet, peer, &completion.timing)
		finishOutboundDelivery(&completion.timing, err)
		m.failTX(job, pipeline, err)
	}
}

func (m *meshRuntime) failTX(job dataplaneJob, pipeline *gatewayBabelPipeline, err error) {
	if err == nil {
		return
	}
	m.stateMu.Lock()
	defer m.stateMu.Unlock()
	p := m.byData[job.owner]
	if p != nil && p.leaf.pipeline == pipeline && job.ctx.Err() == nil && job.sa == job.owner.active {
		m.failDelivery(p, err)
	}
}
