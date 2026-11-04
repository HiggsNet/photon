package photonwindows

import (
	"context"
	"errors"
	"time"

	"github.com/HiggsNet/photon/internal/photonclient/babel"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

// runRX owns inbound ESP and Wintun delivery. The socket has detached every
// queued datagram, so the receiver can decrypt it in place.
func (m *meshRuntime) runRX(ctx context.Context) {
	for ctx.Err() == nil {
		select {
		case <-ctx.Done():
			return
		case packet := <-m.socket.espPackets:
			m.receiveESP(packet)
		}
	}
}

func (m *meshRuntime) receiveESP(packet tunnelDatagram) {
	packet.timing.Dequeue()
	job, ok := m.prepareRX(packet)
	if !ok {
		packet.timing.Finish(fixturePacketTimingRejected)
		return
	}
	completion := openOwnedInbound(job, packet.packet, packet.timing)
	device, pipeline := m.prepareRXDelivery(&completion)
	if device == nil {
		return
	}
	if job.ctx.Err() != nil {
		completion.timing.Finish(fixturePacketTimingCanceled)
		return
	}
	// The fresh gate committed delivery before releasing the state lock. The
	// device handles its own lifetime while this write is in progress.
	if _, err := deliverInbound(device, completion.packet, &completion.timing); err != nil {
		m.stateMu.Lock()
		p := m.byData[job.owner]
		if p != nil && p.leaf.pipeline == pipeline && job.ctx.Err() == nil {
			m.failDelivery(p, err)
		}
		m.stateMu.Unlock()
	}
}

func (m *meshRuntime) prepareRX(packet tunnelDatagram) (dataplaneJob, bool) {
	m.stateMu.Lock()
	defer m.stateMu.Unlock()
	p := m.findGeneration(packet.generation)
	var facts packetAuthorization
	if p == nil || !m.packetFacts(p, corestate.View{}, time.Now(), &facts) {
		return dataplaneJob{}, false
	}
	data := p.tunnel.data
	sa := data.inboundSA(packet.generation, facts.plan, packet.peer, packet.packet)
	if sa == nil {
		return dataplaneJob{}, false
	}
	return dataplaneJob{owner: data, ctx: data.generationCtx, generation: packet.generation, sa: sa}, true
}

func openOwnedInbound(job dataplaneJob, packet []byte, timing fixturePacketTiming) dataplaneCompletion {
	result := dataplaneCompletion{timing: timing, job: job}
	if err := job.ctx.Err(); err != nil {
		result.err = err
		return result
	}
	result.timing.MarkAESBegin()
	result.packet, result.err = job.sa.receiver.OpenOwned(packet)
	result.timing.MarkAESEnd()
	if result.err == nil && result.timing.Sampled() {
		if _, _, business := businessEndpoints(result.packet); business {
			result.timing.Classify(fixturePacketTimingBusiness)
		}
	}
	return result
}

func (m *meshRuntime) prepareRXDelivery(completion *dataplaneCompletion) (packetDevice, *gatewayBabelPipeline) {
	m.stateMu.Lock()
	defer m.stateMu.Unlock()
	var facts packetAuthorization
	p := m.prepareCompletion(completion, time.Now(), &facts)
	if p == nil {
		return nil, nil
	}
	pipeline := p.leaf.pipeline
	packet, _, _, ok := pipeline.authorizeCompletion(&facts, completion)
	if !ok {
		return nil, nil
	}
	device, accepted, err := pipeline.prepareInboundDelivery(&facts, packet, &completion.timing)
	if err != nil {
		m.failDelivery(p, err)
	} else if accepted && device == nil {
		m.noteSequence(p)
	}
	return device, pipeline
}

// prepareInboundDelivery processes Babel messages under the route owner's
// state guard and returns the already-authorized device for business traffic.
func (p *gatewayBabelPipeline) prepareInboundDelivery(facts *packetAuthorization, packet []byte, timing *fixturePacketTiming) (packetDevice, bool, error) {
	if from, _, err := babel.ParsePacket(packet, p.local); err == nil && from == p.peer {
		timing.Classify(fixturePacketTimingControl)
		updates, err := p.leaf.SetLocal(facts.localOrigins)
		if err != nil {
			p.leaf = nil
			timing.Finish(fixturePacketTimingRejected)
			return nil, false, err
		}
		messages, err := p.leaf.Receive(packet, facts.now, facts.authorizeRoute)
		if err != nil {
			timing.Finish(fixturePacketTimingRejected)
			return nil, false, err
		}
		p.send(facts, append(updates, messages...))
		timing.Finish(fixturePacketTimingDelivered)
		return nil, true, nil
	}
	if p.device == nil {
		timing.Finish(fixturePacketTimingRejected)
		return nil, false, nil
	}
	return p.device, true, nil
}

func deliverInbound(device packetDevice, packet []byte, timing *fixturePacketTiming) (bool, error) {
	timing.MarkDeliveryBegin()
	err := device.Write(packet)
	timing.MarkDeliveryEnd()
	if err != nil {
		timing.Finish(fixturePacketTimingDeliveryError)
		// A full ring drops this packet while the host drains the ring.
		if errors.Is(err, errPacketDeviceFull) {
			return false, nil
		}
	} else {
		timing.Finish(fixturePacketTimingDelivered)
	}
	return true, err
}
