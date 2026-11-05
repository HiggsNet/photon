package photonwindows

import (
	"context"
	"time"
)

const (
	meshHostBatchSize = 8
	// Fit in the IPv4 UDP payload limit, also safe for IPv6.
	maxHostBatchPayload = 65507
)

// Only this synchronous owner turn may submit a sealed host packet.
type meshHostCompletion struct {
	dataplaneCompletion
	pipeline   *gatewayBabelPipeline
	projection *meshPolicyProjection
}

func (c *meshHostCompletion) finishStale() {
	outcome := fixturePacketTimingRejected
	if c.job.ctx.Err() != nil {
		outcome = fixturePacketTimingCanceled
	}
	c.timing.Finish(outcome)
}

type meshHostBatch struct {
	packets [meshHostBatchSize]meshHostCompletion
	wire    []byte
	count   int
	size    int
}

func (m *meshRuntime) handleHostBatch(ctx context.Context, pending <-chan leafDevicePacket, first leafDevicePacket) {
	if !udpSegmentation || len(pending) == 0 || m.socket.udpSegmentationDisabled.Load() {
		m.handleHost(first)
		return
	}

	if m.outboundBatch == nil {
		m.outboundBatch = make([]byte, maxHostBatchPayload)
	}
	batch := meshHostBatch{wire: m.outboundBatch[:0]}
	event := first
	for i := 0; ; i++ {
		// A device read error can tear down the attachment. Submit any
		// preceding packets before entering that lifecycle path.
		if event.err != nil {
			batch.flush(m)
			m.handleHost(event)
			return
		}
		if completion, ok := m.prepareHost(event); ok {
			if len(completion.packet)*2 > maxHostBatchPayload {
				batch.flush(m)
				m.completeHost(completion)
			} else {
				if !batch.canAppend(completion) {
					batch.flush(m)
				}
				batch.append(completion)
			}
		}
		if i+1 == meshHostBatchSize || ctx.Err() != nil {
			break
		}
		select {
		case event = <-pending:
		default:
			batch.flush(m)
			return
		}
	}
	batch.flush(m)
}

func (b *meshHostBatch) canAppend(completion meshHostCompletion) bool {
	if b.count == 0 {
		return true
	}
	first := &b.packets[0]
	job := first.job
	return first.pipeline == completion.pipeline && first.projection == completion.projection &&
		job.owner == completion.job.owner && job.generation == completion.job.generation &&
		job.sa == completion.job.sa && b.size == len(completion.packet) &&
		len(b.wire)+b.size <= cap(b.wire)
}

func (b *meshHostBatch) append(completion meshHostCompletion) {
	// processOwnedOutbound's single workspace is overwritten by the next
	// encryption. Keep each ciphertext distinct until the batch is written.
	start := len(b.wire)
	b.wire = append(b.wire, completion.packet...)
	completion.packet = b.wire[start:]
	b.size = len(completion.packet)
	b.packets[b.count] = completion
	b.count++
}

func (b *meshHostBatch) flush(m *meshRuntime) {
	if b.count == 0 {
		return
	}
	packets := b.packets[:b.count]
	wire := b.wire
	defer func() {
		clear(packets)
		b.count, b.size, b.wire = 0, 0, b.wire[:0]
	}()
	if b.count == 1 {
		m.completeHost(packets[0])
		return
	}

	p := m.currentHost(&packets[0], time.Now())
	if p == nil {
		for i := range packets {
			packets[i].finishStale()
		}
		return
	}
	var traces [meshHostBatchSize]fixturePacketTiming
	for i := range packets {
		traces[i] = packets[i].timing
		traces[i].MarkDeliveryBegin()
	}
	job := packets[0].job
	submitted, err := m.socket.writeTunnelSegments(job.generation, job.sa.endpoint, wire, b.size, traces[:len(packets)])
	if submitted {
		for i := range packets {
			finishOutboundDelivery(&traces[i], err)
		}
		if err != nil {
			m.failDelivery(p, err)
		}
		return
	}

	// Winsock definitively rejected segmentation. Submit the same ciphertext
	// in order using ordinary writes and the same transport gate.
	for _, completion := range packets {
		m.completeHost(completion)
	}
}
