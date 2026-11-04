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

// Only the TX worker may submit a sealed host packet.
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

func (m *meshRuntime) handleHostBatch(ctx context.Context, writer *meshPacketWriter, first leafDevicePacket, reader readyPacketDevice) {
	if !udpSegmentation || reader == nil || m.socket.udpSegmentationDisabled.Load() {
		if completion, ok := m.sealHost(first); ok {
			m.submitHost(writer, &completion)
		}
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
			batch.flush(m, writer)
			m.sealHost(event)
			return
		}
		if completion, ok := m.sealHost(event); ok {
			if len(completion.packet)*2 > maxHostBatchPayload {
				batch.flush(m, writer)
				m.submitHost(writer, &completion)
			} else {
				if !batch.canAppend(completion) {
					batch.flush(m, writer)
				}
				batch.append(completion)
			}
		}
		if i+1 == meshHostBatchSize || ctx.Err() != nil {
			break
		}
		packet, ok, err := reader.TryRead()
		if !ok && err == nil {
			break
		}
		event = meshHostEvent(first.generation, packet, err)
	}
	batch.flush(m, writer)
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
	// The sender's scratch is overwritten by the next
	// encryption. Keep each ciphertext distinct until the batch is written.
	start := len(b.wire)
	b.wire = append(b.wire, completion.packet...)
	completion.packet = b.wire[start:]
	b.size = len(completion.packet)
	b.packets[b.count] = completion
	b.count++
}

func (b *meshHostBatch) flush(m *meshRuntime, writer *meshPacketWriter) {
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
		m.submitHost(writer, &packets[0])
		return
	}

	if !m.hostCanSubmit(&packets[0]) {
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
	submitted, err := writer.writeTunnelSegments(job.generation, job.sa.endpoint, wire, b.size, traces[:len(packets)])
	if submitted {
		for i := range packets {
			finishOutboundDelivery(&traces[i], err)
		}
		m.failTX(job, packets[0].pipeline, err)
		return
	}

	// Winsock definitively rejected segmentation. Submit the same ciphertext
	// in order using ordinary writes and the same transport gate.
	for i := range packets {
		m.submitHost(writer, &packets[i])
	}
}

func (m *meshRuntime) hostCanSubmit(completion *meshHostCompletion) bool {
	m.stateMu.Lock()
	defer m.stateMu.Unlock()
	return m.currentHost(completion, time.Now()) != nil
}

func (m *meshRuntime) submitHost(writer *meshPacketWriter, completion *meshHostCompletion) {
	if !m.hostCanSubmit(completion) {
		completion.finishStale()
		return
	}
	job := completion.job
	completion.timing.MarkDeliveryBegin()
	err := writer.writeTunnel(job.generation, completion.packet, job.sa.endpoint, &completion.timing)
	finishOutboundDelivery(&completion.timing, err)
	m.failTX(job, completion.pipeline, err)
}
