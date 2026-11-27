package photonwindows

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"slices"
	"time"
)

const meshIKEWriteQueueSize = 64

type meshIKEWrite struct {
	generation uint64
	peer       netip.AddrPort
	packet     []byte
	deadline   time.Time
	retire     bool
}

type meshIKEWriteFailure struct {
	generation uint64
	err        error
}

func (m *meshRuntime) queueIKEWrite(generation uint64, packet []byte, peer netip.AddrPort, retire bool) error {
	now := time.Now()
	write := meshIKEWrite{
		generation: generation, peer: peer, packet: slices.Clone(packet),
		deadline: now.Add(time.Second), retire: retire,
	}
	select {
	case m.ikeWrites <- write:
		if m.ikeTrace != nil {
			m.traceIKEWrite(now, "send_queued", write)
		}
		return nil
	default:
		if m.ikeTrace != nil {
			m.traceIKEWrite(now, "send_queue_full", write)
		}
		return errors.New("tunnel: IKE send queue full")
	}
}

func (m *meshRuntime) runIKEWrites(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case write := <-m.ikeWrites:
			err := context.DeadlineExceeded
			started := time.Now()
			submitted := started.Before(write.deadline)
			if submitted {
				if m.ikeTrace != nil {
					m.traceIKEWrite(started, "send_started", write)
				}
				err = m.socket.WriteIKE(write.generation, write.packet, write.peer)
			}
			if m.ikeTrace != nil {
				m.traceIKEWrite(time.Now(), "send_finished", write, slog.Time("write_started_at", started),
					slog.Bool("write_attempted", submitted), slog.Any("error", err))
			}
			if write.retire {
				m.socket.releaseTunnel(write.generation)
			} else if err != nil {
				select {
				case m.ikeWriteFailures <- meshIKEWriteFailure{write.generation, err}:
				case <-ctx.Done():
					return
				}
			}
		}
	}
}

func (m *meshRuntime) traceIKEWrite(at time.Time, stage string, write meshIKEWrite, attrs ...slog.Attr) {
	header, ok := ikeTraceHeader(write.packet)
	if !ok {
		return
	}
	r := m.ikeTrace.event(at, stage, write.generation, write.peer, attrs...)
	r.AddAttrs(slog.Time("send_queued_at", write.deadline.Add(-time.Second)), slog.Int("wire_bytes", len(write.packet)))
	addIKETraceHeader(&r, header)
	m.ikeTrace.emit(r)
}

func (t *gatewayTunnel) writeIKE(packet []byte) error {
	if t.queueIKE != nil {
		return t.queueIKE(t.generation, packet, t.peer, false)
	}
	return t.socket.WriteIKE(t.generation, packet, t.peer)
}
