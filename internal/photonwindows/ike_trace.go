package photonwindows

import (
	"context"
	"encoding/binary"
	"log/slog"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/HiggsNet/photon/internal/photonclient/ike"
)

// IKE debug tracing never waits for the logger, even with a full trace queue.
// Records contain public headers and timing only. Protocol queues are separate.
type ikeTrace struct {
	records chan slog.Record
	stop    chan struct{}
	done    chan struct{}
	nextID  atomic.Uint64
	dropped atomic.Uint64
}

func startIKETrace(logger *slog.Logger) *ikeTrace {
	ctx := context.Background()
	if !logger.Enabled(ctx, slog.LevelDebug) {
		return nil
	}
	trace := &ikeTrace{records: make(chan slog.Record, 1024), stop: make(chan struct{}), done: make(chan struct{})}
	handler := logger.Handler()
	go func() {
		defer close(trace.done)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		reportDrops := func() {
			if dropped := trace.dropped.Swap(0); dropped != 0 {
				logger.Warn("ike_trace_overflow", "dropped_events", dropped)
			}
		}
		for {
			select {
			case record := <-trace.records:
				_ = handler.Handle(ctx, record)
			case <-ticker.C:
				reportDrops()
			case <-trace.stop:
				for {
					select {
					case record := <-trace.records:
						_ = handler.Handle(ctx, record)
					default:
						reportDrops()
						return
					}
				}
			}
		}
	}()
	return trace
}

func (t *ikeTrace) close() {
	if t != nil {
		close(t.stop)
		<-t.done
	}
}

type ikeTraceDatagram struct {
	at    time.Time
	id    uint64
	wire  int
	ident ike.Header
}

func (t *ikeTrace) read(wire []byte) *ikeTraceDatagram {
	if t == nil || len(wire) < ike.HeaderLen {
		return nil
	}
	at := time.Now()
	header, ok := ikeTraceHeader(wire)
	if !ok {
		return nil
	}
	return &ikeTraceDatagram{at: at, id: t.nextID.Add(1), ident: header, wire: len(wire)}
}

func ikeTraceHeader(wire []byte) (ike.Header, bool) {
	if len(wire) >= ike.HeaderLen+4 && binary.BigEndian.Uint32(wire) == 0 {
		if header, ok := decodeIKETraceHeader(wire[4:]); ok {
			return header, ok
		}
	}
	return decodeIKETraceHeader(wire)
}

func decodeIKETraceHeader(wire []byte) (ike.Header, bool) {
	if len(wire) < ike.HeaderLen || wire[17]>>4 != 2 || binary.BigEndian.Uint32(wire[24:]) != uint32(len(wire)) {
		return ike.Header{}, false
	}
	header, _, err := ike.DecodeHeader(wire)
	return header, err == nil
}

func (t *ikeTrace) event(at time.Time, stage string, generation uint64, peer netip.AddrPort, attrs ...slog.Attr) slog.Record {
	record := slog.NewRecord(at, slog.LevelDebug, "ike_trace", 0)
	record.AddAttrs(slog.String("stage", stage))
	if generation != 0 {
		record.AddAttrs(slog.Uint64("generation", generation))
	}
	if peer.IsValid() {
		record.AddAttrs(slog.String("remote", peer.String()))
	}
	record.AddAttrs(attrs...)
	return record
}

func (t *ikeTrace) emit(record slog.Record) {
	select {
	case t.records <- record:
	default:
		t.dropped.Add(1)
	}
}

func addIKETraceHeader(record *slog.Record, header ike.Header) {
	record.AddAttrs(
		slog.Uint64("initiator_spi", header.InitiatorSPI), slog.Uint64("responder_spi", header.ResponderSPI),
		slog.Int("exchange", int(header.ExchangeType)), slog.Int("flags", int(header.Flags)),
		slog.Uint64("message_id", uint64(header.MessageID)),
	)
}

func (t *ikeTrace) ingress(at time.Time, stage string, d ikeDatagram, attrs ...slog.Attr) {
	if t == nil || d.trace == nil {
		return
	}
	r := t.event(at, stage, d.generation, d.peer, attrs...)
	r.AddAttrs(slog.Uint64("rx_id", d.trace.id), slog.String("socket_read_at", d.trace.at.UTC().Format(time.RFC3339Nano)),
		slog.Int64("since_read_us", at.Sub(d.trace.at).Microseconds()), slog.Int("wire_bytes", d.trace.wire))
	addIKETraceHeader(&r, d.trace.ident)
	t.emit(r)
}

func (t *ikeTrace) worker(at time.Time, stage string, request *meshIKEResponse, attrs ...slog.Attr) {
	if t == nil {
		return
	}
	if request.timer.kind == 0 {
		t.ingress(at, stage, request.packet, attrs...)
		return
	}
	r := t.event(at, stage, request.packet.generation, request.packet.peer, attrs...)
	r.AddAttrs(slog.Int("timer_kind", int(request.timer.kind)), slog.Time("timer_due_at", request.at))
	t.emit(r)
}
