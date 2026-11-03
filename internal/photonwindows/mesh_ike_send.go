package photonwindows

import (
	"context"
	"errors"
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
	write := meshIKEWrite{
		generation: generation, peer: peer, packet: slices.Clone(packet),
		deadline: time.Now().Add(time.Second), retire: retire,
	}
	select {
	case m.ikeWrites <- write:
		return nil
	default:
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
			if time.Now().Before(write.deadline) {
				err = m.socket.WriteIKE(write.generation, write.packet, write.peer)
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

func (t *gatewayTunnel) writeIKE(packet []byte) error {
	if t.queueIKE != nil {
		return t.queueIKE(t.generation, packet, t.peer, false)
	}
	return t.socket.WriteIKE(t.generation, packet, t.peer)
}
