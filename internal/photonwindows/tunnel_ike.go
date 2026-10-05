package photonwindows

import (
	"errors"
	"time"

	"github.com/HiggsNet/photon/internal/photonclient/ike"
)

// At most the previous and redundant IKE SA survive an adoption, for bounded
// Delete/retransmission handling. Their CHILDs have moved to the active session.
type ikeOverlap struct {
	session        *ike.Initiator
	until, retryAt time.Time
	pending        [][]byte
	attempts       int
}

func (t *gatewayTunnel) ikeSession(packet []byte) (*ike.Initiator, *ikeOverlap, error) {
	h, _, err := ike.DecodeHeader(packet)
	if err != nil {
		return nil, nil, err
	}
	match := func(session *ike.Initiator) bool {
		a, b := session.SPIs()
		return a == h.InitiatorSPI && b == h.ResponderSPI
	}
	if match(t.session) {
		return t.session, nil, nil
	}
	for _, old := range t.oldIKE {
		if match(old.session) {
			return old.session, old, nil
		}
	}
	return nil, nil, errors.New("tunnel: unknown IKE SPI pair")
}

func (t *gatewayTunnel) switchIKE(previous, next *ike.Initiator, deleteOld bool, redundant *ike.Initiator, deleteRedundant bool, now time.Time) error {
	if next == nil {
		return errors.New("tunnel: missing IKE rekey winner")
	}
	needed := 1
	if redundant != nil {
		needed++
	}
	if len(t.oldIKE)+needed > 2 {
		return errors.New("tunnel: IKE overlap limit reached")
	}
	t.session, t.pending = next, nil
	t.probeAt = now // validate the new keys promptly, without changing ESP counters
	t.ikeRekeyAt, t.ikeExpiresAt = now.Add(30*time.Minute), now.Add(time.Hour)
	for _, candidate := range []struct {
		session *ike.Initiator
		remove  bool
	}{{previous, deleteOld}, {redundant, deleteRedundant}} {
		if candidate.session == nil {
			continue
		}
		old := &ikeOverlap{session: candidate.session, until: now.Add(120 * time.Second)}
		t.oldIKE = append(t.oldIKE, old)
		if candidate.remove {
			if _, err := old.session.IKEDeleteRequest(); err != nil {
				return err
			}
			packets, err := old.session.PendingRequestPackets(1196)
			if err != nil {
				return err
			}
			old.pending, old.retryAt = packets, now
		}
	}
	return nil
}

func (t *gatewayTunnel) tickOldIKE(now time.Time) {
	retained := t.oldIKE[:0]
	for _, old := range t.oldIKE {
		if !now.Before(old.until) {
			continue
		}
		retained = append(retained, old)
		if len(old.pending) == 0 || old.attempts >= 5 || now.Before(old.retryAt) {
			continue
		}
		for _, packet := range old.pending {
			wire, err := ike.EncapsulateIKE(packet)
			if err != nil {
				break
			}
			if err := t.socket.WriteTunnel(t.generation, wire, t.peer); err != nil {
				break
			}
		}
		old.retryAt = now.Add(time.Second << old.attempts)
		old.attempts++
	}
	clear(t.oldIKE[len(retained):])
	t.oldIKE = retained
}

func (t *gatewayTunnel) handleOldIKE(old *ikeOverlap, message *ike.ExchangeMessage, now time.Time) error {
	result, err := old.session.HandleExchange(message, nil)
	if err != nil {
		return err
	}
	if message.Header().Flags&ike.FlagResponse != 0 {
		old.pending = nil
	}
	if result.Deleted != nil && result.Deleted.IKE {
		old.pending = nil
	}
	if result.Reply != nil {
		return t.sendSessionReply(old.session, result.Reply)
	}
	return nil
}
