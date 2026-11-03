package photonwindows

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"slices"
	"time"

	"github.com/HiggsNet/photon/internal/photonclient/esp"
	"github.com/HiggsNet/photon/internal/photonclient/ike"
)

func freshChildSPI() (uint32, error) {
	var b [4]byte
	for binary.BigEndian.Uint32(b[:]) < 256 {
		if _, err := rand.Read(b[:]); err != nil {
			return 0, err
		}
	}
	return binary.BigEndian.Uint32(b[:]), nil
}

func (t *gatewayTunnel) sendReply(reply []byte) error {
	return t.sendSessionReply(t.session, reply)
}

func (t *gatewayTunnel) sendSessionReply(session *ike.Initiator, reply []byte) error {
	packets, err := session.ReplyPackets(reply, 1196)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(time.Second)
	for _, packet := range packets {
		if time.Now().After(deadline) {
			return context.DeadlineExceeded
		}
		wire, err := ike.EncapsulateIKE(packet)
		if err != nil {
			return err
		}
		if err := t.writeIKE(wire); err != nil {
			return err
		}
	}
	return nil
}

type childSelectorPair struct {
	local, remote []ike.TrafficSelector
}

// The request owns selector snapshots. The worker uses only the selected IKE
// session, whose methods must remain exclusively leased until it returns.
type establishedExchangeInput struct {
	session *ike.Initiator
	old     *ikeOverlap
	active  childSelectorPair
	bySPI   map[uint32]childSelectorPair
}

type establishedExchangeResult struct {
	header   ike.Header
	exchange *ike.ExchangeResult
	refusal  *ike.ChildExchangeError
	err      error
}

func (t *gatewayTunnel) establishedExchangeInput(packet []byte) (establishedExchangeInput, error) {
	session, old, err := t.ikeSession(packet)
	if err != nil {
		return establishedExchangeInput{}, err
	}
	input := establishedExchangeInput{session: session, old: old}
	if old == nil {
		input.active = childSelectorPair{slices.Clone(t.child.LocalSelectors), slices.Clone(t.child.RemoteSelectors)}
		input.bySPI = make(map[uint32]childSelectorPair, len(t.data.sas))
		for spi, sa := range t.data.sas {
			input.bySPI[spi] = childSelectorPair{slices.Clone(sa.local), slices.Clone(sa.remote)}
		}
	}
	return input, nil
}

func prepareEstablishedExchange(input establishedExchangeInput, packet []byte, now time.Time) establishedExchangeResult {
	session := input.session
	message, err := session.DecodeExchange(packet, now)
	if err != nil || message == nil {
		return establishedExchangeResult{err: err}
	}
	header := message.Header()
	var config *ike.ChildExchangeConfig
	if input.old == nil && header.ExchangeType == ike.ExchangeCreateChild && header.Flags&ike.FlagResponse == 0 && !message.IsIKERekey() {
		offer, err := session.InspectChildExchange(message)
		if err != nil {
			return establishedExchangeResult{err: err}
		}
		spi, err := freshChildSPI()
		if err != nil {
			return establishedExchangeResult{err: err}
		}
		// A peer may narrow selectors on rekey but cannot widen them.
		selectors, exists := input.bySPI[offer.RekeySPI]
		if !exists {
			selectors = input.active
		}
		if err := ike.ValidateTrafficSelectorNarrowing(offer.LocalSelectors, selectors.local); err != nil {
			return establishedExchangeResult{err: err}
		}
		if err := ike.ValidateTrafficSelectorNarrowing(offer.RemoteSelectors, selectors.remote); err != nil {
			return establishedExchangeResult{err: err}
		}
		config = &ike.ChildExchangeConfig{Child: ike.ChildConfig{InitiatorSPI: spi, LocalSelectors: offer.LocalSelectors, RemoteSelectors: offer.RemoteSelectors}, RekeySPI: offer.RekeySPI, DHGroup: offer.DHGroup}
	}
	result, err := session.HandleExchange(message, config)
	prepared := establishedExchangeResult{header: header, exchange: result, err: err}
	if input.old == nil {
		errors.As(err, &prepared.refusal)
	}
	return prepared
}

func (t *gatewayTunnel) handleEstablished(packet []byte, plan GatewayPlan, now time.Time) error {
	input, err := t.establishedExchangeInput(packet)
	if err != nil {
		return err
	}
	return t.applyEstablishedExchange(input, prepareEstablishedExchange(input, packet, now), plan, now)
}

func (t *gatewayTunnel) applyEstablishedExchange(input establishedExchangeInput, prepared establishedExchangeResult, plan GatewayPlan, now time.Time) error {
	result, header, session := prepared.exchange, prepared.header, input.session
	if old := input.old; old != nil {
		if prepared.err != nil || result == nil {
			return prepared.err
		}
		if header.Flags&ike.FlagResponse != 0 || result.Deleted != nil && result.Deleted.IKE {
			old.pending = nil
		}
		if result.Reply != nil {
			return t.sendSessionReply(session, result.Reply)
		}
		return nil
	}

	if prepared.err != nil {
		if refusal := prepared.refusal; refusal != nil {
			t.pending = nil
			if refusal.IKERekey {
				t.ikeRekeyAt = now.Add(30 * time.Second)
				return nil
			}
			if refusal.RemovedSPI != 0 {
				t.data.retire(refusal.RemovedSPI)
				if t.deleteSPI == refusal.RemovedSPI {
					t.deleteSPI = 0
				}
			}
			if refusal.RekeySPI != 0 {
				_ = t.resolveChild(refusal.RekeySPI, now)
			}
			if refusal.Notification == 14 && t.rekeyGroup == ike.GroupP256 {
				t.rekeyGroup, t.rekeyAt = 0, now // no-PFS is part of the frozen v1 suite
			} else {
				t.rekeyAt = now.Add(30 * time.Second)
			}
			return nil
		}
		return prepared.err
	}
	if result == nil {
		return nil // Waiting for additional authenticated fragments.
	}
	if header.Flags&ike.FlagResponse != 0 {
		t.pending = nil
	}
	if result.Child != nil {
		if header.Flags&ike.FlagResponse == 0 {
			local, remote := t.child.LocalSelectors, t.child.RemoteSelectors
			if previous := t.data.sas[result.Child.RekeySPI]; previous != nil {
				local, remote = previous.local, previous.remote
			}
			if err := ike.ValidateTrafficSelectorNarrowing(result.Child.Child.LocalSelectors, local); err != nil {
				t.failed = err
				return err
			}
			if err := ike.ValidateTrafficSelectorNarrowing(result.Child.Child.RemoteSelectors, remote); err != nil {
				t.failed = err
				return err
			}
		}
		if err := t.installRekey(result.Child, plan, now); err != nil {
			t.failed = err
			return err
		}
	}
	if result.Deleted != nil {
		for _, spi := range result.Deleted.Removed {
			t.data.retire(spi)
			if t.deleteSPI == spi {
				t.deleteSPI = 0
			}
			if !result.Deleted.IKE {
				_ = t.resolveChild(spi, now)
			}
		}
		if result.Deleted.Successor != nil {
			if err := t.switchIKE(session, result.Deleted.Successor, false, nil, false, now); err != nil {
				t.failed = err
				return err
			}
		} else if result.Deleted.IKE {
			t.failed = errors.New("tunnel: authenticated IKE Delete")
		}
	}
	if result.IKE != nil {
		decision, err := session.ResolveIKERekey()
		if err != nil {
			t.failed = err
			return err
		}
		if !decision.Pending {
			decision, err = session.AdoptIKERekey()
			if err != nil {
				t.failed = err
				return err
			}
			if err := t.switchIKE(session, decision.Surviving, decision.DeleteOld, decision.Redundant, decision.DeleteRedundant, now); err != nil {
				t.failed = err
				return err
			}
		}
	}
	if result.Liveness && header.Flags&ike.FlagResponse != 0 {
		t.probeAt = now.Add(20 * time.Second)
	}
	if result.Reply != nil {
		return t.sendSessionReply(session, result.Reply)
	}
	return nil
}

func (t *gatewayTunnel) installRekey(result *ike.ChildExchangeResult, plan GatewayPlan, now time.Time) error {
	firstOverlap := len(t.data.sas) == 1
	if err := t.data.install(t.generation, plan, t.peer, result.Child); err != nil {
		return err
	}
	if firstOverlap {
		t.childOverlapUntil = now.Add(120 * time.Second)
		if t.expiresAt.Before(t.childOverlapUntil) {
			t.childOverlapUntil = t.expiresAt
		}
	}
	if result.RekeySPI == 0 {
		// A second independent CHILD is not a second gateway; its selectors and
		// data still face the same current B4 gate. Prefer the existing sender.
		return nil
	}
	return t.resolveChild(result.RekeySPI, now)
}

func (t *gatewayTunnel) resolveChild(oldSPI uint32, now time.Time) error {
	decision, err := t.session.ResolveChildRekey(oldSPI)
	if err != nil {
		return err
	}
	if decision.SurvivingSPI == 0 {
		return nil
	}
	if decision.LocalInitiated || t.data.sas[oldSPI] == nil {
		if err := t.activateChild(decision.SurvivingSPI, now); err != nil {
			return err
		}
	} else {
		t.pendingChildSPI = decision.SurvivingSPI
	}
	if !decision.Pending && decision.DeleteSPI != 0 {
		t.deleteSPI, t.deleteAt = decision.DeleteSPI, now.Add(5*time.Second)
	}
	return nil
}

func (t *gatewayTunnel) activateChild(spi uint32, now time.Time) error {
	sa := t.data.sas[spi]
	if sa == nil || sa.child.InitiatorSPI != spi {
		return errors.New("tunnel: rekey winner not present")
	}
	if err := t.data.activate(spi); err != nil {
		return err
	}
	// Cleanup can resolve the same survivor again. Its already-running key
	// lifetimes belong to first activation, never to a later Delete response.
	if t.child.InitiatorSPI == spi {
		t.pendingChildSPI = 0
		return nil
	}
	t.child = sa.child
	t.pendingChildSPI = 0
	t.expiresAt, t.rekeyAt = now.Add(10*time.Minute), now.Add(5*time.Minute)
	return nil
}

func (t *gatewayTunnel) observeData(result dataplaneCompletion, plan GatewayPlan, now time.Time) {
	if t.phase != 3 || t.failed != nil || !now.Before(t.ikeExpiresAt) || !now.Before(t.expiresAt) {
		return
	}
	job := result.job
	if job.sa != nil && job.outbound && job.sa == t.data.active && errors.Is(result.err, esp.ErrSequenceExhausted) && job.ctx.Err() == nil && t.data.current(job.generation, job.sa, plan) {
		t.rekeyAt = now // exhausted Sender remains fail-closed until fresh CHILD
		return
	}
	if t.pendingChildSPI == 0 || job.sa == nil || job.sa.spi != t.pendingChildSPI || job.outbound || result.err != nil || job.ctx.Err() != nil {
		return
	}
	if t.data.current(job.generation, job.sa, plan) && dataplaneSelectors(job.sa, result.packet, false) {
		if err := t.activateChild(t.pendingChildSPI, now); err != nil {
			t.failed = err
		}
	}
}
