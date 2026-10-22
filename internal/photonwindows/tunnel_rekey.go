package photonwindows

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
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
		if err := t.socket.WriteTunnel(t.generation, wire, t.peer); err != nil {
			return err
		}
	}
	return nil
}

func (t *gatewayTunnel) handleEstablished(packet []byte, plan GatewayPlan, now time.Time) error {
	session, old, err := t.ikeSession(packet)
	if err != nil {
		return err
	}
	message, err := session.DecodeExchange(packet, now)
	if err != nil || message == nil {
		return err
	}
	header := message.Header()
	var config *ike.ChildExchangeConfig
	if old != nil {
		return t.handleOldIKE(old, message, now)
	}
	if header.ExchangeType == ike.ExchangeCreateChild && header.Flags&ike.FlagResponse == 0 && !message.IsIKERekey() {
		offer, err := session.InspectChildExchange(message)
		if err != nil {
			return err
		}
		spi, err := freshChildSPI()
		if err != nil {
			return err
		}
		// A peer cannot widen an existing CHILD by asking to rekey it. The
		// current gateway pin was revalidated before this authenticated offer.
		local, remote := t.child.LocalSelectors, t.child.RemoteSelectors
		if old := t.data.sas[offer.RekeySPI]; old != nil {
			local, remote = old.local, old.remote
		}
		if err := ike.ValidateTrafficSelectorNarrowing(offer.LocalSelectors, local); err != nil {
			return err
		}
		if err := ike.ValidateTrafficSelectorNarrowing(offer.RemoteSelectors, remote); err != nil {
			return err
		}
		config = &ike.ChildExchangeConfig{Child: ike.ChildConfig{InitiatorSPI: spi, LocalSelectors: offer.LocalSelectors, RemoteSelectors: offer.RemoteSelectors}, RekeySPI: offer.RekeySPI, DHGroup: offer.DHGroup}
	}
	result, err := session.HandleExchange(message, config)
	if err != nil {
		var refusal *ike.ChildExchangeError
		if errors.As(err, &refusal) {
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
		return err
	}
	if header.Flags&ike.FlagResponse != 0 {
		t.pending = nil
	}
	if result.Child != nil {
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
	if err := t.data.activate(spi); err != nil {
		return err
	}
	child, ok := t.session.Child(spi)
	if !ok {
		return errors.New("tunnel: rekey winner not present")
	}
	clear(child.Keys.InitiatorToResponder)
	clear(child.Keys.ResponderToInitiator)
	child.Keys = ike.ChildKeys{}
	t.child = child
	t.pendingChildSPI = 0
	t.expiresAt, t.rekeyAt = now.Add(10*time.Minute), now.Add(5*time.Minute)
	return nil
}

func (t *gatewayTunnel) observeData(result dataplaneCompletion, plan GatewayPlan, now time.Time) {
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
