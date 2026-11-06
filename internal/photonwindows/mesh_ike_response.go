package photonwindows

import (
	"context"
	"errors"
	"time"
)

const meshIKEPendingResponses = 16

type meshIKEResponse struct {
	peer        *meshPeer
	packet      tunnelDatagram
	phase       uint8
	at          time.Time
	input       ikeHandshakeInput
	established establishedExchangeInput
	timer       ikeTimerRequest
}

type meshIKEResponseResult struct {
	request     *meshIKEResponse
	action      ikeHandshakeAction
	established establishedExchangeResult
	packets     [][]byte
	err         error
}

// enqueueIKEResponse leases the IKE session to the worker.
// Only the Mesh owner may queue ingress or apply a completed action.
func (m *meshRuntime) enqueueIKEResponse(p *meshPeer, packet tunnelDatagram, plan GatewayPlan, now time.Time) {
	t := p.tunnel
	t.observeEvent("packet_received", now, nil)
	if err := t.validateIKEIngress(packet, plan); err != nil {
		m.rejectIKE(p, now, err)
		return
	}
	if p.responding != nil || len(p.ikeInbox) != 0 || !m.submitIKEResponse(p, packet, plan, now) {
		if len(p.ikeInbox) < meshIKEPendingResponses {
			p.ikeInbox = append(p.ikeInbox, packet)
		}
	}
}

func (m *meshRuntime) submitIKEResponse(p *meshPeer, packet tunnelDatagram, plan GatewayPlan, now time.Time) bool {
	t := p.tunnel
	request := &meshIKEResponse{peer: p, packet: packet, phase: t.phase, at: now}
	if t.phase == 3 {
		input, err := t.establishedExchangeInput(packet.packet)
		if err != nil {
			m.rejectIKE(p, now, err)
			return true
		}
		request.established = input
	} else {
		request.input = t.ikeHandshakeInput(plan)
	}
	select {
	case m.ikeResponses <- request:
		p.responding = request
		if t.phase == 3 {
			t.ikeLeased = true
		} else {
			t.session, t.private = nil, nil
		}
		return true
	default:
		return false
	}
}

func (m *meshRuntime) scheduleIKETimer(p *meshPeer, timer ikeTimerRequest, now time.Time) {
	t := p.tunnel
	request := &meshIKEResponse{peer: p, phase: t.phase, at: now, timer: timer,
		packet: tunnelDatagram{generation: t.generation, peer: t.peer}}
	select {
	case m.ikeResponses <- request:
		p.responding, t.ikeLeased = request, true
	default:
	}
}

func (m *meshRuntime) runIKEResponses(ctx context.Context) {
	defer func() {
		for {
			select {
			case request := <-m.ikeResponses:
				clear(request.input.private)
			default:
				return
			}
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case request := <-m.ikeResponses:
			result := meshIKEResponseResult{request: request}
			if request.timer.kind != 0 {
				result.packets, result.err = prepareIKETimer(request.timer)
			} else if request.phase == 3 {
				result.established = prepareEstablishedExchange(request.established, request.packet.packet, request.at)
			} else {
				result.action, result.err = prepareIKEHandshakeResponse(request.phase, request.packet.packet, request.at, request.input)
			}
			select {
			case m.ikeResponded <- result:
			case <-ctx.Done():
				clear(request.input.private)
				return
			}
		}
	}
}

func (m *meshRuntime) finishIKEResponse(result meshIKEResponseResult) error {
	request := result.request
	p := request.peer
	t := p.tunnel
	if p.responding != request {
		clear(request.input.private)
		return nil
	}
	now := time.Now()
	plan, pending := m.projectedPlan(p, now)
	if pending {
		p.heldResponse = &result
		return nil
	}
	p.responding, p.heldResponse = nil, nil
	expired := t.phase == 3 && (!now.Before(t.ikeExpiresAt) || !now.Before(t.expiresAt))
	if err := t.validateIKEIngress(request.packet, plan); err != nil || t.phase != request.phase || expired {
		clear(request.input.private)
		m.stopPeer(p, "IKE response authorization or generation changed")
		return nil
	}
	t.ikeLeased = false
	var err error
	if request.timer.kind != 0 {
		err = result.err
		if errors.Is(err, errMOBIKEPathUnavailable) {
			t.waitForMOBIKEPath(now)
			m.dispatchPendingIKE(p, now)
			return nil
		}
		if err == nil {
			err = t.applyIKETimer(request.timer, result.packets, now)
		}
		if err != nil {
			m.stopPeer(p, err.Error())
			return nil
		}
	} else if request.phase == 3 {
		err = t.applyEstablishedExchange(request.established, result.established, plan, now)
	} else {
		t.session, t.private = request.input.session, request.input.private
		err = t.applyIKEHandshakeResponse(result.action, plan, now, result.err)
	}
	if err != nil {
		m.rejectIKE(p, now, err)
	} else if t.phase == 3 {
		if len(t.pending) == 0 {
			t.observeProgress()
		}
		if request.phase != 3 {
			p.backoff = m.initial
			m.logger.Info("tunnel_authenticated", "peer", p.config.Gateway.AllowedZones[0], "child_installed", true)
			if err := m.reconcile(); err != nil {
				return err
			}
		}
	}
	m.dispatchPendingIKE(p, now)
	return nil
}

func (m *meshRuntime) dispatchPendingIKE(p *meshPeer, now time.Time) {
	t := p.tunnel
	if p.responding != nil || len(p.ikeInbox) == 0 {
		return
	}
	plan, pending := m.projectedPlan(p, now)
	if pending {
		return
	}
	packet := p.ikeInbox[0]
	if err := t.validateIKEIngress(packet, plan); err != nil {
		m.rejectIKE(p, now, err)
	} else if !m.submitIKEResponse(p, packet, plan, now) {
		return
	}
	p.ikeInbox[0] = tunnelDatagram{}
	p.ikeInbox = p.ikeInbox[1:]
}

func (m *meshRuntime) rejectIKE(p *meshPeer, now time.Time, err error) {
	p.tunnel.observeEvent("packet_rejected", now, err)
	m.logger.Debug("tunnel_packet_rejected", "peer", p.config.Gateway.AllowedZones[0], "error", err)
}
