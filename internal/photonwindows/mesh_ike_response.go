package photonwindows

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

const meshIKEPendingResponses = 16

type meshIKEResponse struct {
	peer        *meshPeer
	packet      ikeDatagram
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
func (m *meshRuntime) enqueueIKEResponse(p *meshPeer, packet ikeDatagram, plan GatewayPlan, now time.Time) {
	t := p.tunnel
	t.observeEvent("packet_received", now, nil)
	if err := t.validateIKEIngress(packet.tunnelDatagram, plan); err != nil {
		m.rejectIKE(p, packet, now, err)
		return
	}
	if p.responding != nil || len(p.ikeInbox) != 0 {
		m.queuePendingIKE(p, packet, now, "peer_busy")
	} else if !m.submitIKEResponse(p, packet, plan, now) {
		m.queuePendingIKE(p, packet, now, "worker_queue_full")
	}
}

func (m *meshRuntime) queuePendingIKE(p *meshPeer, packet ikeDatagram, now time.Time, reason string) {
	stage := "inbox_queued"
	depth := len(p.ikeInbox)
	if depth < meshIKEPendingResponses {
		p.ikeInbox = append(p.ikeInbox, packet)
	} else {
		stage = "inbox_full"
	}
	if packet.trace != nil {
		m.ikeTrace.ingress(now, stage, packet, slog.String("reason", reason), slog.Int("depth_before", depth))
	}
}

func (m *meshRuntime) submitIKEResponse(p *meshPeer, packet ikeDatagram, plan GatewayPlan, now time.Time) bool {
	t := p.tunnel
	request := &meshIKEResponse{peer: p, packet: packet, phase: t.phase, at: now}
	if t.phase == 3 {
		input, err := t.establishedExchangeInput(packet.packet)
		if err != nil {
			m.rejectIKE(p, packet, now, err)
			return true
		}
		request.established = input
	} else {
		request.input = t.ikeHandshakeInput(plan)
	}
	var queuedAt time.Time
	depth := len(m.ikeResponses)
	if packet.trace != nil {
		queuedAt = time.Now()
	}
	select {
	case m.ikeResponses <- request:
		if !queuedAt.IsZero() {
			m.ikeTrace.worker(queuedAt, "worker_queued", request, slog.Int("depth_before", depth))
		}
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
		packet: ikeDatagram{tunnelDatagram: tunnelDatagram{generation: t.generation, peer: t.peer}}}
	select {
	case m.ikeResponses <- request:
		p.responding, t.ikeLeased = request, true
		m.ikeTrace.worker(now, "worker_queued", request)
	default:
		m.ikeTrace.worker(now, "worker_queue_full", request)
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
			if m.ikeTrace != nil {
				m.ikeTrace.worker(time.Now(), "worker_started", request)
			}
			if request.timer.kind != 0 {
				result.packets, result.err = prepareIKETimer(request.timer)
			} else if request.phase == 3 {
				result.established = prepareEstablishedExchange(request.established, request.packet.packet, request.at)
			} else {
				result.action, result.err = prepareIKEHandshakeResponse(request.phase, request.packet.packet, request.at, request.input)
			}
			if m.ikeTrace != nil {
				m.ikeTrace.worker(time.Now(), "worker_finished", request,
					slog.Any("error", errors.Join(result.err, result.established.err)))
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
		if m.ikeTrace != nil {
			m.ikeTrace.worker(time.Now(), "result_discarded", request, slog.String("reason", "lease retired"))
		}
		clear(request.input.private)
		return nil
	}
	now := time.Now()
	plan, pending := m.projectedPlan(p, now)
	if pending {
		p.heldResponse = &result
		m.ikeTrace.worker(now, "result_waiting_policy", request)
		return nil
	}
	p.responding, p.heldResponse = nil, nil
	expired := t.phase == 3 && (!now.Before(t.ikeExpiresAt) || !now.Before(t.expiresAt))
	if err := t.validateIKEIngress(request.packet.tunnelDatagram, plan); err != nil || t.phase != request.phase || expired {
		clear(request.input.private)
		m.ikeTrace.worker(now, "result_discarded", request, slog.Any("error", err),
			slog.Bool("expired", expired), slog.Int("current_phase", int(t.phase)))
		m.stopPeer(p, "IKE response authorization or generation changed")
		return nil
	}
	t.ikeLeased = false
	var err error
	hadPending := len(t.pending) != 0
	if request.timer.kind != 0 {
		err = result.err
		if errors.Is(err, errMOBIKEPathUnavailable) {
			m.ikeTrace.worker(now, "timer_waiting_path", request, slog.Any("error", err))
			t.waitForMOBIKEPath(now)
			m.dispatchPendingIKE(p, now)
			return nil
		}
		if err == nil {
			err = t.applyIKETimer(request.timer, result.packets, now)
		}
		if err != nil {
			m.ikeTrace.worker(time.Now(), "timer_failed", request, slog.Any("error", err))
			m.stopPeer(p, err.Error())
			return nil
		}
	} else if request.phase == 3 {
		err = t.applyEstablishedExchange(request.established, result.established, plan, now)
	} else {
		t.session, t.private = request.input.session, request.input.private
		err = t.applyIKEHandshakeResponse(result.action, plan, now, result.err)
	}
	if m.ikeTrace != nil {
		m.ikeTrace.worker(time.Now(), "owner_applied", request, slog.Any("error", err), slog.Int("phase", int(t.phase)),
			slog.Bool("pending_cleared", hadPending && len(t.pending) == 0))
	}
	if err != nil {
		m.rejectIKE(p, request.packet, now, err)
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
	if err := t.validateIKEIngress(packet.tunnelDatagram, plan); err != nil {
		m.rejectIKE(p, packet, now, err)
	} else if !m.submitIKEResponse(p, packet, plan, now) {
		return
	}
	p.ikeInbox[0] = ikeDatagram{}
	p.ikeInbox = p.ikeInbox[1:]
}

func (m *meshRuntime) rejectIKE(p *meshPeer, packet ikeDatagram, now time.Time, err error) {
	p.tunnel.observeEvent("packet_rejected", now, err)
	m.ikeTrace.ingress(now, "owner_rejected", packet, slog.Any("error", err))
	m.logger.Debug("tunnel_packet_rejected", "peer", p.config.Gateway.AllowedZones[0], "error", err)
}
