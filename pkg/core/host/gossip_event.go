package host

import (
	"context"
	"encoding/hex"
	"errors"
	"net"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
)

const DefaultGossipRelayFanout = 8

type gossipDriverSender struct {
	transport *gossip.Transport
	replyAddr *net.UDPAddr
}

func (sender gossipDriverSender) SendGossip(_ context.Context, outbound gossip.OutboundMessage) error {
	if sender.transport == nil {
		return ErrGossipTransportRequired
	}
	if sender.replyAddr != nil {
		return sender.transport.SendTo(outbound.PeerID, sender.replyAddr, outbound.Message)
	}
	return sender.transport.Send(outbound.PeerID, outbound.Message)
}

func (sender gossipDriverSender) datagramBudget() int {
	if sender.transport == nil {
		return gossip.DefaultDatagramBudget
	}
	return sender.transport.MaxMessageBytes()
}

// StartGossipSession creates and queues one common gossip pull session. It is
// also the only announce-hint suppression/defer boundary.
func (driver *GossipDriver) StartGossipSession(peerID, reason string) error {
	if driver == nil {
		return ErrGossipDriverStopped
	}
	if peerID == "" {
		return nil
	}
	now := driver.schedulerForRead().clock.Now()
	if driver.Gossip.HasActiveSession(peerID) {
		driver.Gossip.DeferHint(peerID)
		driver.observeSyncHint(peerID, reason, "session_active", false, now)
		driver.logGossip("debug", "announce_hint_suppressed", peerID, "session", nil, map[string]any{"reason": "session_active"})
		return nil
	}
	summary := driver.GossipCatalogSummary()
	if summary == nil {
		return nil
	}
	session := driver.Gossip.NewSession(peerID)
	if err := driver.PostGossip(&gossip.SyncTimerEvent{PeerID: peerID, LocalSummary: summary}); err != nil {
		driver.Gossip.RemoveSession(peerID)
		driver.logGossip("warn", "event_dropped", peerID, "session", err, map[string]any{"reason": "sync_events_full"})
		return err
	}
	driver.observeSyncHint(peerID, reason, "", true, now)
	driver.observeActivePull(peerID, "hint_queued", session, now)
	driver.logGossip("debug", "hinted_sync_started", peerID, "session", nil, map[string]any{"reason": reason})
	return nil
}

var (
	ErrGossipEventPeerRequired = errors.New("gossip event peer is required")
	ErrGossipSessionNotFound   = errors.New("gossip session not found")
)

// GossipEventResult is the platform-neutral outcome of advancing one session
// event and executing every action it produced.
type GossipEventResult struct {
	PeerID         string
	OldState       gossip.SyncSessionState
	NewState       gossip.SyncSessionState
	Pending        int
	Inflight       int
	Done           bool
	NetworkChanged bool
	ProtocolErr    error
	TerminalErr    error
	FollowupQueued bool
}

// GossipHostEventResult describes the common gossip work performed for one
// GossipDriver event. It does not expose the received packet or logging outcome;
// platform composition only observes session changes needed during migration.
type GossipHostEventResult struct {
	Handled bool
	Session GossipEventResult
}

// HandleGossipHostEvent is the only switch from GossipDriver queue events to the
// gossip inbound planner or session FSM. Packet, timer and object-pull
// completion producers therefore share one consumer on every platform.
func (driver *GossipDriver) HandleGossipHostEvent(ctx context.Context, hostEvent Event, now time.Time, suppressedPeers map[string]bool) (GossipHostEventResult, error) {
	var out GossipHostEventResult
	if driver == nil {
		return out, ErrGossipDriverStopped
	}
	transport := driver.gossipTransportForRead()
	if transport == nil {
		return out, ErrGossipTransportRequired
	}
	if received, ok := hostEvent.(GossipPacketReceived); ok {
		out.Handled = true
		if received.Packet == nil {
			return out, nil
		}
		driver.acceptGossipInboundPath(ctx, received.Packet, now, suppressedPeers, transport)
		sender := gossipDriverSender{transport: transport, replyAddr: received.Packet.Addr}
		err := driver.executeGossipPacketActions(ctx, driver.Gossip.PlanInbound(received.Packet), sender, sender.datagramBudget())
		if err != nil {
			driver.logGossipPacketFailure(received.Packet, err)
		}
		return out, err
	}
	event, ok := driver.GossipSessionEventFor(hostEvent)
	if !ok {
		return out, nil
	}
	out.Handled = true
	result, err := driver.handleGossipSessionEvent(ctx, event, now, gossipDriverSender{transport: transport})
	if err == nil && result.Done {
		driver.finishGossipSession(ctx, &result, now, suppressedPeers)
	}
	out.Session = result
	return out, err
}

func (driver *GossipDriver) acceptGossipInboundPath(ctx context.Context, packet *gossip.Packet, now time.Time, suppressedPeers map[string]bool, transport *gossip.Transport) {
	if driver == nil || packet == nil || packet.Message == nil || packet.Addr == nil {
		return
	}
	peerID := packet.Message.PeerID
	committed, err := driver.recordGossipObservedPath(ctx, peerID, packet.Addr.String(), suppressedPeers, now)
	if err != nil {
		driver.logGossip("warn", "observed_checkpoint_commit_failed", peerID, "persistence", err, nil)
	} else if committed {
		driver.observeObservedSource(peerID, packet.Message.Type, now)
	}
	if err := driver.restoreGossipObservedPath(peerID, suppressedPeers, now, transport); err != nil {
		driver.logGossip("debug", "observed_path_restore_failed", peerID, "discovery", err, nil)
	}
}

// finishGossipSession closes the common session lifecycle at the same boundary
// that advanced its FSM. Platform composition receives only the detached
// terminal result needed for data-plane reconciliation and route cleanup.
func (driver *GossipDriver) finishGossipSession(ctx context.Context, result *GossipEventResult, now time.Time, suppressedPeers map[string]bool) {
	if driver == nil || result == nil || result.PeerID == "" {
		return
	}
	peerID := result.PeerID
	session := driver.Gossip.Session(peerID)
	if session == nil {
		return
	}
	driver.CancelGossipTimers(peerID)
	result.NetworkChanged = session.NetworkChanged()
	result.TerminalErr = session.LastError()
	if session.State == gossip.SyncSessionCompleted && result.NetworkChanged {
		driver.relayGossipUpdate(ctx, peerID, now, suppressedPeers)
	}
	driver.Gossip.RemoveSession(peerID)
	if driver.Gossip.TakePendingHint(peerID) {
		if err := driver.StartGossipSession(peerID, "announce_hint_followup"); err == nil {
			result.FollowupQueued = driver.Gossip.HasActiveSession(peerID)
		}
	}
}

func (driver *GossipDriver) relayGossipUpdate(ctx context.Context, sourcePeerID string, now time.Time, suppressedPeers map[string]bool) {
	input := driver.GossipDiscoveryInput(suppressedPeers)
	summary := driver.GossipCatalogSummary()
	if summary == nil {
		return
	}
	root := hex.EncodeToString(summary.CatalogRoot)
	relayed := 0
	for _, peerID := range GossipOutboundPeers(input, now) {
		if peerID == sourcePeerID {
			continue
		}
		if relayed >= DefaultGossipRelayFanout {
			driver.observeRelaySuppression(peerID, "relay_fanout_limited", now)
			continue
		}
		allowed, reason := ShouldRelayGossipUpdate(input.Peers[peerID], peerID, sourcePeerID, root, now)
		if !allowed {
			driver.observeRelaySuppression(peerID, reason, now)
			continue
		}
		relayed++
		if driver.Gossip.HasActiveSession(peerID) {
			continue
		}
		driver.Gossip.NewSession(peerID)
		if err := driver.PostGossip(&gossip.SyncTimerEvent{PeerID: peerID, LocalSummary: summary}); err != nil {
			driver.Gossip.RemoveSession(peerID)
			driver.logGossip("warn", "relay_event_dropped", peerID, "session", err, map[string]any{"source_peer": sourcePeerID})
			continue
		}
		committed, err := driver.RecordGossipRelay(ctx, peerID, root, now)
		if err != nil {
			driver.logGossip("warn", "relay_checkpoint_commit_failed", peerID, "persistence", err, nil)
			continue
		}
		if committed {
			driver.observeRelaySuccess(peerID, sourcePeerID, now)
		}
	}
}

func (driver *GossipDriver) logGossipPacketFailure(packet *gossip.Packet, err error) {
	peerID := ""
	fields := map[string]any{"reason": gossip.RejectReason(err)}
	if packet != nil && packet.Message != nil {
		peerID = packet.Message.PeerID
		fields["type"] = packet.Message.Type
	}
	driver.logGossip("warn", "packet_failed", peerID, "packet", err, fields)
}

// handleGossipSessionEvent is the internal bridge from Engine/FSM advancement
// to ordered GossipDriver effects. Platform code may enrich an event before
// calling it and observe the detached result afterwards, but cannot implement
// a second Engine-to-action loop.
func (driver *GossipDriver) handleGossipSessionEvent(ctx context.Context, event gossip.SyncEvent, now time.Time, controller GossipSender) (GossipEventResult, error) {
	var out GossipEventResult
	if driver == nil {
		return out, ErrGossipDriverStopped
	}
	if controller == nil {
		return out, errGossipSenderRequired
	}
	peerID := gossip.SyncEventPeerID(event)
	if peerID == "" {
		driver.logGossip("debug", "event_dropped", "", "session", ErrGossipEventPeerRequired, nil)
		return out, ErrGossipEventPeerRequired
	}
	session := driver.Gossip.Session(peerID)
	if session == nil {
		driver.logGossip("debug", "event_dropped", peerID, "session", ErrGossipSessionNotFound, nil)
		return out, ErrGossipSessionNotFound
	}
	if _, ok := event.(*gossip.RoundTimeoutEvent); ok {
		driver.dropGossipPeerChunks(peerID)
	}
	if typed, ok := event.(*gossip.ChunkRepairTimeoutEvent); ok {
		nack := driver.gossipChunks.BuildRepairNACK(peerID, typed.TransferID)
		out = GossipEventResult{PeerID: peerID, OldState: session.State, NewState: session.State, Pending: session.PendingCount(), Inflight: session.InflightCount(), Done: session.Done()}
		if nack == nil {
			return out, nil
		}
		err := controller.SendGossip(ctx, gossip.OutboundMessage{PeerID: peerID, Message: &gossip.Message{Type: gossip.MessageObjectChunkNACK, ObjectChunkNACK: nack}})
		if err != nil {
			driver.reportGossipIssue(GossipExecutionIssue{Phase: GossipPhaseSend, PeerID: peerID, Err: err})
			return out, nil
		}
		driver.observeChunkRepair(peerID, false, 0, now)
		return out, nil
	}
	switch typed := event.(type) {
	case *gossip.PongReceivedEvent:
		if typed.Pong != nil && typed.Pong.Summary != nil {
			driver.observeCatalogSummary(peerID, typed.Pong.Summary, now)
		}
	case *gossip.CatalogSummaryReceivedEvent:
		driver.observeCatalogSummary(peerID, typed.Summary, now)
	case *gossip.CatalogPageReceivedEvent:
		typed.LocalEntries, typed.Page = FilterGossipCatalogPage(driver.GossipDiscoveryInput(nil), peerID, typed.Page, now)
		driver.observeCatalogPage(peerID, typed.Page, now)
	}
	engineResult := driver.Gossip.HandleEvent(event, now)
	execution := driver.ExecuteGossipActions(ctx, session, engineResult.Actions, controller)
	session.AccumulateNetworkChanged(execution.NetworkChanged)
	out = GossipEventResult{
		PeerID:         peerID,
		OldState:       engineResult.OldState,
		NewState:       session.State,
		Pending:        session.PendingCount(),
		Inflight:       session.InflightCount(),
		Done:           session.Done(),
		NetworkChanged: execution.NetworkChanged,
		ProtocolErr:    engineResult.Err,
	}
	driver.observeActivePull(peerID, gossip.SyncEventName(event), session, now)
	if out.ProtocolErr != nil {
		driver.logGossip("warn", "session_event_error", peerID, "session", out.ProtocolErr, nil)
	}
	if out.NewState != out.OldState {
		driver.logGossip("debug", "session_state_changed", peerID, "session", nil, map[string]any{
			"event": gossip.SyncEventName(event), "old_state": out.OldState, "new_state": out.NewState,
			"pending": out.Pending, "inflight": out.Inflight,
		})
	}
	return out, nil
}
