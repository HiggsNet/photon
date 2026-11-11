package host

import (
	"context"
	"encoding/hex"
	"errors"
	"log/slog"
	"maps"
	"net"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
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

// SyncGossipPeers starts eligible periodic pulls on the event-loop goroutine.
// The first event executes directly: a full queue must not strand an idle session.
// The returned flag reports completed sessions requiring platform reconciliation.
func (driver *GossipDriver) SyncGossipPeers(ctx context.Context, now time.Time, force bool) (bool, error) {
	defer driver.LogSlowOperation("gossip", "sync_peers", time.Now(), driver.PendingEventCount())
	if !driver.gossipDiscoveryAvailable() {
		return false, ErrGossipDriverStopped
	}
	transport := driver.gossipTransportForRead()
	if transport == nil {
		return false, ErrGossipTransportRequired
	}
	input := driver.gossipDiscoveryInput("", true)
	revoked := gossipDiscoveryRevocations(input, now)
	if !maps.Equal(driver.revokedPeers, revoked) {
		ApplyGossipDiscoveryPlan(transport, PlanGossipDiscovery(input, now))
		for path := range revoked {
			if !driver.revokedPeers[path] {
				driver.dropRevokedGossipPeer(path.String())
			}
		}
		driver.revokedPeers = revoked
	}
	summary := driver.GossipCatalogSummary()
	if summary == nil {
		summary = corestate.CatalogSummaryForDigests(nil)
	}
	changed := false
	var errs []error
	// Signed-state commits normally remove these rows. A restored row or a
	// revocation that became active since the commit can still need pruning.
	for peerID := range input.Peers {
		if revoked[zone.ZonePath(peerID)] {
			if err := driver.gossipState.PruneRevokedPeerCheckpoints(ctx, now); err != nil {
				errs = append(errs, err)
			}
			break
		}
	}
	for _, peerID := range GossipOutboundPeers(input, now) {
		if !force && GossipBackoffRemaining(input.Peers[peerID], now) > 0 {
			continue
		}
		if driver.Gossip.HasActiveSession(peerID) {
			continue
		}
		if driver.gossipObjectPullDraining(peerID) {
			driver.Gossip.DeferHint(peerID)
			continue
		}
		driver.Gossip.NewSession(peerID)
		eventChanged, err := driver.HandleGossipHostEvent(ctx, GossipEvent{Value: &gossip.SyncTimerEvent{PeerID: peerID, LocalSummary: summary}}, now)
		if err != nil {
			driver.removeGossipSession(peerID)
			errs = append(errs, err)
		}
		changed = changed || eventChanged
	}
	return changed, errors.Join(errs...)
}

// StartGossipSession queues a locally triggered session, deferring the hint
// while a session or its canceled object pulls are still active.
func (driver *GossipDriver) StartGossipSession(peerID, reason string) error {
	if driver == nil {
		return ErrGossipDriverStopped
	}
	now := driver.schedulerForRead().clock.Now()
	if peerID == "" || driver.gossipPeerRevoked(peerID, now) {
		return nil
	}
	if driver.Gossip.HasActiveSession(peerID) {
		driver.Gossip.DeferHint(peerID)
		driver.observeSyncHint(peerID, reason, "session_active", false, now)
		driver.logGossip(slog.LevelDebug, "sync_hint_suppressed", peerID, "session", nil, map[string]any{"reason": "session_active"})
		return nil
	}
	if driver.gossipObjectPullDraining(peerID) {
		driver.Gossip.DeferHint(peerID)
		driver.observeSyncHint(peerID, reason, "pulls_draining", false, now)
		return nil
	}
	summary := driver.GossipCatalogSummary()
	if summary == nil {
		return nil
	}
	session := driver.Gossip.NewSession(peerID)
	if err := driver.PostGossip(&gossip.SyncTimerEvent{PeerID: peerID, LocalSummary: summary}); err != nil {
		driver.Gossip.RemoveSession(peerID)
		driver.logGossip(slog.LevelWarn, "event_dropped", peerID, "session", err, map[string]any{"reason": "sync_events_full"})
		return err
	}
	driver.observeSyncHint(peerID, reason, "", true, now)
	driver.observeActivePull(peerID, "hint_queued", session, now)
	driver.logGossip(slog.LevelDebug, "hinted_sync_started", peerID, "session", nil, map[string]any{"reason": reason})
	return nil
}

var (
	ErrGossipEventPeerRequired = errors.New("gossip event peer is required")
	errGossipSessionNotFound   = errors.New("gossip session not found")
)

// HandleGossipHostEvent is the only switch from GossipDriver queue events to the
// inbound message handler or session FSM. It reports whether any step committed
// verified state. Object-pull I/O remains on the bounded worker group.
func (driver *GossipDriver) HandleGossipHostEvent(ctx context.Context, hostEvent Event, now time.Time) (bool, error) {
	defer driver.LogSlowOperation("gossip", "host_event", time.Now(), driver.PendingEventCount())
	changed := false
	if driver == nil {
		return false, ErrGossipDriverStopped
	}
	if ctx == nil {
		ctx = context.Background()
	}
	transport := driver.gossipTransportForRead()
	if transport == nil {
		return false, ErrGossipTransportRequired
	}
	defer driver.wakeGossipInternal()
	var errs []error
	steps := 0
	if _, continuation := hostEvent.(gossipContinue); !continuation {
		stepChanged, events, err := driver.handleGossipHostStep(ctx, hostEvent, now, transport)
		changed = stepChanged
		driver.appendGossipInternal(events)
		if err != nil {
			errs = append(errs, err)
		}
		steps++
	}
	for ; steps < maxGossipEventBatch && driver.internalPending.Load() > 0 && ctx.Err() == nil; steps++ {
		event := driver.takeGossipInternal()
		if event == nil {
			break
		}
		stepChanged, events, err := driver.handleGossipHostStep(ctx, GossipEvent{Value: event}, now, transport)
		changed = changed || stepChanged
		driver.appendGossipInternal(events)
		if err != nil {
			errs = append(errs, err)
		}
	}
	return changed, errors.Join(errs...)
}

func (driver *GossipDriver) handleGossipHostStep(ctx context.Context, hostEvent Event, now time.Time, transport *gossip.Transport) (bool, []gossip.SyncEvent, error) {
	if timer, ok := hostEvent.(TimerFired); ok && timer.ID.Namespace == GossipChunkSendNamespace {
		if !driver.schedulerForRead().Accept(timer) {
			return false, nil, nil
		}
		if err := driver.flushGossipChunkSend(ctx, timer.ID); err != nil {
			driver.reportGossipIssue(GossipExecutionIssue{Phase: GossipPhaseSend, PeerID: timer.ID.Owner, Err: err})
		}
		return false, nil, nil
	}
	if received, ok := hostEvent.(GossipPacketReceived); ok {
		if received.Packet == nil || received.Packet.Message == nil {
			return false, nil, nil
		}
		peerID := received.Packet.Message.PeerID
		if driver.gossipPeerRevoked(peerID, now) {
			return false, nil, nil
		}
		driver.acceptGossipInboundPath(ctx, received.Packet, now, transport)
		sender := gossipDriverSender{transport: transport, replyAddr: received.Packet.Addr}
		events, err := driver.handleGossipMessage(ctx, received.Packet.Message, sender, transport.MaxMessageBytes())
		if err != nil {
			driver.logGossipPacketFailure(received.Packet, err)
		}
		return false, events, nil
	}
	event, ok := driver.GossipSessionEventFor(hostEvent)
	if !ok {
		return false, nil, nil
	}
	if completion, ok := hostEvent.(GossipEvent); ok && completion.pullRound != nil && !driver.completeGossipObjectPull(completion.pullRound) {
		return false, nil, nil
	}
	if peerID := gossip.SyncEventPeerID(event); driver.gossipPeerRevoked(peerID, now) {
		driver.dropRevokedGossipPeer(peerID)
		return false, nil, nil
	}
	if tick, ok := event.(*gossip.SyncTimerEvent); ok && transport != nil && transport.HasRememberedPeerAddr(tick.PeerID) {
		input := driver.gossipDiscoveryInput(tick.PeerID, false)
		input.observedVerifier = &driver.observedPathVerifier
		if !discoveryPeerVerified(input, tick.PeerID, now) {
			transport.SetRememberedPeerAddr(tick.PeerID, nil)
		}
	}
	return driver.handleGossipSessionEvent(ctx, event, now, gossipDriverSender{transport: transport})
}

func (driver *GossipDriver) acceptGossipInboundPath(ctx context.Context, packet *gossip.Packet, now time.Time, transport *gossip.Transport) {
	if driver == nil || packet == nil || packet.Message == nil || packet.Addr == nil {
		return
	}
	peerID := packet.Message.PeerID
	confirmed := false
	if pong := packet.Message.Pong; packet.Message.Type == gossip.MessagePong &&
		pong != nil && pong.Summary != nil && len(pong.Summary.CatalogRoot) != 0 && transport != nil {
		session := driver.Gossip.Session(peerID)
		if session != nil && session.State == gossip.SyncSessionSummarySent {
			addr := transport.LastPingAddr(peerID)
			confirmed = addr != nil && addr.String() == packet.Addr.String()
		}
	}
	verification, recorded, err := driver.recordGossipObservedPath(ctx, peerID, packet.Addr.String(), confirmed, now)
	if err != nil {
		driver.logGossip(slog.LevelWarn, "observed_path_update_failed", peerID, "discovery", err, nil)
	} else if recorded {
		driver.observeObservedSource(peerID, packet.Message.Type, now)
	}
	if err := driver.publishGossipObservedPath(peerID, now, transport, verification); err != nil {
		driver.logGossip(slog.LevelDebug, "observed_path_publish_failed", peerID, "discovery", err, nil)
	}
}

func (driver *GossipDriver) finishGossipSession(session *gossip.SyncSession) {
	peerID := session.PeerID
	driver.CancelGossipTimers(peerID)
	driver.dropGossipPeerChunks(peerID)
	driver.removeGossipSession(peerID)
	driver.startDeferredGossipSession(peerID)
}

func (driver *GossipDriver) removeGossipSession(peerID string) {
	driver.Gossip.RemoveSession(peerID)
	if round := driver.objectPullRounds[peerID]; round != nil && round.stop() {
		delete(driver.objectPullRounds, peerID)
	}
}

func (driver *GossipDriver) dropRevokedGossipPeer(peerID string) {
	driver.CancelGossipTimers(peerID)
	driver.dropGossipPeerChunks(peerID)
	driver.removeGossipSession(peerID)
	driver.Gossip.TakePendingHint(peerID)
	driver.Observability.Delete(peerID)
}

func (driver *GossipDriver) startDeferredGossipSession(peerID string) {
	if driver.Gossip.HasActiveSession(peerID) || driver.gossipObjectPullDraining(peerID) || !driver.Gossip.TakePendingHint(peerID) {
		return
	}
	_ = driver.StartGossipSession(peerID, "deferred_sync")
}

// RelayGossipUpdate queues a bounded number of summary PINGs after a verified
// change. For local changes sourcePeerID is empty.
func (driver *GossipDriver) RelayGossipUpdate(ctx context.Context, sourcePeerID string, now time.Time) {
	input := driver.gossipDiscoveryInput("", true)
	summary := driver.GossipCatalogSummary()
	if summary == nil {
		return
	}
	root := hex.EncodeToString(summary.CatalogRoot)
	var queuedPeers []string
	for _, peerID := range GossipOutboundPeers(input, now) {
		if peerID == sourcePeerID {
			continue
		}
		if len(queuedPeers) >= DefaultGossipRelayFanout {
			driver.observeRelaySuppression(peerID, "relay_fanout_limited", now)
			continue
		}
		allowed, reason := ShouldRelayGossipUpdate(input.Peers[peerID], peerID, sourcePeerID, root, now)
		if !allowed {
			driver.observeRelaySuppression(peerID, reason, now)
			continue
		}
		if driver.Gossip.HasActiveSession(peerID) {
			continue
		}
		if driver.gossipObjectPullDraining(peerID) {
			driver.Gossip.DeferHint(peerID)
			continue
		}
		driver.Gossip.NewSession(peerID)
		if err := driver.PostGossip(&gossip.SyncTimerEvent{PeerID: peerID, LocalSummary: summary}); err != nil {
			driver.Gossip.RemoveSession(peerID)
			driver.logGossip(slog.LevelWarn, "relay_event_dropped", peerID, "session", err, map[string]any{"source_peer": sourcePeerID})
			continue
		}
		queuedPeers = append(queuedPeers, peerID)
	}
	if len(queuedPeers) == 0 {
		return
	}
	updated, err := driver.recordGossipRelays(ctx, queuedPeers, root, now)
	for _, peerID := range queuedPeers {
		if err != nil {
			driver.logGossip(slog.LevelWarn, "relay_state_update_failed", peerID, "relay", err, nil)
			continue
		}
		if updated {
			driver.observeRelaySuccess(peerID, sourcePeerID, now)
		}
	}
}

func (driver *GossipDriver) logGossipPacketFailure(packet *gossip.Packet, err error) {
	peerID := ""
	fields := map[string]any{"reason": gossip.RejectReason(err)}
	if errors.Is(err, ErrGossipEventQueueFull) {
		fields["reason"] = "input_queue_full"
	}
	if packet != nil && packet.Message != nil {
		peerID = packet.Message.PeerID
		fields["type"] = packet.Message.Type
		if packet.Message.FetchZone != nil {
			fields["zone"] = packet.Message.FetchZone.Zone
		} else if packet.Message.ObjectChunk != nil {
			fields["zone"] = packet.Message.ObjectChunk.Zone
		}
	}
	if errors.Is(err, gossip.ErrChunkSendCacheFull) {
		now := driver.schedulerForRead().clock.Now()
		driver.mu.Lock()
		if !driver.chunkLimitLastLog.IsZero() && now.Sub(driver.chunkLimitLastLog) < slowGossipOperationInterval {
			driver.chunkLimitSuppressed++
			driver.mu.Unlock()
			return
		}
		fields["suppressed"] = driver.chunkLimitSuppressed
		driver.chunkLimitLastLog, driver.chunkLimitSuppressed = now, 0
		driver.mu.Unlock()
		var capacity *gossip.ChunkSendCacheFullError
		if errors.As(err, &capacity) {
			fields["limit"] = capacity.Limit
			fields["peer_transfers"] = capacity.PeerTransfers
			fields["peer_transfer_limit"] = gossip.MaxChunkPeerInflight
			fields["cache_transfers"] = capacity.Transfers
			fields["cache_transfer_limit"] = gossip.MaxChunkSendTransfers
			fields["cache_bytes"] = capacity.Bytes
			fields["cache_byte_limit"] = gossip.MaxChunkSendCacheBytes
			fields["requested_bytes"] = capacity.RequestedBytes
		}
	}
	driver.logGossip(slog.LevelWarn, "packet_failed", peerID, "packet", err, fields)
}

func (driver *GossipDriver) handleGossipSessionEvent(ctx context.Context, event gossip.SyncEvent, now time.Time, sender GossipSender) (bool, []gossip.SyncEvent, error) {
	peerID := gossip.SyncEventPeerID(event)
	if peerID == "" {
		driver.logGossip(slog.LevelDebug, "event_dropped", "", "session", ErrGossipEventPeerRequired, nil)
		return false, nil, ErrGossipEventPeerRequired
	}
	session := driver.Gossip.Session(peerID)
	if session == nil {
		driver.logGossip(slog.LevelDebug, "event_dropped", peerID, "session", errGossipSessionNotFound, nil)
		return false, nil, nil
	}
	if typed, ok := event.(*gossip.ChunkRepairTimeoutEvent); ok {
		nack := driver.gossipChunks.BuildRepairNACK(peerID, typed.TransferID, now)
		if nack == nil {
			return false, nil, nil
		}
		err := sender.SendGossip(ctx, gossip.OutboundMessage{PeerID: peerID, Message: &gossip.Message{Type: gossip.MessageObjectChunkNACK, ObjectChunkNACK: nack}})
		if scheduleErr := driver.ScheduleGossipChunkRepair(peerID, typed.TransferID); scheduleErr != nil {
			driver.reportGossipIssue(GossipExecutionIssue{Phase: GossipPhaseTimer, PeerID: peerID, Err: scheduleErr})
		}
		if err != nil {
			driver.reportGossipIssue(GossipExecutionIssue{Phase: GossipPhaseSend, PeerID: peerID, Err: err})
			return false, nil, nil
		}
		driver.observeChunkRepair(peerID, false, 0, now)
		return false, nil, nil
	}
	catalog := driver.readGossipCatalog()
	switch typed := event.(type) {
	case *gossip.SyncTimerEvent:
		typed.DatagramBudget = driver.Transport().MaxMessageBytes()
	case *gossip.PongReceivedEvent:
		if typed.Pong != nil && typed.Pong.Summary != nil {
			driver.observeCatalogSummary(peerID, typed.Pong.Summary, now)
		}
	case *gossip.CatalogSummaryReceivedEvent:
		driver.observeCatalogSummary(peerID, typed.Summary, now)
	case *gossip.CatalogPageReceivedEvent:
		var managedZone zone.ZonePath
		typed.LocalEntries = nil
		if catalog != nil {
			managedZone = catalog.ManagedZone
			typed.LocalEntries = catalog.Digests
		}
		var peer corestate.PeerCheckpoint
		if driver.gossipState != nil {
			peer = driver.gossipState.PeerCheckpoints([]string{peerID})[peerID]
		}
		typed.Page = filterGossipCatalogPage(managedZone, peer, typed.Page, now)
		driver.observeCatalogPage(peerID, typed.Page, now)
	case *gossip.SnapshotAppliedEvent:
		typed.LocalEntries = nil
		if catalog != nil {
			typed.LocalEntries = catalog.Digests
		}
	}
	oldState := session.State
	actions, protocolErr := session.OnEvent(event, now)
	if protocolErr != nil {
		session.Fail(protocolErr)
	}
	execution := driver.ExecuteGossipActions(ctx, session, catalog, actions, sender)
	if execution.NetworkChanged {
		driver.RelayGossipUpdate(ctx, peerID, now)
	}
	trigger := gossip.SyncEventName(event)
	driver.observeActivePull(peerID, trigger, session, now)
	if protocolErr != nil {
		driver.logGossip(slog.LevelWarn, "session_event_error", peerID, "session", protocolErr, nil)
	}
	if session.State != oldState {
		driver.logGossip(slog.LevelDebug, "session_state_changed", peerID, "session", nil, map[string]any{
			"trigger": trigger, "old_state": oldState, "new_state": session.State,
			"pending": session.PendingCount(), "inflight": session.InflightCount(),
		})
	}
	if session.Done() {
		switch event.(type) {
		case *gossip.RoundTimeoutEvent, *gossip.CatalogPageTimeoutEvent:
			// TCP pull timeouts are not evidence against the UDP address.
			if transport := driver.gossipTransportForRead(); transport != nil && session.State == gossip.SyncSessionFailed {
				switch oldState {
				case gossip.SyncSessionSummarySent:
					transport.RecordAddrFailure(peerID, transport.LastPingAddr(peerID))
				case gossip.SyncSessionCatalogDiffing:
					transport.RecordAddrFailure(peerID, transport.LastSendAddr(peerID))
				}
			}
		}
		driver.finishGossipSession(session)
	}
	return execution.NetworkChanged, execution.Events, nil
}
