package host

import (
	"context"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

const GossipPhaseInbound = "inbound"

// executeGossipPacketActions executes the ordered decisions produced by
// gossip.PlanInboundPacket. Platforms no longer switch on InboundActionKind.
func (driver *GossipDriver) executeGossipPacketActions(ctx context.Context, actions []gossip.InboundAction, sender GossipSender, budget int) error {
	if driver == nil {
		return ErrGossipDriverStopped
	}
	if sender == nil {
		return errGossipSenderRequired
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for _, action := range actions {
		message := action.Message
		if message == nil {
			continue
		}
		switch action.Kind {
		case gossip.InboundPostSessionEvent:
			err := driver.PostGossip(action.Event)
			if err == nil {
				continue
			}
			driver.reportGossipIssue(GossipExecutionIssue{Phase: GossipPhaseInbound, PeerID: message.PeerID, Err: err})
			// An active PING must still receive its responder messages even if
			// its summary event encountered queue backpressure.
			if message.Type == gossip.MessagePing {
				continue
			}
			return err
		case gossip.InboundRespondPing:
			if err := driver.respondGossipPing(ctx, action, sender); err != nil {
				return err
			}
		case gossip.InboundRespondFetchCatalogPage:
			driver.respondGossipCatalogPage(ctx, message, sender, budget)
		case gossip.InboundRespondFetchZone:
			if err := driver.respondGossipFetchZone(ctx, message.PeerID, message.FetchZone, sender, budget); err != nil {
				return err
			}
		case gossip.InboundHandleAnnounce:
			if err := driver.StartGossipSession(message.PeerID, "announce_hint"); err != nil {
				return err
			}
		case gossip.InboundHandleObjectChunk:
			result, err := driver.HandleGossipObjectChunk(ctx, message, driver.schedulerForRead().clock.Now())
			if result.CheckpointErr != nil {
				driver.logGossip("warn", "chunk_reject_state_commit_failed", result.PeerID, "checkpoint", result.CheckpointErr, map[string]any{"zone": result.Zone})
			}
			if result.ChunkFallback {
				driver.observeChunkFallback(result.PeerID, 1, driver.schedulerForRead().clock.Now())
			}
			if err != nil {
				return err
			}
		case gossip.InboundHandleObjectChunkNACK:
			if err := driver.handleGossipObjectChunkNACK(ctx, message, sender); err != nil {
				return err
			}
		}
	}
	return nil
}

func (driver *GossipDriver) respondGossipPing(ctx context.Context, action gossip.InboundAction, sender GossipSender) error {
	message := action.Message
	if message == nil || message.Ping == nil {
		return nil
	}
	view := driver.gossipStateView()
	if !view.Loaded {
		return nil
	}
	summary := corestate.CatalogSummaryForDigests(view.Digests)
	driver.observeCatalogSummary(message.PeerID, summary, driver.schedulerForRead().clock.Now())
	for _, response := range gossip.PlanPingResponse(message.Ping, summary) {
		if err := sender.SendGossip(ctx, gossip.OutboundMessage{PeerID: message.PeerID, Message: response}); err != nil {
			driver.reportGossipIssue(GossipExecutionIssue{Phase: GossipPhaseSend, PeerID: message.PeerID, Err: err})
		}
	}
	if action.ActiveSession || message.Ping.Summary == nil {
		return nil
	}
	if !gossip.CatalogRootsMatch(message.Ping.Summary, summary) {
		return driver.StartGossipSession(message.PeerID, "announce_hint")
	}
	if err := driver.commitGossipEventCheckpoint(ctx, &gossip.SyncSession{PeerID: message.PeerID, State: gossip.SyncSessionCompleted}, nil, driver.schedulerForRead().clock.Now()); err != nil {
		return err
	}
	driver.observeSyncHint(message.PeerID, "ping_summary_match", "", true, driver.schedulerForRead().clock.Now())
	driver.logGossip("debug", "ping_summary_shortcut", message.PeerID, "session", nil, map[string]any{"reason": "catalog_root_match"})
	return nil
}

func (driver *GossipDriver) respondGossipCatalogPage(ctx context.Context, message *gossip.Message, sender GossipSender, budget int) {
	if message == nil || message.FetchCatalogPage == nil {
		return
	}
	view := driver.gossipStateView()
	if !view.Loaded {
		return
	}
	cursor := message.FetchCatalogPage.Cursor
	page, err := gossip.CatalogPageForDigests(view.Digests, cursor, budget, view.SenderPeerID)
	if err != nil {
		driver.observeDatagramTooLarge(message.PeerID, "catalog_page", "", "", 0, budget, driver.schedulerForRead().clock.Now())
		driver.observeCatalogReject(message.PeerID, cursor, gossip.RejectReason(err), driver.schedulerForRead().clock.Now())
		driver.logGossip("warn", "catalog_page_failed", message.PeerID, "responder", err, map[string]any{"cursor": cursor})
		return
	}
	driver.observeCatalogPage(message.PeerID, page, driver.schedulerForRead().clock.Now())
	driver.observeReadOnlyResponder(message.PeerID, "catalog_page", "", driver.schedulerForRead().clock.Now())
	if err := sender.SendGossip(ctx, gossip.OutboundMessage{
		PeerID: message.PeerID,
		Message: &gossip.Message{
			Type:        gossip.MessageCatalogPage,
			CatalogPage: page,
		},
	}); err != nil {
		driver.reportGossipIssue(GossipExecutionIssue{Phase: GossipPhaseSend, PeerID: message.PeerID, Err: err})
	}
}
