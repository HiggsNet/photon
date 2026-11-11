package host

import (
	"bytes"
	"context"
	"log/slog"

	"github.com/HiggsNet/photon/pkg/core/gossip"
)

const GossipPhaseInbound = "inbound"

// handleGossipMessage dispatches an inbound message and returns ready FSM
// events for the current batch.
func (driver *GossipDriver) handleGossipMessage(ctx context.Context, message *gossip.Message, sender GossipSender, budget int) ([]gossip.SyncEvent, error) {
	if message == nil {
		return nil, nil
	}
	peerID := message.PeerID
	switch message.Type {
	case gossip.MessagePing:
		if message.Ping == nil {
			return nil, nil
		}
		return driver.respondGossipPing(ctx, message, sender)
	case gossip.MessagePong:
		if message.Pong != nil && driver.Gossip.Session(peerID) != nil {
			return []gossip.SyncEvent{&gossip.PongReceivedEvent{PeerID: peerID, Pong: message.Pong}}, nil
		}
	case gossip.MessageFetchCatalogPage:
		driver.respondGossipCatalogPage(ctx, message, sender, budget)
	case gossip.MessageFetchZone:
		return nil, driver.respondGossipFetchZone(ctx, peerID, message.FetchZone, sender, budget)
	case gossip.MessageCatalogPage:
		if message.CatalogPage != nil && driver.Gossip.Session(peerID) != nil {
			return []gossip.SyncEvent{&gossip.CatalogPageReceivedEvent{PeerID: peerID, Page: message.CatalogPage}}, nil
		}
	case gossip.MessageObjectChunk:
		if driver.Gossip.Session(peerID) == nil {
			return nil, nil
		}
		now := driver.schedulerForRead().clock.Now()
		event, err := driver.HandleGossipObjectChunk(message, now)
		if event == nil {
			return nil, err
		}
		if event.Snapshot != nil {
			driver.observeChunkFallback(peerID, 1, now)
		}
		return []gossip.SyncEvent{event}, err
	case gossip.MessageObjectChunkNACK:
		return nil, driver.handleGossipObjectChunkNACK(ctx, message, sender)
	}
	return nil, nil
}

func (driver *GossipDriver) respondGossipPing(ctx context.Context, message *gossip.Message, sender GossipSender) ([]gossip.SyncEvent, error) {
	summary := driver.GossipCatalogSummary()
	if summary == nil {
		return nil, nil
	}
	peerID := message.PeerID
	if err := sender.SendGossip(ctx, gossip.OutboundMessage{PeerID: peerID, Message: &gossip.Message{
		Type: gossip.MessagePong, Pong: &gossip.Pong{Summary: summary},
	}}); err != nil {
		driver.reportGossipIssue(GossipExecutionIssue{Phase: GossipPhaseSend, PeerID: peerID, Err: err})
	}
	remote := message.Ping.Summary
	if remote == nil {
		return nil, nil
	}
	session := driver.Gossip.Session(peerID)
	if session != nil && session.State != gossip.SyncSessionIdle {
		return []gossip.SyncEvent{&gossip.CatalogSummaryReceivedEvent{PeerID: peerID, Summary: remote}}, nil
	}
	now := driver.schedulerForRead().clock.Now()
	driver.observeCatalogSummary(peerID, remote, now)
	if session == nil {
		if bytes.Equal(remote.CatalogRoot, summary.CatalogRoot) {
			if err := driver.commitGossipEventCheckpoint(ctx, &gossip.SyncSession{PeerID: peerID, State: gossip.SyncSessionCompleted}, now); err != nil {
				return nil, err
			}
			driver.observeSyncHint(peerID, "ping_summary_match", "", true, now)
			driver.logGossip(slog.LevelDebug, "ping_summary_shortcut", peerID, "session", nil, map[string]any{"reason": "catalog_root_match"})
			return nil, nil
		}
		if driver.gossipObjectPullDraining(peerID) {
			driver.Gossip.DeferHint(peerID)
			driver.observeSyncHint(peerID, "ping_summary", "pulls_draining", false, now)
			return nil, nil
		}
		driver.Gossip.NewSession(peerID)
	}
	driver.observeSyncHint(peerID, "ping_summary", "", true, now)
	return []gossip.SyncEvent{&gossip.SyncTimerEvent{PeerID: peerID, LocalSummary: summary, RemoteSummary: remote}}, nil
}

func (driver *GossipDriver) respondGossipCatalogPage(ctx context.Context, message *gossip.Message, sender GossipSender, budget int) {
	if message == nil || message.FetchCatalogPage == nil {
		return
	}
	catalog := driver.readGossipCatalog()
	if catalog == nil {
		return
	}
	cursor := message.FetchCatalogPage.Cursor
	page, err := gossip.CatalogPageForDigests(catalog.Digests, cursor, budget, driver.gossipConfig.PeerID)
	if err != nil {
		driver.observeDatagramTooLarge(message.PeerID, "catalog_page", "", "", 0, budget, driver.schedulerForRead().clock.Now())
		driver.observeCatalogReject(message.PeerID, cursor, gossip.RejectReason(err), driver.schedulerForRead().clock.Now())
		driver.logGossip(slog.LevelWarn, "catalog_page_failed", message.PeerID, "responder", err, map[string]any{"cursor": cursor})
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
