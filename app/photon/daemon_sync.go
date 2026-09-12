package main

import (
	"context"
	"errors"
	"net"
	"strings"

	photonlinux "github.com/HiggsNet/photon/internal/photonlinux"
	"github.com/HiggsNet/photon/pkg/core/gossip"
	corehost "github.com/HiggsNet/photon/pkg/core/host"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

// EnableEventLoopSync configures the event-loop gossip.SyncSession clock. The
// objectPullTCPAddr derives the TCP object-pull address from a gossip UDP
// endpoint. TCP and UDP intentionally share the numeric port.
func objectPullTCPAddr(udpAddr string) string {
	udp, err := net.ResolveUDPAddr("udp", udpAddr)
	if err != nil {
		return ""
	}
	return (&net.TCPAddr{IP: udp.IP, Port: udp.Port}).String()
}

func (d *Daemon) objectPullResponse(req *gossip.ObjectPullRequest) *gossip.ObjectPullResponse {
	if d == nil || d.gossipDriver == nil {
		return &gossip.ObjectPullResponse{Error: "invalid request"}
	}
	response := d.gossipDriver.GossipObjectPullResponse(req, d.now())
	if req != nil && response != nil && response.OK && response.Snapshot != nil {
		encoded, _ := gossip.EncodeZoneSnapshotObject(response.Snapshot)
		d.logDebug("object_pull", "lookup_snapshot", map[string]any{
			"zone": req.Zone.String(), "records": len(response.Snapshot.Records), "bytes": len(encoded),
		})
	}
	return response
}

func newDaemonObjectPullExecutor(d *Daemon) *corehost.GossipObjectPullExecutor {
	return corehost.NewGossipObjectPullExecutor(corehost.GossipObjectPullExecutorConfig{
		Client: photonlinux.GossipObjectPullClient{},
		Discovery: func() corehost.GossipDiscoveryInput {
			return d.gossipDriver.GossipDiscoveryInput(d.gossipSuppressions())
		},
		Now: d.now,
	})
}

// startObjectPullServer binds the platform listener and gives its lifecycle to
// GossipDriver.
func startObjectPullServer(ctx context.Context, d *Daemon) error {
	if d == nil || d.gossipDriver == nil || d.gossipDriver.Transport() == nil {
		return errors.New("object-pull server runtime is not configured")
	}
	addr := objectPullTCPAddr(d.gossipDriver.Transport().LocalAddr().String())
	if addr == "" {
		return nil
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	if err := d.gossipDriver.StartGossipObjectPullServer(ctx, listener, d.objectPullResponse, 0, 0); err != nil {
		_ = listener.Close()
		return err
	}
	d.logInfo("object_pull", "serve_started", map[string]any{"addr": listener.Addr()})
	return nil
}

// event-loop sync path is the only daemon sync path; this helper remains for
// tests that need a fake clock.
func (d *Daemon) EnableEventLoopSync(clock corehost.Clock) {
	if clock == nil {
		if d.App != nil && d.App.Clock != nil {
			clock = corehost.NewClock(d.App.Clock)
		} else {
			clock = corehost.NewClock(nil)
		}
	}
	if d.gossipDriver == nil {
		view := d.State.Common.ReadView()
		d.gossipDriver = corehost.NewGossipDriver(clock, corehost.DefaultEventBuffer, d.State.Common, gossipDriverConfig(d.App.Config, view.State, d.Log))
		return
	}
	d.gossipDriver.ResetScheduler(clock)
}

func (d *Daemon) handleSyncTimerEvent(ctx context.Context, force bool) error {
	if d == nil {
		return nil
	}
	now := d.now()
	input := d.gossipDriver.GossipDiscoveryInput(d.gossipSuppressions())
	peers := corehost.GossipOutboundPeers(input, now)
	if len(peers) == 0 {
		return nil
	}
	summary := corestate.CatalogSummaryFor(input.Network)
	d.logDebug("sync", "event_loop_timer", map[string]any{
		"peer_count": len(peers),
		"force":      force,
	})
	for _, peerID := range peers {
		if !force && corehost.GossipBackoffRemaining(input.Peers[peerID], now) > 0 {
			d.logDebug("sync", "event_loop_skipped", map[string]any{
				"peer_id": peerID,
				"reason":  "backoff",
			})
			continue
		}
		if d.gossipDriver.Gossip.HasActiveSession(peerID) {
			d.logDebug("sync", "event_loop_skipped", map[string]any{
				"peer_id": peerID,
				"reason":  "session_active",
			})
			continue
		}
		d.gossipDriver.Gossip.NewSession(peerID)
		event := &gossip.SyncTimerEvent{
			PeerID:       peerID,
			LocalSummary: summary,
		}
		// This function already runs on the daemon event-loop goroutine. Execute
		// the initial event directly so a saturated internal event queue cannot
		// leave an idle session behind forever. Such a zombie session suppresses
		// every later periodic/bootstrap retry as "session_active".
		d.handleSyncEvent(ctx, event)
	}
	return nil
}

func (d *Daemon) processPacketEvent(packet *gossip.Packet, ctx context.Context) error {
	if packet == nil || packet.Message == nil {
		return errors.New("packet event is nil")
	}
	_, err := d.gossipDriver.HandleGossipHostEvent(ctx, corehost.GossipPacketReceived{Packet: packet}, d.now(), d.gossipSuppressions())
	return err
}

func (d *Daemon) handleSyncEvent(ctx context.Context, event gossip.SyncEvent) bool {
	eventNow := d.now()
	hostResult, err := d.gossipDriver.HandleGossipHostEvent(ctx, corehost.GossipEvent{Value: event}, eventNow, d.gossipSuppressions())
	if err != nil {
		return false
	}
	return d.observeSyncEventResult(hostResult.Session)
}

func (d *Daemon) handleGossipDriverEvent(ctx context.Context, hostEvent corehost.Event) (corehost.GossipHostEventResult, error) {
	now := d.now()
	result, err := d.gossipDriver.HandleGossipHostEvent(ctx, hostEvent, now, d.gossipSuppressions())
	if result.Session.PeerID != "" && err == nil {
		d.observeSyncEventResult(result.Session)
	}
	return result, err
}

func (d *Daemon) observeSyncEventResult(result corehost.GossipEventResult) bool {
	peerID := result.PeerID
	if result.Done {
		// Address health and the ephemeral reply route belong to the platform
		// transport. The GossipDriver has already removed the session, queued
		// any deferred hint and scheduled relay work before returning here.
		transport := d.gossipDriver.Transport()
		if result.TerminalErr != nil && transport != nil && strings.Contains(result.TerminalErr.Error(), "timeout") {
			if lastAddr := transport.LastSendAddr(peerID); lastAddr != nil {
				transport.RecordAddrFailure(peerID, lastAddr)
			}
		}
		if result.NetworkChanged {
			if transport != nil {
				d.refreshGossipDiscovery()
			}
			d.notifyStateChanged()
		}
	}
	return result.NetworkChanged
}
