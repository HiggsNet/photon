package gossip

import (
	"sync"
	"time"
)

// Engine owns only mutable per-peer protocol state. It is a synchronous,
// deterministic protocol machine: the GossipDriver serially supplies events and
// executes the returned actions.
type Engine struct {
	sessionsMu   sync.RWMutex // Protects membership while query readers take a snapshot.
	sessions     map[string]*SyncSession
	pendingHints map[string]bool
}

func NewEngine() *Engine {
	return &Engine{
		sessions:     make(map[string]*SyncSession),
		pendingHints: make(map[string]bool),
	}
}

func (engine *Engine) NewSession(peerID string) *SyncSession {
	if engine == nil || peerID == "" {
		return nil
	}
	session := NewSyncSession(peerID)
	engine.SetSession(peerID, session)
	return session
}

// SetSession installs a detached session. It supports restored/test sessions;
// normal callers use NewSession.
func (engine *Engine) SetSession(peerID string, session *SyncSession) {
	if engine == nil || peerID == "" {
		return
	}
	engine.sessionsMu.Lock()
	defer engine.sessionsMu.Unlock()
	if session == nil {
		delete(engine.sessions, peerID)
		return
	}
	engine.sessions[peerID] = session
}

func (engine *Engine) Session(peerID string) *SyncSession {
	if engine == nil {
		return nil
	}
	engine.sessionsMu.RLock()
	defer engine.sessionsMu.RUnlock()
	return engine.sessions[peerID]
}

// SessionPeers returns the round owners without exposing mutable sessions.
func (engine *Engine) SessionPeers() map[string]bool {
	if engine == nil {
		return nil
	}
	engine.sessionsMu.RLock()
	defer engine.sessionsMu.RUnlock()
	peers := make(map[string]bool, len(engine.sessions))
	for id := range engine.sessions {
		peers[id] = true
	}
	return peers
}

func (engine *Engine) HasActiveSession(peerID string) bool {
	session := engine.Session(peerID)
	return session != nil && !session.Done()
}

func (engine *Engine) RemoveSession(peerID string) {
	engine.SetSession(peerID, nil)
}

func (engine *Engine) PlanInbound(packet *Packet) []InboundAction {
	if engine == nil {
		return PlanInboundPacket(packet, nil)
	}
	engine.sessionsMu.RLock()
	defer engine.sessionsMu.RUnlock()
	return PlanInboundPacket(packet, engine.sessions)
}

type EngineEventResult struct {
	Accepted bool
	PeerID   string
	Session  *SyncSession
	OldState SyncSessionState
	Actions  []SyncAction
	Err      error
}

// HandleEvent advances the owning session and fails it on protocol errors.
// Callers may enrich packet-derived event fields before invoking this method.
func (engine *Engine) HandleEvent(event SyncEvent, now time.Time) EngineEventResult {
	peerID := SyncEventPeerID(event)
	result := EngineEventResult{PeerID: peerID}
	if engine == nil || peerID == "" {
		return result
	}
	session := engine.sessions[peerID]
	if session == nil {
		return result
	}
	result.Accepted = true
	result.Session = session
	result.OldState = session.State
	result.Actions, result.Err = session.OnEvent(event, now)
	if result.Err != nil {
		session.Fail(result.Err)
	}
	return result
}

func (engine *Engine) DeferHint(peerID string) {
	if engine != nil && peerID != "" {
		engine.pendingHints[peerID] = true
	}
}

func (engine *Engine) PendingHint(peerID string) bool {
	return engine != nil && engine.pendingHints[peerID]
}

func (engine *Engine) TakePendingHint(peerID string) bool {
	if engine == nil || !engine.pendingHints[peerID] {
		return false
	}
	delete(engine.pendingHints, peerID)
	return true
}
