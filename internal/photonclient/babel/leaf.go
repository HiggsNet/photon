package babel

import (
	"net/netip"
	"slices"
	"time"

	"github.com/HiggsNet/photon/internal/photonclient/sadr"
)

const (
	MaxOrigins     = 256
	updateInterval = 16 * time.Second
)

// Origin is a locally originated destination/source pair. The caller must
// replace the set whenever current local prefix authorization changes.
type Origin struct{ Prefix, SourcePrefix netip.Prefix }

type learnedRoute struct {
	message          Message
	expires, refresh time.Time
	requested        bool
}

// Leaf is a single-gateway, non-transit Babel speaker. It never advertises
// learned routes, and therefore never establishes feasibility distances for
// remote origins. Updates claiming its own router ID are always rejected.
// One serial owner must retain it across SA rekeys and discard it on gateway
// replacement/revocation. All output must be split into bounded wire packets
// and sent to the peer as unicast (in particular acknowledgments).
type Leaf struct {
	neighbor             *Neighbor
	routerID             [8]byte
	seqno                uint16
	origins              []Origin
	routes               map[Origin]learnedRoute
	nextUpdate, nextDump time.Time
}

func NewLeaf(local, peer netip.Addr, routerID [8]byte, receiveCost uint16) (*Leaf, error) {
	if !validRouterID(routerID) {
		return nil, ErrPacket
	}
	n, err := NewNeighbor(local, peer, receiveCost)
	if err != nil {
		return nil, err
	}
	return &Leaf{neighbor: n, routerID: routerID, routes: make(map[Origin]learnedRoute)}, nil
}

// SetLocal atomically replaces the currently authorized local origin set.
// The returned triggered updates include retractions for removed origins.
// Callers must send them promptly, including when no neighbor is yet up.
func (l *Leaf) SetLocal(origins []Origin) ([]Message, error) {
	if len(origins) > MaxOrigins {
		return nil, ErrPacket
	}
	next := slices.Clone(origins)
	for _, o := range next {
		if !validOrigin(o) {
			return nil, ErrPacket
		}
	}
	slices.SortFunc(next, compareOrigin)
	next = slices.Compact(next)
	if slices.Equal(next, l.origins) {
		return nil, nil
	}
	l.seqno++
	out := make([]Message, 0, len(next)+len(l.origins))
	for _, o := range l.origins {
		if !slices.Contains(next, o) {
			out = append(out, l.update(o, MetricInfinity))
		}
	}
	l.origins = next
	for _, o := range next {
		out = append(out, l.update(o, 0))
	}
	return out, nil
}

func validOrigin(o Origin) bool {
	p := o.Prefix
	if !p.IsValid() || p != p.Masked() || p.Addr().Is4In6() || p.Addr().Zone() != "" {
		return false
	}
	s := o.SourcePrefix
	return !s.IsValid() || s.Bits() > 0 && s == s.Masked() && !s.Addr().Is4In6() && s.Addr().Zone() == "" && s.Addr().BitLen() == p.Addr().BitLen()
}
func compareOrigin(a, b Origin) int {
	if c := a.Prefix.Addr().Compare(b.Prefix.Addr()); c != 0 {
		return c
	}
	if a.Prefix.Bits() != b.Prefix.Bits() {
		return a.Prefix.Bits() - b.Prefix.Bits()
	}
	if c := a.SourcePrefix.Addr().Compare(b.SourcePrefix.Addr()); c != 0 {
		return c
	}
	return a.SourcePrefix.Bits() - b.SourcePrefix.Bits()
}
func (l *Leaf) update(o Origin, metric uint16) Message {
	return Message{Type: TLVUpdate, Prefix: o.Prefix, SourcePrefix: o.SourcePrefix, RouterID: l.routerID, NextHop: l.neighbor.local, Seqno: l.seqno, Metric: metric, Interval: uint16(updateInterval / (10 * time.Millisecond))}
}

// Tick has no catch-up bursts. It emits local origins every update interval,
// and requests a refresh once before each learned route expires.
func (l *Leaf) Tick(now time.Time) []Message {
	out := l.neighbor.Tick(now)
	if !now.Before(l.nextUpdate) {
		l.nextUpdate = now.Add(updateInterval)
		for _, o := range l.origins {
			out = append(out, l.update(o, 0))
		}
	}
	for o, r := range l.routes {
		if !now.Before(r.expires) {
			delete(l.routes, o)
			continue
		}
		if !r.requested && !now.Before(r.refresh) && l.neighbor.Cost(now) != MetricInfinity {
			out = append(out, Message{Type: TLVRouteRequest, Prefix: o.Prefix, SourcePrefix: o.SourcePrefix})
			r.requested = true
			l.routes[o] = r
		}
	}
	return out
}

// Receive requires an authenticated packet from the active gateway. authorize
// binds the full remote RouterID and both prefixes to current verified state;
// nil denies every finite update. Packet validation precedes every mutation.
func (l *Leaf) Receive(packet []byte, now time.Time, authorize func(sadr.Route) bool) ([]Message, error) {
	batch, err := l.neighbor.Receive(packet, now)
	if err != nil {
		return nil, err
	}
	// Prune before insertion so expired or newly unauthorized entries cannot
	// exhaust the bounded table. Lookup must still revalidate on every use.
	for o, r := range l.routes {
		if !now.Before(r.expires) || authorize == nil || !authorize(l.candidate(r.message, r.expires, now)) {
			delete(l.routes, o)
		}
	}
	for _, m := range batch.Updates {
		if m.Wildcard {
			clear(l.routes)
			continue
		}
		o := Origin{m.Prefix, m.SourcePrefix}
		if m.Metric == MetricInfinity {
			// RFC 8966 section 3.5.3 keys a route by prefix and neighbor;
			// retractions are feasible regardless of a change in router ID.
			delete(l.routes, o)
			continue
		}
		if !validOrigin(o) || m.RouterID == l.routerID || m.NextHop != l.neighbor.peer {
			continue
		}
		expires := now.Add(hold(m.Interval))
		candidate := l.candidate(m, expires, now)
		if authorize == nil || candidate.Metric == MetricInfinity || !authorize(candidate) {
			continue
		}
		old, exists := l.routes[o]
		if exists && old.message.RouterID == m.RouterID && int16(m.Seqno-old.message.Seqno) < 0 {
			continue
		}
		if !exists && len(l.routes) >= sadr.MaxRoutes {
			continue
		}
		l.routes[o] = learnedRoute{message: m, expires: expires, refresh: now.Add(time.Duration(m.Interval) * 30 * time.Millisecond)}
	}
	out := batch.Replies
	// Requests cannot turn learned routes into transit advertisements.
	for _, m := range batch.Requests {
		if m.Wildcard {
			if now.Before(l.nextDump) {
				continue
			}
			l.nextDump = now.Add(time.Second)
			for _, o := range l.origins {
				out = append(out, l.update(o, 0))
			}
			continue
		}
		o := Origin{m.Prefix, m.SourcePrefix}
		if !validOrigin(o) {
			continue
		}
		if slices.Contains(l.origins, o) {
			if m.Type == TLVSeqnoRequest && m.RouterID == l.routerID && int16(m.Seqno-l.seqno) > 0 {
				l.seqno++
			}
			out = append(out, l.update(o, 0))
		} else if m.Type == TLVRouteRequest {
			out = append(out, l.update(o, MetricInfinity))
		}
	}
	return out, nil
}

func (l *Leaf) candidate(m Message, expires time.Time, now time.Time) sadr.Route {
	metric := uint16(min(uint32(MetricInfinity), uint32(m.Metric)+uint32(l.neighbor.Cost(now))))
	return sadr.Route{Destination: m.Prefix, Source: m.SourcePrefix, RouterID: m.RouterID, NextHop: m.NextHop, Metric: metric, ExpiresAt: expires}
}

// Candidates returns detached feasible routes with current link cost and
// authorization. Remote feasibility distances are absent because this leaf
// never advertises learned routes (RFC 8966 sections 3.5.1 and 3.7.3).
func (l *Leaf) Candidates(now time.Time, authorize func(sadr.Route) bool) []sadr.Route {
	var out []sadr.Route
	for o, r := range l.routes {
		candidate := l.candidate(r.message, r.expires, now)
		if !now.Before(r.expires) || authorize == nil || !authorize(candidate) {
			delete(l.routes, o)
			continue
		}
		if candidate.Metric != MetricInfinity {
			out = append(out, candidate)
		}
	}
	slices.SortFunc(out, func(a, b sadr.Route) int {
		return compareOrigin(Origin{a.Destination, a.Source}, Origin{b.Destination, b.Source})
	})
	return out
}
