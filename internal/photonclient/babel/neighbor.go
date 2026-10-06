package babel

import (
	"net/netip"
	"time"
)

const helloInterval = 4 * time.Second

// Neighbor is the Babel control state of one authenticated point-to-point peer.
// The daemon owns it serially. Its lifetime is the logical gateway attachment:
// CHILD/IKE rekeys retain it; gateway changes, rebinds and revocation discard it.
// No unverified packet may reach Receive. It neither installs nor forwards routes.
type Neighbor struct {
	local, peer         netip.Addr
	rxCost              uint16
	hello               [2]helloState
	txCost              uint16
	ihuUntil, nextHello time.Time
	seqno               uint16
}
type helloState struct {
	seqno    uint16
	expires  time.Time
	interval time.Duration
}

// NeighborBatch contains only observations requiring the caller's current
// origin/route authorization. Requests may be answered only from locally
// originated authorized prefixes; learned routes must never be advertised.
type NeighborBatch struct {
	Replies  []Message
	Updates  []Message
	Requests []Message
}

func NewNeighbor(local, peer netip.Addr, receiveCost uint16) (*Neighbor, error) {
	if !linkLocal(local) || !linkLocal(peer) || local == peer || receiveCost == 0 || receiveCost == MetricInfinity {
		return nil, ErrPacket
	}
	return &Neighbor{local: local, peer: peer, rxCost: receiveCost, txCost: MetricInfinity}, nil
}

// Tick emits a single periodic multicast-sequence Hello, plus an IHU when reverse
// reachability exists. Missed scheduler ticks never create a catch-up burst.
// RFC 8966 section 3.4.1 permits sending this Hello to each peer by unicast.
func (n *Neighbor) Tick(now time.Time) []Message {
	if now.Before(n.nextHello) {
		return nil
	}
	n.nextHello = now.Add(helloInterval)
	n.seqno++
	out := []Message{{Type: TLVHello, Seqno: n.seqno, Interval: uint16(helloInterval / (10 * time.Millisecond))}}
	if n.heard(now) {
		out = append(out, n.ihu())
	}
	if n.Cost(now) == MetricInfinity {
		out = append(out, Message{Type: TLVRouteRequest, Wildcard: true})
	}
	return out
}

// Cost is infinite as soon as either Hello or IHU expires, including precisely
// at the deadline. Route selection must check it before using learned routes.
func (n *Neighbor) Cost(now time.Time) uint16 {
	if !n.heard(now) || !now.Before(n.ihuUntil) || n.txCost == MetricInfinity {
		return MetricInfinity
	}
	return max(n.rxCost, n.txCost)
}
func (n *Neighbor) heard(now time.Time) bool {
	return now.Before(n.hello[0].expires) || now.Before(n.hello[1].expires)
}
func (n *Neighbor) ihu() Message {
	return Message{Type: TLVIHU, Address: n.peer, Metric: n.rxCost, Interval: uint16(helloInterval / (10 * time.Millisecond))}
}
func hold(interval uint16) time.Duration {
	return time.Duration(interval) * 10 * time.Millisecond * 7 / 2
}

// Receive validates complete IPv6/UDP framing and the pinned peer address
// before any mutation. Unsupported mandatory semantics never affect liveness.
func (n *Neighbor) Receive(packet []byte, now time.Time) (NeighborBatch, error) {
	source, payload, err := ParsePacket(packet, n.local)
	if err != nil || source != n.peer {
		return NeighborBatch{}, ErrPacket
	}
	messages, err := Decode(payload, source)
	if err != nil {
		return NeighborBatch{}, err
	}
	batch := NeighborBatch{}
	wasUp := n.Cost(now) != MetricInfinity
	heardHello := false
	for _, m := range messages {
		if m.Ignore {
			continue
		}
		switch m.Type {
		case TLVHello:
			index := 0
			if m.Unicast {
				index = 1
			}
			h := &n.hello[index]
			// Duplicate/backward sequence numbers cannot extend a live lease.
			if now.Before(h.expires) && int16(m.Seqno-h.seqno) <= 0 {
				continue
			}
			h.seqno = m.Seqno
			if m.Interval != 0 {
				h.interval = time.Duration(m.Interval) * 10 * time.Millisecond
				h.expires = now.Add(h.interval * 7 / 2)
			}
			// An unscheduled Hello does not extend the previous promise.
			heardHello = n.heard(now)
		case TLVIHU:
			if m.Address.IsValid() && m.Address != n.local {
				continue
			}
			n.txCost = m.Metric
			n.ihuUntil = now.Add(hold(m.Interval))
		case TLVAckRequest:
			// A single packet cannot trigger an unbounded response queue.
			if len(batch.Replies) < MaxMessages {
				batch.Replies = append(batch.Replies, Message{Type: TLVAck, Opaque: m.Opaque})
			}
		}
	}
	if heardHello {
		batch.Replies = append(batch.Replies, n.ihu())
	}
	isUp := n.Cost(now) != MetricInfinity
	if isUp && !wasUp {
		batch.Replies = append(batch.Replies, Message{Type: TLVRouteRequest, Wildcard: true})
	}
	for _, m := range messages {
		if m.Ignore {
			continue
		}
		switch m.Type {
		case TLVUpdate:
			// A retraction remains effective while bidirectionality is down;
			// otherwise a later Hello could revive a withdrawn candidate.
			if !isUp && m.Metric != MetricInfinity {
				continue
			}
			// An alternate IPv6 next hop is not reachable through this single peer.
			if m.Metric != MetricInfinity && m.NextHop != n.peer {
				continue
			}
			batch.Updates = append(batch.Updates, m)
		case TLVRouteRequest, TLVSeqnoRequest:
			if isUp {
				batch.Requests = append(batch.Requests, m)
			}
		}
	}
	return batch, nil
}
