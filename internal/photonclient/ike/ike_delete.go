package ike

import "fmt"

func isIKEDelete(ps []Payload) bool {
	return len(ps) == 1 && ps[0].Type == PayloadDelete && len(ps[0].Data) == 4 && ps[0].Data[0] == 1 && ps[0].Data[1] == 0 && ps[0].Data[2] == 0 && ps[0].Data[3] == 0
}

// IKEDeleteRequest closes this IKE SA and its remaining CHILDs. After a rekey
// adopts the children into a new SA, closing the old IKE SA leaves them intact.
func (i *Initiator) IKEDeleteRequest() ([]byte, error) {
	packet, err := i.beginExchange(ExchangeInformational, exchangeIKEDelete, []Payload{{Type: PayloadDelete, Data: []byte{1, 0, 0, 0}}})
	if err != nil {
		return nil, err
	}
	i.closing = true
	return packet, nil
}

// HandleIKEDelete handles SK wire messages; HandleExchange also supports SKF.
func (i *Initiator) HandleIKEDelete(packet []byte) ([]byte, *DeleteResult, error) {
	m, err := i.decodeSKExchange(packet)
	if err != nil {
		return nil, nil, err
	}
	return i.handleIKEDelete(m)
}

func (i *Initiator) handleIKEDelete(m *ExchangeMessage) ([]byte, *DeleteResult, error) {
	h, ps, cached, err := i.openAuthenticated(m, ExchangeInformational)
	if err != nil {
		return nil, nil, err
	}
	if cached != nil {
		return cached, nil, nil
	}
	if h.Flags&FlagResponse != 0 {
		if i.exchanges.pendingKind != exchangeIKEDelete || len(ps) != 0 {
			return nil, nil, fmt.Errorf("ike: invalid IKE Delete response")
		}
		i.completeExchange()
		return nil, i.closeIKE(), nil
	}
	if !isIKEDelete(ps) {
		return nil, nil, fmt.Errorf("ike: invalid IKE Delete request")
	}
	reply, err := i.replyExchange(m.identity, h, nil)
	if err != nil {
		return nil, nil, err
	}
	return reply, i.closeIKE(), nil
}

func (i *Initiator) closeIKE() *DeleteResult {
	result := &DeleteResult{IKE: true}
	i.exchanges.pending = nil
	i.exchanges.pendingKind = 0
	i.exchanges.requestFragments = nil
	// A peer that completed its rekey may delete the old SA before seeing our
	// simultaneous request. Stop that request and inherit into the peer's SA.
	if i.peerRekey != nil && i.ikePending != nil {
		i.ikePending = nil
	}
	if i.localRekey != nil || i.peerRekey != nil {
		if resolution, err := i.AdoptIKERekey(); err == nil {
			result.Successor = resolution.Surviving
		}
	}
	for spi := range i.children {
		result.Removed = append(result.Removed, spi)
		i.forgetChild(spi)
	}
	i.childPending = nil
	i.ikePending = nil
	i.deletePending = nil
	i.ResetExchangeFragments()
	i.closing, i.closed = false, true
	// Keep keys and the one reply cache solely for retransmitted peer Delete.
	// Transport owns the bounded closing timeout and then discards this session.
	return result
}
