package ike

import (
	"encoding/binary"
	"fmt"
)

const PayloadDelete uint8 = 42

type childDeletePending struct {
	// Detached local-to-peer SPI pairs also survive a simultaneous peer Delete.
	pairs map[uint32]uint32
}

// DeleteResult lists local inbound SPIs whose entire CHILD pair can be removed
// by the dataplane owner. A replay has nil result and never removes twice.
type DeleteResult struct{ Removed []uint32 }

func encodeChildDelete(spis []uint32) (Payload, error) {
	if len(spis) == 0 || len(spis) > maxChildSAs {
		return Payload{}, fmt.Errorf("ike: invalid CHILD Delete count")
	}
	b := []byte{3, 4, 0, byte(len(spis))}
	for _, spi := range spis {
		if spi < 256 {
			return Payload{}, fmt.Errorf("ike: reserved Delete SPI")
		}
		b = binary.BigEndian.AppendUint32(b, spi)
	}
	return Payload{Type: PayloadDelete, Data: b}, nil
}

func parseChildDeletes(ps []Payload) ([]uint32, error) {
	var spis []uint32
	seen := make(map[uint32]bool)
	for _, p := range ps {
		b := p.Data
		if p.Type != PayloadDelete || len(b) < 4 || b[0] != 3 || b[1] != 4 {
			return nil, fmt.Errorf("ike: expected ESP Delete payload")
		}
		count := int(binary.BigEndian.Uint16(b[2:]))
		if count == 0 || count > maxChildSAs || len(b) != 4+4*count || len(spis)+count > maxChildSAs {
			return nil, fmt.Errorf("ike: invalid ESP Delete length/count")
		}
		for n := 0; n < count; n++ {
			spi := binary.BigEndian.Uint32(b[4+n*4:])
			if spi < 256 || seen[spi] {
				return nil, fmt.Errorf("ike: reserved or duplicate Delete SPI")
			}
			seen[spi] = true
			spis = append(spis, spi)
		}
	}
	return spis, nil
}

// ChildDeleteRequest names local inbound SPIs. Successful rekeying does not
// implicitly delete the old pair; explicit deletion allows receive overlap.
func (i *Initiator) ChildDeleteRequest(localSPIs []uint32) ([]byte, error) {
	pairs := make(map[uint32]uint32, len(localSPIs))
	for _, spi := range localSPIs {
		child := i.children[spi]
		if child == nil || pairs[spi] != 0 {
			return nil, fmt.Errorf("ike: unknown or repeated local CHILD Delete SPI")
		}
		pairs[spi] = child.result.ResponderSPI
	}
	payload, err := encodeChildDelete(localSPIs)
	if err != nil {
		return nil, err
	}
	packet, err := i.beginExchange(ExchangeInformational, exchangeDelete, []Payload{payload})
	if err != nil {
		return nil, err
	}
	i.deletePending = &childDeletePending{pairs: pairs}
	return packet, nil
}

func (i *Initiator) forgetChild(spi uint32) bool {
	child := i.children[spi]
	if child == nil {
		return false
	}
	clear(child.result.Keys.InitiatorToResponder)
	clear(child.result.Keys.ResponderToInitiator)
	delete(i.children, spi)
	return true
}

// HandleChildDelete processes an authenticated CHILD Delete request or response.
// Unknown peer SPIs are ignored and answered with an empty response as RFC 7296
// requires. Simultaneous Deletes omit the corresponding SPI in their response.
func (i *Initiator) HandleChildDelete(packet []byte) ([]byte, *DeleteResult, error) {
	h, ps, cached, err := i.openExchange(packet, ExchangeInformational)
	if err != nil {
		return nil, nil, err
	}
	if cached != nil {
		return cached, nil, nil
	}
	spis, err := parseChildDeletes(ps)
	if err != nil {
		return nil, nil, err
	}
	result := &DeleteResult{}
	if h.Flags&FlagResponse != 0 {
		if i.exchanges.pendingKind != exchangeDelete || i.deletePending == nil {
			return nil, nil, fmt.Errorf("ike: no pending CHILD Delete")
		}
		allowed := make(map[uint32]bool, len(i.deletePending.pairs))
		for _, peer := range i.deletePending.pairs {
			allowed[peer] = true
		}
		for _, spi := range spis {
			if !allowed[spi] {
				return nil, nil, fmt.Errorf("ike: Delete response contains unrequested CHILD SPI")
			}
		}
		for local := range i.deletePending.pairs {
			if i.forgetChild(local) {
				result.Removed = append(result.Removed, local)
			}
		}
		i.deletePending = nil
		i.completeExchange()
		return nil, result, nil
	}
	if len(ps) == 0 {
		return nil, nil, fmt.Errorf("ike: empty request is liveness, not CHILD Delete")
	}
	var replySPIs []uint32
	for _, peer := range spis {
		for local, child := range i.children {
			if child.result.ResponderSPI == peer {
				result.Removed = append(result.Removed, local)
				if i.deletePending == nil || i.deletePending.pairs[local] == 0 {
					replySPIs = append(replySPIs, local)
				}
				break
			}
		}
	}
	var responsePS []Payload
	if len(replySPIs) > 0 {
		p, err := encodeChildDelete(replySPIs)
		if err != nil {
			return nil, nil, err
		}
		responsePS = []Payload{p}
	}
	reply, err := i.replyExchange(packet, h, responsePS)
	if err != nil {
		return nil, nil, err
	}
	for _, local := range result.Removed {
		i.forgetChild(local)
	}
	return reply, result, nil
}

// ChildRekeyResolution is a decision for the dataplane and exchange caller.
// SurvivingSPI remains installed; receive overlap lasts until Delete completes.
// DeleteSPI is nonzero only for the deletion this endpoint is responsible for.
// Pending means a simultaneous locally initiated rekey has no final response.
type ChildRekeyResolution struct {
	SurvivingSPI, RedundantSPI, DeleteSPI uint32
	Pending                               bool
}

func (i *Initiator) ResolveChildRekey(oldLocalSPI uint32) (ChildRekeyResolution, error) {
	r := ChildRekeyResolution{}
	if i.childPending != nil && i.childPending.config.RekeySPI == oldLocalSPI {
		r.Pending = true
		return r, nil
	}
	var candidates []*childSA
	for _, child := range i.children {
		if child.predecessor == oldLocalSPI {
			candidates = append(candidates, child)
		}
	}
	if len(candidates) == 0 || len(candidates) > 2 {
		return r, fmt.Errorf("ike: no unique CHILD rekey resolution")
	}
	survivor := candidates[0]
	if len(candidates) == 2 {
		other := candidates[1]
		comparison := compareRekeyNonce(survivor.minimumNonce, other.minimumNonce)
		if comparison == 0 {
			return r, fmt.Errorf("ike: equal rekey nonces; replace IKE SA")
		}
		if comparison < 0 {
			survivor, other = other, survivor
		}
		r.RedundantSPI = other.result.InitiatorSPI
		if other.localInitiated {
			r.DeleteSPI = r.RedundantSPI
		}
	}
	r.SurvivingSPI = survivor.result.InitiatorSPI
	if survivor.localInitiated {
		r.DeleteSPI = oldLocalSPI
	}
	return r, nil
}
