package ike

import "fmt"

const ExchangeInformational uint8 = 37

// InformationalRequest begins one authenticated empty liveness exchange after
// IKE_AUTH. A timeout requires abandoning this SA; it must not free the pending
// slot or skip the unanswered message ID. Other exchange types share this slot.
func (i *Initiator) InformationalRequest() ([]byte, error) {
	return i.beginExchange(ExchangeInformational, exchangeLiveness, nil)
}

// PendingInformationalRequest returns the original encrypted empty liveness
// request or nil. PendingRequest also supports other post-AUTH exchange types.
func (i *Initiator) PendingInformationalRequest() []byte {
	if i.exchanges.pendingKind != exchangeLiveness {
		return nil
	}
	return i.PendingRequest()
}

// HandleInformational accepts authenticated empty INFORMATIONAL messages.
// A non-nil result is a reply to send; nil with no error completes the pending
// local liveness exchange. Invalid messages do not mutate the session.
func (i *Initiator) HandleInformational(packet []byte) ([]byte, error) {
	m, err := i.decodeSKExchange(packet)
	if err != nil {
		return nil, err
	}
	return i.handleInformational(m)
}

func (i *Initiator) handleInformational(m *ExchangeMessage) ([]byte, error) {
	h, ps, cached, err := i.openAuthenticated(m, ExchangeInformational)
	if err != nil {
		return nil, err
	}
	if len(ps) != 0 {
		return nil, fmt.Errorf("ike: nonempty INFORMATIONAL unsupported")
	}
	if h.Flags&FlagResponse != 0 {
		if i.exchanges.pendingKind != exchangeLiveness {
			return nil, fmt.Errorf("ike: pending exchange is not liveness")
		}
		i.completeExchange()
		return nil, nil
	}
	if cached != nil {
		return cached, nil
	}
	return i.replyExchange(m.identity, h, nil)
}
