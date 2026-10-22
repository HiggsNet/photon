package ike

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const NotifyCookie uint16 = 16390

// HandleInitCookie handles a stateless RFC 7296 section 2.6 challenge. The caller
// must validate the source endpoint and keep its original retry deadline. At
// most three cookie challenges are accepted per initiator, including duplicates.
// The nonce, DH key, initiator SPI and message ID are retained, and Request()
// becomes the exact retry transcript used by subsequent AUTH computation.
func (i *Initiator) HandleInitCookie(packet []byte) ([]byte, error) {
	if i.private == nil || i.init != nil || len(i.request) == 0 {
		return nil, fmt.Errorf("ike: no pending SA_INIT for COOKIE")
	}
	h, ps, err := DecodeMessage(packet)
	if err != nil {
		return nil, err
	}
	// RFC 7296 permits a nonzero responder SPI on an error response, but the
	// retried request must still use zero until a successful SA_INIT completes.
	if h.InitiatorSPI != i.spi || h.ExchangeType != ExchangeSAInit || h.MessageID != 0 || h.Flags&FlagResponse == 0 || h.Flags&FlagInitiator != 0 {
		return nil, fmt.Errorf("ike: COOKIE does not match pending SA_INIT")
	}
	var cookie []byte
	for _, p := range ps {
		if p.Type != PayloadNotify {
			if p.Type == PayloadVendor || (p.Type > 48 && !p.Critical) {
				continue
			}
			return nil, fmt.Errorf("ike: unexpected COOKIE response payload")
		}
		n, err := DecodeNotify(p.Data)
		if err != nil {
			return nil, err
		}
		if n.Type != NotifyCookie {
			return nil, fmt.Errorf("ike: response is not a COOKIE challenge")
		}
		if cookie != nil || n.Protocol != 0 || len(n.SPI) != 0 || len(n.Data) < 1 || len(n.Data) > 64 {
			return nil, fmt.Errorf("ike: invalid COOKIE notification")
		}
		cookie = bytes.Clone(p.Data)
	}
	if cookie == nil {
		return nil, fmt.Errorf("ike: missing COOKIE notification")
	}
	if i.cookieRetries >= 3 {
		return nil, fmt.Errorf("ike: COOKIE retry limit reached")
	}
	requestHeader, first, err := DecodeHeader(i.request)
	if err != nil {
		return nil, err
	}
	body := i.request[HeaderLen:]
	if first == PayloadNotify && len(body) >= 8 && binary.BigEndian.Uint16(body[6:]) == NotifyCookie {
		// Replace the prior leading COOKIE, never accumulate untrusted challenges.
		length := int(binary.BigEndian.Uint16(body[2:]))
		if length < 8 || length > len(body) {
			return nil, fmt.Errorf("ike: invalid pending COOKIE request")
		}
		first = body[0]
		body = body[length:]
	}
	_, prefix, err := EncodePayloads([]Payload{{Type: PayloadNotify, Data: cookie}})
	if err != nil {
		return nil, err
	}
	prefix[0] = first
	retry, err := requestHeader.Marshal(PayloadNotify, HeaderLen+len(prefix)+len(body))
	if err != nil {
		return nil, err
	}
	retry = append(retry, prefix...)
	retry = append(retry, body...)
	i.request = retry
	i.cookieRetries++
	return bytes.Clone(retry), nil
}
