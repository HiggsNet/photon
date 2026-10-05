package ike

import (
	"encoding/binary"
	"fmt"
)

const (
	NotifyTemporaryFailure uint16 = 43
	NotifyChildNotFound    uint16 = 44
)

// ChildExchangeError is an authenticated peer refusal that completed the local
// exchange. Other errors leave it pending. TEMPORARY_FAILURE requires caller
// backoff. IKERekey selects the caller's IKE retry timer instead of its CHILD
// timer. RekeySPI retains the attempted CHILD predecessor even if a peer Delete
// already removed it; RemovedSPI names a stale CHILD removed by this refusal.
type ChildExchangeError struct {
	Notification uint16
	RemovedSPI   uint32
	RekeySPI     uint32
	IKERekey     bool
}

func (e *ChildExchangeError) Error() string {
	if e.IKERekey {
		return fmt.Sprintf("ike: IKE rekey refused with notification %d", e.Notification)
	}
	return fmt.Sprintf("ike: CHILD exchange refused with notification %d", e.Notification)
}

func childRefusal(ps []Payload, rekeySPI uint32) (*ChildExchangeError, error) {
	if len(ps) != 1 || ps[0].Type != PayloadNotify {
		return nil, nil
	}
	n, err := DecodeNotify(ps[0].Data)
	if err != nil {
		return nil, err
	}
	if n.Type >= 16384 {
		return nil, nil
	}
	switch n.Type {
	case NotifyChildNotFound:
		if rekeySPI == 0 || n.Protocol != 3 || len(n.SPI) != 4 || len(n.Data) != 0 || binary.BigEndian.Uint32(n.SPI) != rekeySPI {
			return nil, fmt.Errorf("ike: mismatched CHILD_SA_NOT_FOUND")
		}
	case 14, 38, NotifyTemporaryFailure: // NO_PROPOSAL_CHOSEN, TS_UNACCEPTABLE
		if len(n.SPI) != 0 || len(n.Data) != 0 {
			return nil, fmt.Errorf("ike: malformed CHILD refusal")
		}
	case 17: // INVALID_KE_PAYLOAD: do not silently downgrade; caller decides policy.
		if len(n.SPI) != 0 || len(n.Data) != 2 {
			return nil, fmt.Errorf("ike: malformed INVALID_KE_PAYLOAD")
		}
	default:
		return nil, fmt.Errorf("ike: unsupported CHILD error notification %d", n.Type)
	}
	return &ChildExchangeError{Notification: n.Type}, nil
}
