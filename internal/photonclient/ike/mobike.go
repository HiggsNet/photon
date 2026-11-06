package ike

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"net/netip"
)

const (
	notifyMOBIKESupported       uint16 = 16396
	notifyAdditionalIPv4Address uint16 = 16397
	notifyAdditionalIPv6Address uint16 = 16398
	notifyNoAdditionalAddresses uint16 = 16399
	notifyUpdateSAAddresses     uint16 = 16400
	notifyCookie2               uint16 = 16401
)

func mobilityNotify(kind uint16, data []byte) Payload {
	body, _ := EncodeNotify(Notify{Type: kind, Data: data})
	return Payload{Type: PayloadNotify, Data: body}
}

// MOBIKERequest probes the current path with NAT detection, or explicitly
// migrates the SA to a new local path to the same authorized gateway.
func (i *Initiator) MOBIKERequest(local, remote netip.AddrPort, update bool) ([]byte, error) {
	if !i.mobike || i.init == nil || !validNATEndpoint(local) || !validNATEndpoint(remote) ||
		local.Addr().Unmap().Is4() != remote.Addr().Unmap().Is4() {
		return nil, fmt.Errorf("ike: invalid MOBIKE request")
	}
	ps := []Payload{
		natPayload(NotifyNATDetectionSource, i.spi, i.init.ResponderSPI, local),
		natPayload(NotifyNATDetectionDestination, i.spi, i.init.ResponderSPI, remote),
	}
	kind := exchangeMOBIKEProbe
	var cookie []byte
	if update {
		kind = exchangeMOBIKEUpdate
		cookie = make([]byte, 16)
		if _, err := rand.Read(cookie); err != nil {
			return nil, err
		}
		ps = append(ps, mobilityNotify(notifyUpdateSAAddresses, nil), mobilityNotify(notifyCookie2, cookie))
	}
	packet, err := i.beginExchange(ExchangeInformational, kind, ps)
	if err == nil {
		i.local, i.remote, i.mobikeCookie = local, remote, cookie
	}
	return packet, err
}

func (i *Initiator) handleMOBIKEResponse(m *ExchangeMessage, result *ExchangeResult) error {
	h, ps, _, err := i.openAuthenticated(m, ExchangeInformational)
	if err != nil {
		return err
	}
	nat, err := checkNAT(ps, h, i.local, i.remote)
	if err != nil {
		return err
	}
	if !nat.Checked {
		return fmt.Errorf("ike: missing MOBIKE NAT detection")
	}
	var destination, cookie []byte
	for _, p := range ps {
		if p.Type != PayloadNotify {
			return fmt.Errorf("ike: unexpected MOBIKE response payload %d", p.Type)
		}
		n, _ := DecodeNotify(p.Data) // checkNAT already validated notification framing.
		switch n.Type {
		case NotifyNATDetectionSource:
		case NotifyNATDetectionDestination:
			destination = n.Data
		case notifyCookie2:
			if cookie != nil || len(n.SPI) != 0 || len(n.Data) == 0 {
				return fmt.Errorf("ike: malformed MOBIKE COOKIE2")
			}
			cookie = n.Data
		default:
			return fmt.Errorf("ike: unexpected MOBIKE response notification %d", n.Type)
		}
	}
	if !bytes.Equal(cookie, i.mobikeCookie) {
		return fmt.Errorf("ike: mismatched MOBIKE COOKIE2")
	}
	result.MOBIKEUpdated = i.exchanges.pendingKind == exchangeMOBIKEUpdate
	// The first probe might arrive after a silent mapping change. A NATed
	// first probe requests one explicit update to establish a known baseline.
	result.NATChanged = !result.MOBIKEUpdated && !bytes.Equal(i.mobikeNAT, destination) &&
		(len(i.mobikeNAT) != 0 || nat.Local)
	result.Liveness = true
	i.mobikeNAT = bytes.Clone(destination)
	i.mobikeCookie = nil
	i.completeExchange()
	return nil
}

func hasMOBIKEPathRequest(ps []Payload) bool {
	for _, p := range ps {
		if p.Type == PayloadNotify {
			n, err := DecodeNotify(p.Data)
			if err != nil {
				continue
			}
			switch n.Type {
			case notifyAdditionalIPv4Address, notifyAdditionalIPv6Address, notifyNoAdditionalAddresses,
				notifyCookie2, NotifyNATDetectionSource, NotifyNATDetectionDestination:
				return true
			}
		}
	}
	return false
}

// Gateway address advertisements are acknowledged without replacing signed
// Photon contacts. Only the client may request a migration in this profile.
func (i *Initiator) replyMOBIKEPathRequest(m *ExchangeMessage) ([]byte, error) {
	h, ps, cached, err := i.openAuthenticated(m, ExchangeInformational)
	if err != nil || cached != nil {
		return cached, err
	}
	var reply []Payload
	var natRequested bool
	for _, p := range ps {
		if p.Type != PayloadNotify {
			return nil, fmt.Errorf("ike: unexpected MOBIKE request payload %d", p.Type)
		}
		n, err := DecodeNotify(p.Data)
		if err != nil || len(n.SPI) != 0 {
			return nil, fmt.Errorf("ike: malformed MOBIKE notification")
		}
		switch n.Type {
		case notifyAdditionalIPv4Address, notifyAdditionalIPv6Address, notifyNoAdditionalAddresses:
		case notifyCookie2:
			if len(n.Data) < 8 || len(n.Data) > 64 {
				return nil, fmt.Errorf("ike: invalid MOBIKE COOKIE2 length")
			}
			reply = append(reply, mobilityNotify(notifyCookie2, n.Data))
		case NotifyNATDetectionSource, NotifyNATDetectionDestination:
			natRequested = true
		default:
			return nil, fmt.Errorf("ike: unsupported MOBIKE request notification %d", n.Type)
		}
	}
	if natRequested {
		nat, err := checkNAT(ps, h, i.local, i.remote)
		if err != nil {
			return nil, err
		}
		if !nat.Checked || !validNATEndpoint(i.remote) {
			return nil, fmt.Errorf("ike: missing MOBIKE response endpoints")
		}
		reply = append(reply, natPayload(NotifyNATDetectionSource, h.InitiatorSPI, h.ResponderSPI, i.local),
			natPayload(NotifyNATDetectionDestination, h.InitiatorSPI, h.ResponderSPI, i.remote))
	}
	return i.replyExchange(m.identity, h, reply)
}
