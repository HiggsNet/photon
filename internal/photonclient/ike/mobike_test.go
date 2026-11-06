package ike

import (
	"bytes"
	"net/netip"
	"testing"
	"time"
)

func TestMOBIKEProbeAndUpdateUseAuthenticatedExchange(t *testing.T) {
	i, _, responder, _, auth := authFixture(t)
	i.auth.mobike = true
	result, err := i.HandleAuthResponse(authResponse(t, i, responder, append(auth, mobilityNotify(notifyMOBIKESupported, nil)), nil))
	if err != nil || !result.MOBIKE {
		t.Fatalf("negotiate MOBIKE: %v, %v", result, err)
	}
	local := netip.MustParseAddrPort("192.0.2.1:32000")
	gateway := netip.MustParseAddrPort("198.51.100.1:4500")
	observed := netip.MustParseAddrPort("203.0.113.1:41000")
	spiI, spiR := i.SPIs()
	nat := []Payload{
		natPayload(NotifyNATDetectionSource, spiI, spiR, gateway),
		natPayload(NotifyNATDetectionDestination, spiI, spiR, observed),
	}
	reply := func(id uint32, ps []Payload) (*ExchangeResult, error) {
		t.Helper()
		message, err := i.DecodeExchange(peerInformation(t, i, id, true, ps, nil), time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return i.HandleExchange(message, nil)
	}
	if _, err := i.MOBIKERequest(local, gateway, false); err != nil {
		t.Fatal(err)
	}
	if got, err := reply(2, nat); err != nil || !got.NATChanged || got.MOBIKEUpdated {
		t.Fatalf("first NATed probe: %+v, %v", got, err)
	}
	update, err := i.MOBIKERequest(local, gateway, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reply(3, nat); err == nil || !bytes.Equal(update, i.PendingRequest()) {
		t.Fatal("response without COOKIE2 consumed the update")
	}
	ack := append(nat, mobilityNotify(notifyCookie2, i.mobikeCookie))
	if got, err := reply(3, ack); err != nil || !got.MOBIKEUpdated || got.NATChanged {
		t.Fatalf("MOBIKE response: %+v, %v", got, err)
	}
	if _, err := i.MOBIKERequest(local, gateway, false); err != nil {
		t.Fatal(err)
	}
	if got, err := reply(4, nat); err != nil || got.NATChanged {
		t.Fatalf("unchanged mapping: %+v, %v", got, err)
	}
}
