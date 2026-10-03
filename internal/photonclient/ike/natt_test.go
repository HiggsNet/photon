package ike

import (
	"bytes"
	"encoding/hex"
	"net/netip"
	"testing"
)

func TestNATDetectionHash(t *testing.T) {
	// Independently calculated with OpenSSL SHA1 over the literal SPI/address/port bytes.
	for _, tc := range []struct{ endpoint, hash string }{
		{"192.0.2.1:500", "d798d986143f878f70765e0e869c80bbc375f701"},
		{"[::ffff:192.0.2.1]:500", "d798d986143f878f70765e0e869c80bbc375f701"},
		{"[2001:db8::1]:4500", "1ee24423bf8f59515e0265c6d0f08be3d038f7e5"},
	} {
		got, err := NATDetectionHash(0x0102030405060708, 0x1112131415161718, netip.MustParseAddrPort(tc.endpoint))
		if err != nil || hex.EncodeToString(got) != tc.hash {
			t.Fatalf("%s: %x, %v", tc.endpoint, got, err)
		}
	}
	for _, endpoint := range []string{"0.0.0.0:500", "224.0.0.1:500", "192.0.2.1:0", "[::ffff:0.0.0.0]:500", "[::ffff:224.0.0.1]:500"} {
		if _, err := NATDetectionHash(1, 2, netip.MustParseAddrPort(endpoint)); err == nil {
			t.Fatalf("accepted %s", endpoint)
		}
	}
	if _, err := NewInitiatorWithEndpoints(netip.MustParseAddrPort("192.0.2.1:500"), netip.MustParseAddrPort("[2001:db8::1]:500")); err == nil {
		t.Fatal("mixed endpoints accepted")
	}
}

func TestInitiatorNATDetection(t *testing.T) {
	for _, family := range []struct{ local, remote string }{{"192.0.2.1:51234", "198.51.100.1:500"}, {"[2001:db8::1]:51234", "[2001:db8::2]:500"}} {
		for _, mode := range []string{"none", "local", "forced_remote", "both", "multiple_source", "ignored_protocol", "missing"} {
			t.Run(family.local+"/"+mode, func(t *testing.T) {
				local, remote := netip.MustParseAddrPort(family.local), netip.MustParseAddrPort(family.remote)
				i, err := NewInitiatorWithEndpoints(local, remote)
				if err != nil {
					t.Fatal(err)
				}
				h, ps, _ := DecodeMessage(i.Request())
				requestStatus, err := checkNAT(ps, h, remote, local) // Viewed by responder.
				if err != nil || !requestStatus.Checked || requestStatus.Required() {
					t.Fatalf("request NATD: %+v %v", requestStatus, err)
				}
				r := newResponderFixture(t, i)
				source := natPayload(NotifyNATDetectionSource, i.spi, r.header.ResponderSPI, remote)
				dest := natPayload(NotifyNATDetectionDestination, i.spi, r.header.ResponderSPI, local)
				if mode == "ignored_protocol" {
					source.Data[0], dest.Data[0] = 255, 99
				}
				if mode == "local" || mode == "both" {
					dest.Data[4] ^= 1
				}
				if mode == "forced_remote" || mode == "both" || mode == "multiple_source" {
					source.Data[4] ^= 1
				}
				if mode != "missing" {
					r.payloads = append(r.payloads, source, dest)
				}
				if mode == "multiple_source" {
					r.payloads = append(r.payloads, natPayload(NotifyNATDetectionSource, i.spi, r.header.ResponderSPI, remote))
				}
				packet, _ := EncodeMessage(r.header, r.payloads)
				result, err := i.HandleInitResponse(packet)
				if err != nil {
					t.Fatal(err)
				}
				want := NATStatus{Checked: mode != "missing", Local: mode == "local" || mode == "both", Remote: mode == "forced_remote" || mode == "both"}
				if result.NAT != want {
					t.Fatalf("got %+v, want %+v", result.NAT, want)
				}
				if !bytes.Equal(result.Response, packet) {
					t.Fatal("transcript changed")
				}
				result.NAT.Local = !result.NAT.Local
				if i.init.NAT != want {
					t.Fatal("result mutates session")
				}
			})
		}
	}
}

func TestNATMalformedDoesNotAdvance(t *testing.T) {
	for _, mode := range []string{"source_only", "dest_only", "duplicate_dest", "short_hash", "spi"} {
		t.Run(mode, func(t *testing.T) {
			local, remote := netip.MustParseAddrPort("192.0.2.1:500"), netip.MustParseAddrPort("192.0.2.2:500")
			i, _ := NewInitiatorWithEndpoints(local, remote)
			r := newResponderFixture(t, i)
			source := natPayload(NotifyNATDetectionSource, i.spi, r.header.ResponderSPI, remote)
			dest := natPayload(NotifyNATDetectionDestination, i.spi, r.header.ResponderSPI, local)
			ps := []Payload{source, dest}
			switch mode {
			case "source_only":
				ps = ps[:1]
			case "dest_only":
				ps = ps[1:]
			case "duplicate_dest":
				ps = append(ps, dest)
			case "short_hash":
				ps[0].Data = ps[0].Data[:len(ps[0].Data)-1]
			case "spi":
				ps[0].Data, _ = EncodeNotify(Notify{Type: NotifyNATDetectionSource, SPI: []byte{1}, Data: make([]byte, 20)})
			}
			bad, _ := EncodeMessage(r.header, append(append([]Payload(nil), r.payloads...), ps...))
			if _, err := i.HandleInitResponse(bad); err == nil {
				t.Fatal("invalid NATD accepted")
			}
			good, _ := EncodeMessage(r.header, append(r.payloads, source, dest))
			if _, err := i.HandleInitResponse(good); err != nil {
				t.Fatalf("invalid packet advanced session: %v", err)
			}
		})
	}
	// Legacy construction explicitly cannot detect NAT, even if the peer sends valid hashes.
	i, _ := NewInitiator()
	r := newResponderFixture(t, i)
	r.payloads = append(r.payloads, natPayload(NotifyNATDetectionSource, i.spi, r.header.ResponderSPI, netip.MustParseAddrPort("192.0.2.1:500")), natPayload(NotifyNATDetectionDestination, i.spi, r.header.ResponderSPI, netip.MustParseAddrPort("192.0.2.2:500")))
	packet, _ := EncodeMessage(r.header, r.payloads)
	result, err := i.HandleInitResponse(packet)
	if err != nil || result.NAT.Checked || result.NAT.Required() {
		t.Fatalf("legacy NAT result: %+v %v", result, err)
	}
}

func TestNATDatagrams(t *testing.T) {
	i, _ := NewInitiator()
	original := i.Request()
	wrapped, err := EncapsulateIKE(original)
	if err != nil {
		t.Fatal(err)
	}
	kind, body, err := ParseNATDatagram(wrapped)
	if err != nil || kind != NATDatagramIKE || !bytes.Equal(body, original) {
		t.Fatal("IKE framing failed", err)
	}
	wrapped[4] ^= 1
	if !bytes.Equal(i.Request(), original) {
		t.Fatal("marker changed transcript")
	}
	esp := []byte{0, 0, 0, 1, 0, 0, 0, 1}
	kind, body, err = ParseNATDatagram(esp)
	if err != nil || kind != NATDatagramESP || !bytes.Equal(body, esp) {
		t.Fatal("ESP framing failed", err)
	}
	kind, body, err = ParseNATDatagram([]byte{255})
	if err != nil || kind != NATDatagramKeepalive || body != nil {
		t.Fatal("keepalive framing failed", err)
	}
	for _, bad := range [][]byte{nil, {0}, {255, 0}, {0, 0, 0, 0}, {0, 0, 0, 1}, make([]byte, MaxMessageSize+1)} {
		if _, _, err := ParseNATDatagram(bad); err == nil {
			t.Fatalf("bad datagram accepted: length %d", len(bad))
		}
	}
	if _, err := EncapsulateIKE(nil); err == nil {
		t.Fatal("invalid IKE accepted")
	}
	oversize, _ := (Header{InitiatorSPI: 1}).Marshal(0, MaxMessageSize)
	oversize = append(oversize, make([]byte, MaxMessageSize-HeaderLen)...)
	if _, err := EncapsulateIKE(oversize); err == nil {
		t.Fatal("UDP overflow accepted")
	}
}

func FuzzNATDatagram(f *testing.F) {
	f.Add([]byte{255})
	f.Add([]byte{0, 0, 0, 1, 0, 0, 0, 1})
	i, _ := NewInitiator()
	packet, _ := EncapsulateIKE(i.Request())
	f.Add(packet)
	f.Fuzz(func(t *testing.T, b []byte) { _, _, _ = ParseNATDatagram(b) })
}
