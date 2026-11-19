package trusttunnel

import (
	"bytes"
	"encoding/hex"
	"net/netip"
	"testing"
)

func TestUDPWireFormat(t *testing.T) {
	const source = "0000000000000000000000007f000001c350"
	const destination = "20010db80000000000000000000000010035"
	packet := Datagram{
		Source:      netip.MustParseAddrPort("127.0.0.1:50000"),
		Destination: netip.MustParseAddrPort("[2001:db8::1]:53"),
		Payload:     []byte{0xab, 0xcd},
	}
	request, _ := hex.DecodeString("00000027" + source + destination + "00abcd")
	response, _ := hex.DecodeString("00000026" + source + destination + "abcd")
	withApp, _ := hex.DecodeString("0000002a" + source + destination + "03646e73abcd")
	var wire bytes.Buffer
	if err := WriteRequest(&wire, packet); err != nil || !bytes.Equal(wire.Bytes(), request) {
		t.Fatalf("request wire = %x, %v", wire.Bytes(), err)
	}
	wire.Reset()
	if err := WriteResponse(&wire, packet); err != nil || !bytes.Equal(wire.Bytes(), response) {
		t.Fatalf("response wire = %x, %v", wire.Bytes(), err)
	}
	gotRequest, err := ReadRequest(bytes.NewReader(withApp))
	if err != nil || gotRequest.Source != packet.Source || gotRequest.Destination != packet.Destination || !bytes.Equal(gotRequest.Payload, packet.Payload) {
		t.Fatalf("read request with application label = %+v, %v", gotRequest, err)
	}
	gotResponse, err := ReadResponse(&wire)
	if err != nil || gotResponse.Source != packet.Source || gotResponse.Destination != packet.Destination || !bytes.Equal(gotResponse.Payload, packet.Payload) {
		t.Fatalf("read response = %+v, %v", gotResponse, err)
	}
	if _, err := ReadRequest(bytes.NewReader([]byte{0xff, 0xff, 0xff, 0xff})); err == nil {
		t.Fatal("oversize frame was accepted")
	}
}
