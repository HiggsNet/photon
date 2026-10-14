package gossip

import (
	"bytes"
	"net"
	"testing"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

func TestObjectPullRequestRoundTrip(t *testing.T) {
	req := &ObjectPullRequest{
		Type: ObjectPullZone,
		Zone: "catofes.",
	}
	data, err := EncodeObjectPullRequest(req)
	if err != nil {
		t.Fatalf("EncodeObjectPullRequest: %v", err)
	}
	if len(data) < 4 {
		t.Fatalf("data too short")
	}
	got, err := DecodeObjectPullRequest(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("DecodeObjectPullRequest: %v", err)
	}
	if got.Type != ObjectPullZone || got.Zone != "catofes." {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}

func TestObjectPullExchangeUsesCommonClientAndServerProtocol(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- ServeObjectPull(server, func(request *ObjectPullRequest) *ObjectPullResponse {
			if request.Type != ObjectPullZone || request.Zone != "catofes." {
				return &ObjectPullResponse{Error: "unexpected request"}
			}
			return &ObjectPullResponse{OK: true, Snapshot: &corestate.ZoneSnapshot{Zone: request.Zone}}
		})
	}()

	response, err := ExchangeObjectPull(client, &ObjectPullRequest{Type: ObjectPullZone, Zone: "catofes."})
	if err != nil {
		t.Fatalf("ExchangeObjectPull: %v", err)
	}
	if response == nil || !response.OK || response.Snapshot == nil || response.Snapshot.Zone != "catofes." {
		t.Fatalf("response = %#v", response)
	}
	if err := <-serveErr; err != nil {
		t.Fatalf("ServeObjectPull: %v", err)
	}
}

func TestObjectPullResponseRoundTrip(t *testing.T) {
	resp := &ObjectPullResponse{
		OK: true,
		Snapshot: &corestate.ZoneSnapshot{
			Zone: "catofes.",
			Authority: &zone.ZoneAuthority{
				Zone:      "catofes.",
				Epoch:     1,
				Threshold: 1,
			},
		},
	}
	data, err := EncodeObjectPullResponse(resp)
	if err != nil {
		t.Fatalf("EncodeObjectPullResponse: %v", err)
	}
	got, err := DecodeObjectPullResponse(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("DecodeObjectPullResponse: %v", err)
	}
	if !got.OK || got.Snapshot == nil || got.Snapshot.Zone != "catofes." {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}

func TestBuildObjectPullResponseUsesDetachedVerifiedObject(t *testing.T) {
	network := zone.NewNetworkState()
	path := zone.ZonePath("node-a.catofes.")
	state := zone.NewZoneState(path, &zone.ZoneAuthority{Zone: path, Epoch: 1, Threshold: 1})
	state.Records["endpoint"] = &zone.Record{Zone: path, Key: "endpoint", Type: "test.endpoint", Value: []byte("value"), Version: 1}
	network.Zones[path] = state
	store := corestate.NewStore(&corestate.VerifiedState{Network: network}, nil, nil)

	response := BuildObjectPullResponse(store, &ObjectPullRequest{Type: ObjectPullRecord, Zone: path, Key: "endpoint"}, time.Unix(100, 0))
	if !response.OK || response.Record == nil || response.Record.Record == nil {
		t.Fatalf("response = %#v", response)
	}
	response.Record.Record.Value[0] = 'X'
	again := BuildObjectPullResponse(store, &ObjectPullRequest{Type: ObjectPullRecord, Zone: path, Key: "endpoint"}, time.Unix(100, 0))
	if got := string(again.Record.Record.Value); got != "value" {
		t.Fatalf("response mutation leaked into verified state: %q", got)
	}
	if invalid := BuildObjectPullResponse(store, &ObjectPullRequest{Type: ObjectPullRecord, Zone: path}, time.Unix(100, 0)); invalid.OK || invalid.Error != "missing key" {
		t.Fatalf("invalid response = %#v", invalid)
	}
}

func TestObjectPullRejectsOversizedPayload(t *testing.T) {
	// Encode a length prefix pointing to 2 MiB, but provide no payload.
	var sizeBuf [4]byte
	sizeBuf[0] = 0x00
	sizeBuf[1] = 0x20
	sizeBuf[2] = 0x00
	sizeBuf[3] = 0x00 // 2 MiB
	_, err := DecodeObjectPullRequest(bytes.NewReader(sizeBuf[:]))
	if err == nil {
		t.Fatalf("expected error for oversized payload")
	}
}
