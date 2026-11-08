package gossip

import (
	"bytes"
	"net"
	"testing"

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
