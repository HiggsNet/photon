package photonproxy

import (
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/service"
)

func TestEmbeddedClientChangesPathWithoutRebinding(t *testing.T) {
	origin := zone.ZonePath("desktop.catofes.")
	ctx := t.Context()
	manager := newRouteManager(ctx, nil, func(clientEntry) *v2Client { return &v2Client{} })
	manager.prepare = v2PrepareEntry(origin, true)
	defer manager.close()
	client := &EmbeddedClient{manager: manager, node: &v2Node{ctx: ctx,
		directory: &proxyDirectory{view: service.ProxyDirectory{ManagedZone: origin, ValidUntil: time.Now().Add(time.Minute)}},
	}}
	if _, err := client.Request(EmbeddedClientRequest{Action: "create", Name: "home", Hops: []string{"gateway@h2l4"}}); err != nil {
		t.Fatal(err)
	}
	before := client.Routes()
	if len(before) != 1 || before[0].Address != "127.0.0.1" || before[0].Port == 0 {
		t.Fatalf("unexpected local listeners %+v", before)
	}
	if _, err := client.Request(EmbeddedClientRequest{Action: "update", Name: "home", Hops: []string{"gateway@h2l6"}}); err != nil {
		t.Fatal(err)
	}
	after := client.Routes()
	if len(after) != 1 || after[0].Port != before[0].Port || after[0].Hops[0] != "gateway@h2l6" {
		t.Fatalf("changing hops changed the listener or left the old path %+v", after)
	}
	if _, err := client.Request(EmbeddedClientRequest{Action: "delete", Name: "home"}); err != nil || len(client.Routes()) != 0 {
		t.Fatalf("delete did not remove the route: %v", err)
	}
}
