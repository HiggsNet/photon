package inspect_test

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

func TestZonesResponsePreservesCanonicalZoneSummarySchema(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	authority := &zone.ZoneAuthority{
		Zone:      "node-b.catofes.",
		Epoch:     3,
		Threshold: 1,
		Keys:      []zone.AuthorizedKey{{Key: pub}},
	}
	ns := &zone.NetworkState{Zones: map[zone.ZonePath]*zone.ZoneState{
		"zeta.other.":            zone.NewZoneState("zeta.other.", nil),
		"node-b.catofes.":        zone.NewZoneState("node-b.catofes.", authority),
		"branch.node-b.catofes.": zone.NewZoneState("branch.node-b.catofes.", nil),
	}}
	ns.Zones["node-b.catofes."].Records["identity"] = &zone.Record{Key: "identity"}
	ns.Zones["node-b.catofes."].Delegations["child.node-b.catofes."] = &zone.Delegation{}
	ns.Zones["node-b.catofes."].Revocations["old.node-b.catofes."] = &zone.DelegationRevocation{}

	got := inspect.BuildZonesView(ns, time.Unix(100, 0))
	var paths []string
	for _, item := range got.Zones {
		paths = append(paths, item.Path)
	}
	want := []string{"node-b.catofes.", "branch.node-b.catofes.", "zeta.other."}
	if fmt.Sprint(paths) != fmt.Sprint(want) {
		t.Fatalf("paths = %v, want %v", paths, want)
	}
	if got.GlobalRoot == "" {
		t.Fatalf("global root should be present: %+v", got)
	}
	node := got.Zones[0]
	if node.Records != 1 || node.Delegations != 1 || node.Revocations != 1 || node.RootHashHex == "" {
		t.Fatalf("node summary = %+v", node)
	}
	data, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if decoded["global_root"] == "" || decoded["zones"] == nil {
		t.Fatalf("decoded response missing fields: %#v", decoded)
	}
}
