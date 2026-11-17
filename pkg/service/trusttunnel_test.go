package service

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/routing"
)

func TestTrustTunnelRecordAuthorization(t *testing.T) {
	value := TrustTunnelRecord{Type: TypeTrustTunnel, Endpoints: []SOCKS5Endpoint{{Region: "local", Address: "fd42:1::22", Port: 4433}}, ServerName: "trusttunnel.node.catofes", Fingerprint: strings.Repeat("ab", 32)}
	encoded, _ := json.Marshal(value)
	record := &zone.Record{Zone: "node.catofes.", Key: "services/trusttunnel", Type: RecordTypeTrustTunnel, Value: encoded}
	parsed, err := ParseProxyRecord(record)
	if err != nil || parsed.Fingerprint != value.Fingerprint || !parsed.IsActive() {
		t.Fatal(parsed, err)
	}
	entry := &routing.AssignmentEntry{AssignedTo: record.Zone, Prefix: netip.MustParsePrefix("fd42:1::/64")}
	authorized := &routing.AuthorizedRouteSet{AllAssignments: []*routing.AssignmentEntry{entry}}
	if _, err := AuthorizeProxyRecord(record, authorized); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(){func() { entry.AssignedTo = "other.catofes." }, func() { entry.Shared = true }, func() { entry.Prefix = netip.MustParsePrefix("fd42:2::/64") }} {
		before := *entry
		change()
		if _, err := AuthorizeProxyRecord(record, authorized); err == nil {
			t.Fatal("invalid assignment accepted")
		}
		*entry = before
	}
	for _, change := range []func(*TrustTunnelRecord){func(r *TrustTunnelRecord) { r.Fingerprint = "" }, func(r *TrustTunnelRecord) { r.Fingerprint = strings.Repeat("AB", 32) }, func(r *TrustTunnelRecord) { r.ServerName = "a\nb" }, func(r *TrustTunnelRecord) {
		r.Endpoints = []SOCKS5Endpoint{{Region: "global", Address: "fd42:1::22", Port: 4433}}
	}} {
		r := value
		change(&r)
		if r.Validate() == nil {
			t.Fatal("invalid record accepted", r)
		}
	}
	record.Value = []byte(strings.TrimSuffix(string(encoded), "}") + `,"password":"secret"}`)
	if _, err := ParseProxyRecord(record); err == nil {
		t.Fatal("unknown credential field accepted")
	}
	record.Value = encoded
	if _, err := ParseSOCKS5Record(record); err == nil {
		t.Fatal("TrustTunnel reinterpreted as SOCKS5")
	}
	active := false
	value.Active = &active
	record.Value, _ = json.Marshal(value)
	if _, err := AuthorizeProxyRecord(record, authorized); err == nil {
		t.Fatal("withdrawn service authorized")
	}
}
