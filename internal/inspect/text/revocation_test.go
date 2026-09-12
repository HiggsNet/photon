package text

import (
	"strings"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

func TestWriteRevocationImpactsNoRevokedZones(t *testing.T) {
	var buf strings.Builder
	if err := WriteRevocationImpacts(&buf, nil); err != nil {
		t.Fatalf("WriteRevocationImpacts: %v", err)
	}
	if got, want := buf.String(), "no revoked zones\n"; got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
}

func TestWriteRevocationImpactsOutput(t *testing.T) {
	impacts := []inspect.RevocationImpact{
		{
			RevokedZone:           "node-b.catofes.",
			SourceZone:            "catofes.",
			RevokedSubtree:        []zone.ZonePath{"leaf.node-b.catofes."},
			AffectedLinkInstances: []string{"link-1"},
			AffectedSyncPeers:     []string{"node-b.catofes."},
			ConfiguredButRevoked:  []string{"node-b.catofes."},
			AffectedIPAMPrefixes:  []string{"10.2.0.0/24"},
			Layers: map[string]*inspect.RevocationLayerStatus{
				inspect.RevocationLayerIPsec:    {Status: inspect.RevocationStatusRemoved, Reason: "teardown complete", UnixTime: time.Unix(5000, 0).Unix()},
				inspect.RevocationLayerRouting:  {Status: inspect.RevocationStatusRemoved},
				inspect.RevocationLayerFirewall: {Status: inspect.RevocationStatusRemoved},
				inspect.RevocationLayerGossip:   {Status: inspect.RevocationStatusError, Failure: &inspect.FailureView{Code: inspect.FailureCodeRevocationCleanup, Message: "cache busy"}},
			},
		},
	}

	var buf strings.Builder
	if err := WriteRevocationImpacts(&buf, impacts); err != nil {
		t.Fatalf("WriteRevocationImpacts: %v", err)
	}
	output := buf.String()
	required := []string{
		"revoked_zone: node-b.catofes.",
		"source_zone: catofes.",
		"affected_subtree:",
		"leaf.node-b.catofes.",
		"affected_link_instances:",
		"affected_sync_peers:",
		"configured_but_revoked:",
		"affected_ipam_prefixes:",
		"cleanup_layers:",
		"firewall:",
		"ipsec_xfrm:",
		"reason: teardown complete",
		"time: 1970-01-01T01:23:20Z",
		"failure: code=revocation_cleanup_failed message=cache busy",
	}
	for _, want := range required {
		if !strings.Contains(output, want) {
			t.Fatalf("output missing %q:\n%s", want, output)
		}
	}
}
