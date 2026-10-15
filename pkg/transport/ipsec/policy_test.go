package ipsec

import (
	"testing"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

func TestParseMeshPolicyRuleZoneGlob(t *testing.T) {
	rule, err := ParseMeshPolicyRule("strongswan://*.catofes.?role=in&family=dual&source=manual-dns,discovery&mode=family-redundant&max_peers=32")
	if err != nil {
		t.Fatalf("ParseMeshPolicyRule: %v", err)
	}
	if rule.Provider != ProviderStrongSwan || rule.ZonePattern != "*.catofes." {
		t.Fatalf("rule target = %+v", rule)
	}
	if rule.PeerRole != RoleIn || rule.Family != RuleFamilyDual || rule.PathMode != PathModeFamilyRedundant {
		t.Fatalf("rule predicates = %+v", rule)
	}
	if len(rule.Sources) != 2 || rule.Sources[0] != SourceManualDNS || rule.Sources[1] != SourceDiscovery {
		t.Fatalf("sources = %+v", rule.Sources)
	}
	if rule.MaxPeers != 32 {
		t.Fatalf("MaxPeers = %d, want 32", rule.MaxPeers)
	}
	if !rule.MatchesZone("node-a.catofes.") || rule.MatchesZone("node-a.example.") {
		t.Fatalf("zone match failed")
	}
}

func TestParseMeshPolicyRuleRoleAndTagTargets(t *testing.T) {
	role, err := ParseMeshPolicyRule("strongswan://role=edge?role=both&family=ipv6")
	if err != nil {
		t.Fatalf("Parse role rule: %v", err)
	}
	if role.Role != "edge" || role.Tag != "" || role.ZonePattern != "" {
		t.Fatalf("role rule = %+v", role)
	}
	tag, err := ParseMeshPolicyRule("strongswan://tag=lab")
	if err != nil {
		t.Fatalf("Parse tag rule: %v", err)
	}
	if tag.Tag != "lab" || tag.Role != "" || tag.ZonePattern != "" {
		t.Fatalf("tag rule = %+v", tag)
	}
}

func TestParseMeshPolicyRuleRejectsDeprecatedDirection(t *testing.T) {
	if _, err := ParseMeshPolicyRule("strongswan://*.catofes.?direction=outbound"); err == nil {
		t.Fatalf("expected error for deprecated direction query")
	}
}

func TestParseMeshPolicyRuleRejectsDeprecatedAccept(t *testing.T) {
	if _, err := ParseMeshPolicyRule("strongswan://*.catofes.?accept=inbound"); err == nil {
		t.Fatalf("expected error for deprecated accept query")
	}
}

func TestParseMeshPolicyRuleRejectsUnsupportedValues(t *testing.T) {
	for _, raw := range []string{
		"wireguard://*.catofes.",
		"strongswan://*.catofes.?role=maybe",
		"strongswan://*.catofes.?family=ipv10",
		"strongswan://*.catofes.?source=magic",
		"strongswan://*.catofes.?max_peers=-1",
		"strongswan://role=",
	} {
		if _, err := ParseMeshPolicyRule(raw); err == nil {
			t.Fatalf("ParseMeshPolicyRule(%q) should fail", raw)
		}
	}
}

func TestMeshPolicyRuleSharedZoneGlobCompatibility(t *testing.T) {
	for _, tc := range []struct {
		pattern, peer string
		want          bool
	}{
		{"gateway.catofes.", "gateway.catofes.", true},
		{"*", "gateway.catofes.", true},
		{"*.catofes.", "gateway.catofes.", true},
		{"*.catofes.", "gateway.other.", false},
		{"gateway-?.catofes.", "gateway-a.catofes.", true},
		{"gateway-[ab].catofes.", "gateway-b.catofes.", true},
		{"gateway-[ab].catofes.", "gateway-c.catofes.", false},
		{".*", "gateway.catofes.", false},
		{"[", "gateway.catofes.", false},
	} {
		rule := MeshPolicyRule{ZonePattern: tc.pattern}
		if got := rule.MatchesZone(zone.ZonePath(tc.peer)); got != tc.want {
			t.Errorf("pattern %q peer %q = %v, want %v", tc.pattern, tc.peer, got, tc.want)
		}
	}
}
