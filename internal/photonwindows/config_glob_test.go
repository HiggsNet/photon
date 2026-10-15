package photonwindows

import (
	"reflect"
	"strings"
	"testing"

	"github.com/HiggsNet/photon/pkg/core/zone"
	"gopkg.in/yaml.v3"
)

func configWithGatewaySelectors(patterns []string, peer string) string {
	var lines []string
	for _, pattern := range patterns {
		lines = append(lines, "    - '"+strings.ReplaceAll(pattern, "'", "''")+"'")
	}
	text := strings.Replace(validConfigYAML(), "    - gateway-a.catofes.", strings.Join(lines, "\n"), 1)
	if peer == "" {
		return strings.Replace(text, "  bootstrap_hints:\n    - peer: gateway-a.catofes.\n      address: gateway.example.net:33434\n", "", 1)
	}
	return strings.Replace(text, "peer: gateway-a.catofes.", "peer: '"+strings.ReplaceAll(peer, "'", "''")+"'", 1)
}

func TestParseConfigGatewayZoneGlobsAndConcreteBootstrap(t *testing.T) {
	for _, tc := range []struct {
		name      string
		selectors []string
		peer      string
	}{
		{"exact", []string{"gateway-a.catofes."}, "gateway-a.catofes."},
		{"all", []string{"*"}, "gateway-a.catofes."},
		{"subdomain", []string{"*.catofes."}, "gateway-a.catofes."},
		{"single-rune", []string{"gateway-?.catofes."}, "gateway-a.catofes."},
		{"character-class", []string{"gateway-[ab].catofes."}, "gateway-b.catofes."},
		{"any-selector", []string{"unmatched.example.", "*.catofes."}, "gateway-a.catofes."},
		{"trim", []string{" *.catofes. "}, " gateway-a.catofes. "},
		{"literal-dot-prefix", []string{".*"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config, err := ParseConfig(strings.NewReader(configWithGatewaySelectors(tc.selectors, tc.peer)))
			if err != nil {
				t.Fatal(err)
			}
			if len(config.Gateway.AllowedZones) != len(tc.selectors) {
				t.Fatal("selector list changed")
			}
			for i, selector := range tc.selectors {
				if string(config.Gateway.AllowedZones[i]) != strings.TrimSpace(selector) {
					t.Fatal("selector was expanded or changed during parsing")
				}
			}
			if tc.peer != "" && (len(config.Gateway.BootstrapHints) != 1 || string(config.Gateway.BootstrapHints[0].Peer) != strings.TrimSpace(tc.peer)) {
				t.Fatal("bootstrap identity was expanded or changed")
			}
		})
	}
}

func TestParseConfigGatewayGlobRejectsInvalidSelectorsAndNonConcreteHints(t *testing.T) {
	for _, tc := range []struct {
		name      string
		selectors []string
		peer      string
	}{
		{"root", []string{"."}, ""},
		{"literal-without-fqdn", []string{"gateway"}, ""},
		{"empty", []string{" "}, ""},
		{"bad-glob", []string{"["}, ""},
		{"bad-class", []string{"gateway-[ab.catofes."}, ""},
		{"bad-escape", []string{"gateway\\"}, ""},
		{"provider-not-selector", []string{"strongswan://*"}, ""},
		{"duplicate", []string{"*", " * "}, ""},
		{"unmatched", []string{"*.example."}, "gateway-a.catofes."},
		{"regex-is-not-glob", []string{".*"}, "gateway-a.catofes."},
		{"unmatched-class", []string{"gateway-[bc].catofes."}, "gateway-a.catofes."},
		{"hint-is-glob", []string{"*"}, "*.catofes."},
		{"hint-is-question", []string{"*"}, "gateway-?.catofes."},
		{"hint-is-class", []string{"*"}, "gateway-[ab].catofes."},
		{"hint-is-root", []string{"*"}, "."},
		{"hint-is-not-fqdn", []string{"*"}, "gateway"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseConfig(strings.NewReader(configWithGatewaySelectors(tc.selectors, tc.peer))); err == nil {
				t.Fatal("invalid selector/bootstrap accepted")
			}
		})
	}
}

func TestMarshalConfigPreservesQuotedWildcardSelectors(t *testing.T) {
	input := configWithGatewaySelectors([]string{"*", "*.catofes.", "gateway-[ab].catofes.", ".*"}, "gateway-a.catofes.")
	var options ConfigOptions
	if err := yaml.Unmarshal([]byte(input), &options); err != nil {
		t.Fatal(err)
	}
	data, err := MarshalConfig(options)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseConfig(strings.NewReader(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	want := []zone.ZonePath{"*", "*.catofes.", "gateway-[ab].catofes.", ".*"}
	if !reflect.DeepEqual(got.Gateway.AllowedZones, want) || got.Gateway.BootstrapHints[0].Peer != "gateway-a.catofes." {
		t.Fatal("YAML serialization lost selectors or changed the concrete bootstrap peer")
	}
	// An unquoted star is YAML alias syntax. Editors must serialize through the
	// schema owner so users never have to supply YAML quoting themselves.
	unquoted := strings.Replace(configWithGatewaySelectors([]string{"*"}, "gateway-a.catofes."), "- '*'", "- *", 1)
	if _, err := ParseConfig(strings.NewReader(unquoted)); err == nil {
		t.Fatal("unquoted YAML star unexpectedly accepted")
	}
}
