package mihomoproxy

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/photonwindows"
)

func TestProfilePreservesUserPolicyAcrossOfflineTransition(t *testing.T) {
	template, err := ParseTemplate([]byte(`
external-controller: 0.0.0.0:1234
allow-lan: true
tun: {enable: true}
proxies:
  - {name: Ordinary, type: socks5, server: 192.0.2.1, port: 1080}
proxy-groups:
  - {name: East, type: select, use: [photon-services], filter: tokyo}
rule-providers:
  local: {type: inline, behavior: domain, payload: [example.test]}
rules:
  - DOMAIN,photon.example,East
  - RULE-SET,local,Ordinary
  - MATCH,DIRECT
`))
	if err != nil {
		t.Fatal(err)
	}
	listener := Listener{MixedPort: 7890, ControllerPort: 7891, Secret: "fixture"}
	now := time.Now()
	directory := &photonwindows.ServiceDirectory{
		AdapterName: "Photon Windows", ObservedAt: now, ValidUntil: now.Add(5 * time.Second),
		BypassPrefixes: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
		Services: []photonwindows.ServiceEntry{
			{Status: "active", Owner: "one.example.", Endpoints: []photonwindows.ServiceEndpoint{
				{Address: "fd00::5", Port: 1080, Region: "tokyo"},
			}},
			{Status: "withdrawn", Owner: "two.example.", Endpoints: []photonwindows.ServiceEndpoint{
				{Address: "192.0.2.2", Port: 1080, Region: "withdrawn"},
			}},
		},
	}
	live, online, err := template.Render(listener, directory, now)
	if err != nil || !online {
		t.Fatalf("live render: online=%t error=%v", online, err)
	}
	blocked, online, err := template.Render(listener, directory, directory.ValidUntil)
	if err != nil || online {
		t.Fatalf("expired render: online=%t error=%v", online, err)
	}
	for _, generated := range [][]byte{live, blocked} {
		for _, required := range []string{"127.0.0.1:7891", "allow-lan: false", "enable: false", "name: Ordinary", "filter: tokyo", "RULE-SET,local,Ordinary", "MATCH,DIRECT"} {
			if !bytes.Contains(generated, []byte(required)) {
				t.Fatalf("missing %q in:\n%s", required, generated)
			}
		}
		if bytes.Contains(generated, []byte("withdrawn")) || bytes.Contains(generated, []byte("0.0.0.0:1234")) {
			t.Fatalf("unusable endpoint or template listener escaped:\n%s", generated)
		}
	}
	if !bytes.Contains(live, []byte("interface-name: Photon Windows")) ||
		!bytes.Contains(live, []byte("IP-CIDR6,fd00::5/128,DIRECT,no-resolve")) ||
		bytes.Contains(blocked, []byte("fd00::5")) ||
		!bytes.Contains(blocked, []byte("type: reject")) {
		t.Fatalf("online/offline boundary incorrect:\n%s\n%s", live, blocked)
	}
}

func TestRejectUnsafeTemplateNamesAndMalformedRules(t *testing.T) {
	for _, yaml := range []string{
		"rules: [42]",
		"rules: [\"\"]",
		"rules: [\"MATCH,Photon\"]\n---\nrules: []",
		"rules: [\"MATCH,Photon\"]\nproxies: [{name: REJECT, type: direct}]",
		"rules: [\"MATCH,Photon\"]\nproxy-providers: {photon-services: {type: inline}}",
	} {
		if _, err := ParseTemplate([]byte(yaml)); err == nil {
			t.Fatalf("accepted invalid template: %s", strings.TrimSpace(yaml))
		}
	}
}
