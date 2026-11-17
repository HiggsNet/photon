package mihomoproxy

import (
	"strings"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/photonwindows"
)

func TestTrustTunnelProfileRequiresPinAndKeepsUDP(t *testing.T) {
	now := time.Now()
	endpoint := photonwindows.ServiceEndpoint{Type: "trusttunnel", Region: "local", Address: "fd42::22", Port: 4433, ServerName: "trusttunnel.node.catofes", Fingerprint: strings.Repeat("ab", 32)}
	directory := &photonwindows.ServiceDirectory{AdapterName: "Photon", ObservedAt: now, ValidUntil: now.Add(5 * time.Second), Services: []photonwindows.ServiceEntry{{Owner: "node.catofes.", Status: "active", Endpoints: []photonwindows.ServiceEndpoint{endpoint}}}}
	proxies, _, err := directoryConfig(directory, now)
	if err != nil || len(proxies) != 1 {
		t.Fatal(proxies, err)
	}
	p := proxies[0]
	if p["type"] != "trusttunnel" || p["quic"] != true || p["udp"] != true || p["fingerprint"] != endpoint.Fingerprint || p["sni"] != endpoint.ServerName || p["interface-name"] != "Photon" {
		t.Fatal(p)
	}
	if _, ok := p["skip-cert-verify"]; ok {
		t.Fatal("pin bypass")
	}
	directory.Services[0].Endpoints[0].Fingerprint = ""
	if _, _, err := directoryConfig(directory, now); err == nil {
		t.Fatal("missing pin accepted")
	}
	directory.Services[0].Status = "withdrawn"
	if p, _, err := directoryConfig(directory, now); err != nil || len(p) != 0 {
		t.Fatal("withdrawn endpoint survived", p, err)
	}
}

func TestHTTPProfileDoesNotInventAuthenticationOrUDP(t *testing.T) {
	now := time.Now()
	directory := &photonwindows.ServiceDirectory{AdapterName: "Photon", ObservedAt: now, ValidUntil: now.Add(time.Second), Services: []photonwindows.ServiceEntry{{Owner: "node.catofes.", Status: "active", Endpoints: []photonwindows.ServiceEndpoint{{Type: "http", Region: "local", Address: "fd42::21", Port: 3128}}}}}
	proxies, _, err := directoryConfig(directory, now)
	if err != nil || len(proxies) != 1 || proxies[0]["type"] != "http" || proxies[0]["udp"] != false {
		t.Fatal(proxies, err)
	}
	directory.Services[0].Endpoints[0].AuthRequired = true
	proxies, _, err = directoryConfig(directory, now)
	if err != nil || len(proxies) != 0 {
		t.Fatal("private HTTP credential was guessed", proxies, err)
	}
}
