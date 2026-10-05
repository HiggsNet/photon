//go:build linux

package photonwindows

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

// This fixture runs only inside the disposable Docker network namespace. The
// shell owns container teardown; credentials and SAs intentionally survive this
// setup test so the Windows binary can exercise the remote responder afterward.
func TestPrepareWindowsTunnelCrossHost(t *testing.T) {
	path := os.Getenv("PHOTON_WINDOWS_TUNNEL_PREPARE")
	if path == "" {
		t.Skip("isolated Windows tunnel cross-host fixture")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("fixture requires its disposable container")
	}
	gateway := os.Getenv("PHOTON_WINDOWS_TUNNEL_GATEWAY")
	if address, err := netip.ParseAddr(gateway); err != nil || !address.Is4() {
		t.Fatal("invalid fixture host address")
	}
	parsePort := func(name string) uint16 {
		n, err := strconv.ParseUint(os.Getenv(name), 10, 16)
		if err != nil || n == 0 {
			t.Fatal("invalid fixture port")
		}
		return uint16(n)
	}
	ikePort, nattPort := parsePort("PHOTON_WINDOWS_TUNNEL_IKE_PORT"), parsePort("PHOTON_WINDOWS_TUNNEL_NATT_PORT")
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	vici, err := ipsec.NewGoviciClient("/tmp/ike-auth.vici")
	if err != nil {
		t.Fatal(err)
	}
	defer vici.Close()
	driver := &ipsec.StrongSwanDriver{VICI: vici}
	serverPublic, serverPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientPublic, clientPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(serverPrivate)
	defer clear(clientPrivate)
	serverDER, err := x509.MarshalPKCS8PrivateKey(serverPrivate)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(serverDER)
	clientDER, err := x509.MarshalPKIXPublicKey(clientPublic)
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"link", "add", "phwincross", "type", "xfrm", "if_id", "524249"}, {"link", "set", "phwincross", "up"}, {"addr", "add", "10.55.4.1/32", "dev", "phwincross"}, {"route", "add", "10.55.4.2/32", "dev", "phwincross"}} {
		if output, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("isolated XFRM fixture: %v %s", err, output)
		}
	}
	const name = "photon-windows-cross-host"
	if err := driver.LoadPrivateKey(ctx, name, serverDER, ipsec.AlgorithmEd25519); err != nil {
		t.Fatal(err)
	}
	spec := ipsec.TransportLinkSpec{TransportID: name, LocalZone: "cross-gateway.photon.test.", PeerZone: "cross-windows.photon.test.", LocalAddress: "0.0.0.0", XFRMIfID: 524249, LocalTunnelAddr: netip.MustParseAddr("10.55.4.1"), PeerTunnelAddr: netip.MustParseAddr("10.55.4.2"), LocalPrivateKey: serverDER, LocalPrivateKeyAlgorithm: ipsec.AlgorithmEd25519, PeerPublicKey: clientDER}
	if err := driver.LoadConnection(ctx, spec); err != nil {
		t.Fatal(err)
	}
	config := windowsTunnelCrossConfig{Gateway: gateway, IKEPort: ikePort, NATTPort: nattPort, GatewayID: string(spec.LocalZone), LocalID: string(spec.PeerZone), GatewayPublicKey: serverPublic, PrivateKey: clientPrivate}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Log("isolated production StrongSwan responder and temporary Windows credential file ready")
}
