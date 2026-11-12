package ipsec

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"net/netip"
	"os"
	"testing"
	"time"
)

func TestStrongSwanDriverLoadsKeyAndConnection(t *testing.T) {
	if os.Getenv("PHOTON_IPSEC_XFRM_SMOKE") != "1" {
		t.Skip("set PHOTON_IPSEC_XFRM_SMOKE=1 to run the root/system StrongSwan smoke")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	client, err := NewGoviciClient(ctx, "")
	if err != nil {
		t.Fatalf("connect to charon VICI: %v", err)
	}
	defer client.Close()

	// Probe which key algorithm charon in this container can parse.
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	rsaDER, err := x509.MarshalPKCS8PrivateKey(rsaPriv)
	if err != nil {
		t.Fatalf("marshal rsa key: %v", err)
	}
	rsaPEM, err := PEMEncodePrivateKey(rsaDER)
	if err != nil {
		t.Fatalf("pem rsa key: %v", err)
	}
	_, err = client.Call(ctx, "load-key", map[string]any{
		"type": "rsa",
		"data": string(rsaPEM),
	})
	if err != nil {
		t.Fatalf("load rsa key: %v", err)
	}
	t.Logf("RSA load-key succeeded")

	localPriv, _, err := GenerateTransportKeyRecord(AlgorithmECDSAP256, time.Unix(4000, 0), 0)
	if err != nil {
		t.Fatalf("generate local key: %v", err)
	}
	_, peerRecord, err := GenerateTransportKeyRecord(AlgorithmECDSAP256, time.Unix(4000, 0), 0)
	if err != nil {
		t.Fatalf("generate peer key: %v", err)
	}
	peerPub, err := DecodeTransportPublicKey(*peerRecord)
	if err != nil {
		t.Fatalf("decode peer public key: %v", err)
	}

	driver := &StrongSwanDriver{VICI: client, KeyDir: t.TempDir()}
	transportID := "ipsec-strongswan-integration"
	if err := driver.LoadPrivateKey(ctx, transportID, localPriv.PrivateKey, localPriv.Algorithm); err != nil {
		t.Fatalf("LoadPrivateKey: %v", err)
	}

	spec := TransportLinkSpec{
		LocalZone:                "node-a.catofes.",
		PeerZone:                 "node-b.catofes.",
		OverlayID:                "main",
		Provider:                 ProviderStrongSwan,
		TransportID:              transportID,
		InitiatorRole:            InitiatorRolePrimary,
		PathMode:                 PathModeFamilyRedundant,
		IKEIdentity:              "node-a.catofes.",
		ContactPoints:            []ContactPoint{{Address: "127.0.0.1", IKEPort: DefaultIKEPort, NATTPort: DefaultNATTPort}},
		XFRMIfID:                 424242,
		InterfaceName:            "phxint0",
		LocalTunnelAddr:          mustAddr("10.55.0.1"),
		PeerTunnelAddr:           mustAddr("10.55.0.2"),
		NetNS:                    "",
		LocalPrivateKey:          localPriv.PrivateKey,
		LocalPrivateKeyAlgorithm: localPriv.Algorithm,
		PeerPublicKey:            peerPub,
	}

	if err := driver.LoadConnection(ctx, spec); err != nil {
		t.Fatalf("LoadConnection: %v", err)
	}

	sas, err := driver.ListSAs(ctx)
	if err != nil {
		t.Fatalf("ListSAs: %v", err)
	}
	t.Logf("ListSAs returned %d entries", len(sas))

	if err := driver.UnloadConnection(ctx, transportID); err != nil {
		t.Fatalf("UnloadConnection: %v", err)
	}
	if err := driver.UnloadPrivateKey(ctx, transportID); err != nil {
		t.Fatalf("UnloadPrivateKey: %v", err)
	}
}

func mustAddr(s string) netip.Addr {
	return netip.MustParseAddr(s)
}
