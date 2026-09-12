package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"reflect"
	"testing"
	"time"

	photonlinux "github.com/HiggsNet/photon/internal/photonlinux"
	"github.com/HiggsNet/photon/pkg/health"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestSummarizeIPsecReconcileDropsPrivateMaterialAndSpecPointers(t *testing.T) {
	privateKey := []byte("observation-private-key-sentinel")
	spec := ipsec.TransportLinkSpec{
		PeerZone:                 "node-b.catofes.",
		OverlayID:                "main",
		LinkID:                   "link-b",
		TransportID:              "ipsec-main-b",
		LocalPrivateKey:          privateKey,
		LocalPrivateKeyAlgorithm: "private-algorithm-sentinel",
	}
	summary := summarizeIPsecReconcile(7, 1000, []ipsec.TransportLinkSpec{spec}, nil, []ipsec.ReconcileAction{{
		Action: "create",
		Spec:   &spec,
	}}, nil, nil)

	payload, err := json.Marshal(summary)
	if err != nil {
		t.Fatalf("marshal observation summary: %v", err)
	}
	for _, forbidden := range [][]byte{
		[]byte(base64.StdEncoding.EncodeToString(privateKey)),
		[]byte(spec.LocalPrivateKeyAlgorithm),
	} {
		if bytes.Contains(payload, forbidden) {
			t.Fatalf("observation contains private transport material: %s", payload)
		}
	}
	if len(summary.Desired) != 1 || summary.Desired[0].PeerZone != spec.PeerZone {
		t.Fatalf("desired observation = %#v", summary.Desired)
	}
	if len(summary.Actions) != 1 || summary.Actions[0].InstanceID != ipsec.LinkInstanceID(spec) {
		t.Fatalf("action observation = %#v", summary.Actions)
	}
}

func TestLocalIPsecPortGenerationsIncludesValidPrevious(t *testing.T) {
	now := time.Unix(1717171717, 0)
	verified, _, _, _ := buildTestABVerifiedStates(t)
	local := verified.Network.Zones[verified.ManagedZone]
	addTestIPsecRecords(t, local, verified.ManagedZone, now, ipsec.RoleBoth)
	local.Records[ipsec.RecordKeyPorts] = unsignedIPsecRecord(t, verified.ManagedZone, ipsec.RecordKeyPorts, ipsec.RecordTypePorts, ipsec.PortRecord{
		Version: 1,
		Mode:    ipsec.PortModeFixed,
		Current: &ipsec.PortSelection{
			Generation: 2,
			IKE:        ipsec.PortBinding{Advertised: ipsec.DefaultIKEPort},
			NATT:       ipsec.PortBinding{Advertised: ipsec.DefaultNATTPort},
			ValidUntil: now.Add(time.Hour).Unix(),
		},
		Previous: []ipsec.PortSelection{
			{Generation: 1, IKE: ipsec.PortBinding{Advertised: ipsec.DefaultIKEPort}, NATT: ipsec.PortBinding{Advertised: ipsec.DefaultNATTPort}, ValidUntil: now.Add(time.Minute).Unix()},
			{Generation: 3, IKE: ipsec.PortBinding{Advertised: ipsec.DefaultIKEPort}, NATT: ipsec.PortBinding{Advertised: ipsec.DefaultNATTPort}, ValidUntil: now.Add(-time.Minute).Unix()},
		},
		UpdatedAt: now.Unix(),
	})
	if got, want := ipsecPortGenerations(verified, verified.ManagedZone, now), []uint64{2, 1}; !reflect.DeepEqual(got, want) {
		t.Fatalf("local generations = %v, want %v", got, want)
	}
}

func TestXFRMLinkStateMatchesCandidateRequiresLocalTunnelAddress(t *testing.T) {
	spec := ipsec.TransportLinkSpec{
		InterfaceName:   "phx1",
		LocalTunnelAddr: netip.MustParseAddr("fe80::1234"),
	}
	state := ipsec.XFRMLinkState{
		NamespaceExists: true,
		InterfaceExists: true,
		Addresses:       []netip.Prefix{netip.MustParsePrefix("fe80::9999/64")},
	}
	if matches, _ := photonlinux.XFRMLinkStateMatchReason(state, spec); matches {
		t.Fatalf("candidate matched with wrong interface address")
	}
	state.Addresses = []netip.Prefix{netip.MustParsePrefix("fe80::1234/64")}
	if matches, _ := photonlinux.XFRMLinkStateMatchReason(state, spec); !matches {
		t.Fatalf("candidate did not match expected interface address")
	}
}

func TestXFRMLinkStateMatchesCandidateRequiresKnownInterfaceFlags(t *testing.T) {
	spec := ipsec.TransportLinkSpec{
		InterfaceName:   "phx1",
		LocalTunnelAddr: netip.MustParseAddr("fe80::1234"),
	}
	state := ipsec.XFRMLinkState{
		NamespaceExists: true,
		InterfaceExists: true,
		FlagsKnown:      true,
		InterfaceUp:     true,
		Multicast:       false,
		Addresses:       []netip.Prefix{netip.MustParsePrefix("fe80::1234/64")},
	}
	if matches, _ := photonlinux.XFRMLinkStateMatchReason(state, spec); matches {
		t.Fatalf("candidate matched without multicast enabled")
	}
	state.Multicast = true
	if matches, _ := photonlinux.XFRMLinkStateMatchReason(state, spec); !matches {
		t.Fatalf("candidate did not match with expected flags and address")
	}
	state.InterfaceUp = false
	if matches, _ := photonlinux.XFRMLinkStateMatchReason(state, spec); matches {
		t.Fatalf("candidate matched while interface was not up")
	}
}

func TestIPsecQualityAddrPortMatchesOnlySamePortGeneration(t *testing.T) {
	current := ipsec.PortAdvertisement{
		Generation: 3,
		IKE:        ipsec.PortBinding{Advertised: 30004},
		NATT:       ipsec.PortBinding{Advertised: 33403},
		Current:    true,
	}
	previous := ipsec.PortAdvertisement{
		Generation: 1,
		IKE:        ipsec.PortBinding{Advertised: 500},
		NATT:       ipsec.PortBinding{Advertised: 4500},
		Current:    false,
	}

	if !ipsecQualityAddrPortMatches(33403, current) {
		t.Fatalf("current NAT-T port did not match current generation")
	}
	if ipsecQualityAddrPortMatches(33403, previous) {
		t.Fatalf("current NAT-T port matched previous generation")
	}
	if ipsecQualityAddrPortMatches(0, current) {
		t.Fatalf("zero port matched IPsec contact quality")
	}
}

func TestDaemonIPsecRotateCutoverReadyUsesHealthManager(t *testing.T) {
	now := time.Unix(1717171717, 0)
	manager := health.NewManager(health.DefaultProbeConfig(), health.DefaultHysteresisConfig(), nil)
	manager.SetTargets([]health.ProbeTarget{{
		ProbeID:         "link-1#staged",
		InstanceID:      "link-1",
		InterfaceName:   "phxstage",
		PeerTunnelAddr:  netip.MustParseAddr("fe80::2"),
		LocalTunnelAddr: netip.MustParseAddr("fe80::1"),
		State:           ipsec.LinkStateUp,
		Staged:          true,
		ProbeRole:       "staged",
	}}, now)

	got := (&Daemon{health: &healthDriver{Manager: manager}}).ipsecRotateCutoverReady()
	if ready, ok := got["link-1"]; !ok || ready {
		t.Fatalf("cutover readiness = %#v, want link-1=false while staged health is unknown", got)
	}
	if got := (&Daemon{}).ipsecRotateCutoverReady(); got != nil {
		t.Fatalf("nil health readiness = %#v, want nil", got)
	}
}
