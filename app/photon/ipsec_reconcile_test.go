package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"reflect"
	"testing"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
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
	summary := summarizeIPsecReconcile(1000, []ipsec.TransportLinkSpec{spec}, nil, []ipsec.ReconcileAction{{
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

func TestCollectRevokedPeerZones(t *testing.T) {
	state, catofesPriv, _, _ := buildPeerStateTestOwners(t)
	now := time.Unix(2000, 0)

	// Before revocation: no revoked peers.
	revoked := collectRevokedPeerZones(state.verified.Network, state.observationLinks, state.checkpoint, now)
	if len(revoked) != 0 {
		t.Fatalf("expected 0 revoked zones, got %d", len(revoked))
	}

	// Add a LinkInstance for node-b.
	state.observationLinks["link-node-b"] = ipsec.LinkInstance{
		PeerZone: "node-b.catofes.",
	}
	// Add node-b to SyncPeers.
	state.checkpoint.Peers["node-b.catofes."] = corestate.PeerCheckpoint{}

	// Still no revoked zones.
	revoked = collectRevokedPeerZones(state.verified.Network, state.observationLinks, state.checkpoint, now)
	if len(revoked) != 0 {
		t.Fatalf("expected 0 revoked zones before revocation, got %d", len(revoked))
	}

	// Revoke node-b.
	addRevocationToParent(t, state.verified.Network, "catofes.", "node-b.catofes.", catofesPriv, now)

	// Now node-b should be in the revoked set (from both LinkInstances and SyncPeers).
	revoked = collectRevokedPeerZones(state.verified.Network, state.observationLinks, state.checkpoint, now)
	if !revoked["node-b.catofes."] {
		t.Fatalf("expected node-b.catofes. in revoked set, got %v", revoked)
	}
}

func TestRevokedLinkPeersIncludesSyncPeers(t *testing.T) {
	state, catofesPriv, _, _ := buildPeerStateTestOwners(t)
	now := time.Unix(2000, 0)

	// Add node-b to SyncPeers (no LinkInstance).
	state.checkpoint.Peers["node-b.catofes."] = corestate.PeerCheckpoint{}

	// Before revocation: no revoked peers.
	revoked := collectRevokedPeerZones(state.verified.Network, state.observationLinks, state.checkpoint, now)
	if len(revoked) != 0 {
		t.Fatalf("expected 0 revoked, got %d", len(revoked))
	}

	// Revoke node-b.
	addRevocationToParent(t, state.verified.Network, "catofes.", "node-b.catofes.", catofesPriv, now)

	// After revocation: node-b should be in revoked set even without LinkInstance.
	revoked = collectRevokedPeerZones(state.verified.Network, state.observationLinks, state.checkpoint, now)
	if !revoked["node-b.catofes."] {
		t.Fatalf("expected node-b.catofes. in revoked set from SyncPeers, got %v", revoked)
	}
}
