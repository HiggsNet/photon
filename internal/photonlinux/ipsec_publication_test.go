package photonlinux

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"

	photonstate "github.com/HiggsNet/photon/internal/state"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestPublicTransportKeyRecordDefaultsAndSecretIsolation(t *testing.T) {
	key := &photonstate.IPsecTransportKeyState{PublicKey: []byte("public"), PrivateKey: []byte("private-secret-sentinel"), NotBefore: 123, NotAfter: 456}
	record := PublicTransportKeyRecord(key)
	if record.Kind != ipsec.TransportKeyRawPublicKey || record.Algorithm != ipsec.AlgorithmEd25519 || record.UpdatedAt != 123 || record.NotAfter != 456 || record.Fingerprint != ipsec.TransportKeyFingerprint(ipsec.AlgorithmEd25519, key.PublicKey) {
		t.Fatalf("public metadata: %+v", record)
	}
	if record.PublicKey != base64.StdEncoding.EncodeToString(key.PublicKey) {
		t.Fatal("public key encoding changed")
	}
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, key.PrivateKey) || bytes.Contains(data, []byte(base64.StdEncoding.EncodeToString(key.PrivateKey))) || bytes.Contains(data, []byte("private_key")) {
		t.Fatal("private material leaked")
	}
	if key.Kind != "" || key.Algorithm != "" || key.UpdatedAt != 0 || key.Fingerprint != "" {
		t.Fatal("projection mutated stored key")
	}
	key.Fingerprint, key.UpdatedAt = "existing", 789
	record = PublicTransportKeyRecord(key)
	if record.Fingerprint != "existing" || record.UpdatedAt != 789 {
		t.Fatal("existing metadata overwritten")
	}
}

// Each injected local private key must be detached from storage and other specs.
func TestInjectIPsecKeyMaterialDetachesSecrets(t *testing.T) {
	now := time.Unix(5000, 0)
	generated, record, err := ipsec.GenerateTransportKeyRecord(ipsec.AlgorithmEd25519, now, 0)
	if err != nil {
		t.Fatal(err)
	}
	value, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	network := zone.NewNetworkState()
	peer := zone.ZonePath("peer.example.")
	network.Zones[peer] = zone.NewZoneState(peer, nil)
	network.Zones[peer].Records[ipsec.RecordKeyTransportKey] = &zone.Record{Zone: peer, Key: ipsec.RecordKeyTransportKey, Type: ipsec.RecordTypeTransportKey, Value: value}
	local := &photonstate.IPsecTransportKeyState{PrivateKey: []byte("local-secret"), Algorithm: ipsec.AlgorithmEd25519}
	desired := []ipsec.TransportLinkSpec{{PeerZone: peer}, {PeerZone: "missing.example."}}
	got := InjectIPsecKeyMaterial(network, local, desired)
	if !bytes.Equal(got[0].PeerPublicKey, generated.PublicKey) || len(got[1].PeerPublicKey) != 0 || !bytes.Equal(got[1].LocalPrivateKey, local.PrivateKey) {
		t.Fatal("peer lookup or local key injection failed")
	}
	got[0].LocalPrivateKey[0] ^= 1
	got[0].PeerPublicKey[0] ^= 1
	if string(local.PrivateKey) != "local-secret" || !bytes.Equal(got[1].LocalPrivateKey, local.PrivateKey) || len(desired[0].LocalPrivateKey) != 0 {
		t.Fatal("injected private key aliases storage, another spec or planner input")
	}
	again := InjectIPsecKeyMaterial(network, local, desired)
	if !bytes.Equal(again[0].PeerPublicKey, generated.PublicKey) {
		t.Fatal("peer record mutated")
	}
	network.Zones[peer].Records[ipsec.RecordKeyTransportKey].Value = []byte("{")
	if invalid := InjectIPsecKeyMaterial(network, local, desired); len(invalid[0].PeerPublicKey) != 0 {
		t.Fatal("invalid peer key accepted")
	}
}
