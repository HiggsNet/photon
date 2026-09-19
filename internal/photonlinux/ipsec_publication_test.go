package photonlinux

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"

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
