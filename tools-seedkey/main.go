package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

// Minimal replica of app/photon's state persistence (stateMeta in
// cli_state) — app/photon itself is package main and cannot be imported.
type syncPeerState struct {
	PeerID string `json:"peer_id"`
}

type peerLifecycleCleanupState struct{}

type ipsecTransportKeyState struct {
	Kind        string `json:"kind,omitempty"`
	Algorithm   string `json:"algorithm,omitempty"`
	PublicKey   []byte `json:"public_key,omitempty"`
	PrivateKey  []byte `json:"private_key,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	NotBefore   int64  `json:"not_before,omitempty"`
	NotAfter    int64  `json:"not_after,omitempty"`
	UpdatedAt   int64  `json:"updated_at,omitempty"`
}

type ipsecPortRecordState struct{}

type linkInstanceState struct{}

type ipsecReconcileState struct{}

type routingReconcileState struct{}

type firewallReconcileState struct{}

type endpointACL struct{}

type birdInstanceState struct{}

type admissionState struct{}

type stateMeta struct {
	ManagedZone       zone.ZonePath                        `json:"managed_zone"`
	IdentityKeyPath   string                               `json:"identity_key_path,omitempty"`
	RootPrivateKey    ed25519.PrivateKey                   `json:"root_private_key"`
	ZonePrivateKey    ed25519.PrivateKey                   `json:"zone_private_key"`
	SyncPeers         map[string]syncPeerState             `json:"sync_peers,omitempty"`
	PeerCleanups      map[string]peerLifecycleCleanupState `json:"peer_cleanups,omitempty"`
	IPsecTransportKey *ipsecTransportKeyState              `json:"ipsec_transport_key,omitempty"`
	IPsecPortRecord   *ipsecPortRecordState                `json:"ipsec_port_record,omitempty"`
	LinkInstances     map[string]linkInstanceState         `json:"link_instances,omitempty"`
	IPsecReconcile    *ipsecReconcileState                 `json:"ipsec_reconcile,omitempty"`
	RoutingReconcile  *routingReconcileState               `json:"routing_reconcile,omitempty"`
	FirewallReconcile *firewallReconcileState              `json:"firewall_reconcile,omitempty"`
	EndpointACLs      map[string]endpointACL               `json:"endpoint_acls,omitempty"`
	BirdInstances     map[string]*birdInstanceState        `json:"bird_instances,omitempty"`
	Admission         *admissionState                      `json:"admission,omitempty"`
}

const cliMetaKey = "cli_state"

func main() {
	statePath := os.Args[1]
	pemPath := os.Args[2]
	block, _ := pem.Decode(readFile(pemPath))
	if block == nil {
		panic("pem decode failed")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		panic(fmt.Sprintf("not an ed25519 key: %T", parsed))
	}
	pub := key.Public().(ed25519.PublicKey)
	// The daemon's LoadPrivateKey parses the state bytes as PKCS#8 DER; store
	// the original DER, not the raw ed25519 seed.
	der := block.Bytes

	store, err := zone.OpenBoltStore(statePath, 0o600)
	if err != nil {
		panic(err)
	}
	defer store.Close()

	var meta stateMeta
	if err := store.LoadMetaJSON(cliMetaKey, &meta); err != nil {
		panic(err)
	}
	if meta.ManagedZone == "" {
		panic("state has no managed zone; run join accept first")
	}
	now := time.Now().Unix()
	meta.IPsecTransportKey = &ipsecTransportKeyState{
		Kind:        "raw-public-key",
		Algorithm:   "ed25519",
		PublicKey:   append([]byte(nil), pub...),
		PrivateKey:  append([]byte(nil), der...),
		Fingerprint: ipsec.TransportKeyFingerprint("ed25519", pub),
		NotBefore:   now,
		UpdatedAt:   now,
	}
	if err := store.SaveMetaJSON(cliMetaKey, &meta); err != nil {
		panic(err)
	}

	// Insert the mesh's existing v1 transport-key record into the local zone
	// state so the daemon's startup publish sees content changed and bumps
	// to v2 (the mesh rejects same-version records with different content).
	ns, err := store.LoadNetwork()
	if err != nil {
		panic(err)
	}
	managed := meta.ManagedZone
	zs := ns.Zones[managed]
	if zs != nil {
		if existing := zs.Records["ipsec/transport-key"]; existing != nil && existing.Version >= 2 {
			fmt.Println("transport-key record already at v" + fmt.Sprint(existing.Version) + ", skipping old-record insertion")
		} else {
			oldPub, _ := base64.StdEncoding.DecodeString("jKUmOBZ2aJKkCNXluqCCK6zvT8NJ5Rv6pPrxXLQXu2U=")
			oldValue := fmt.Sprintf(`{"algorithm":"ed25519","fingerprint":"%s","kind":"raw-public-key","not_before":1788693012,"public_key":"jKUmOBZ2aJKkCNXluqCCK6zvT8NJ5Rv6pPrxXLQXu2U=","updated_at":1788693012,"version":1}`,
				ipsec.TransportKeyFingerprint("ed25519", oldPub))
			oldRecord := &zone.Record{
				Zone:      managed,
				Key:       "ipsec/transport-key",
				Type:      "ipsec.transport_key.v1",
				Value:     []byte(oldValue),
				Version:   1,
				Timestamp: 1788693012,
			}
			zoneKey := ed25519.PrivateKey(meta.ZonePrivateKey)
			if err := photoncrypto.SignRecord(oldRecord, zoneKey); err != nil {
				panic(fmt.Errorf("sign old record: %w", err))
			}
			ns.PutAt(oldRecord, time.Unix(1788693012, 0))
			if err := store.SaveNetwork(ns); err != nil {
				panic(err)
			}
			fmt.Println("inserted old v1 transport-key record (4c:a2) into local zone state")
		}
	}

	if err := store.Close(); err != nil {
		panic(err)
	}
	store2, err := zone.OpenBoltStore(statePath, 0o600)
	if err != nil {
		panic(err)
	}
	defer store2.Close()
	var verify stateMeta
	if err := store2.LoadMetaJSON(cliMetaKey, &verify); err != nil {
		panic(err)
	}
	fmt.Println("seeded:", len(verify.IPsecTransportKey.PrivateKey), "bytes, fingerprint:", verify.IPsecTransportKey.Fingerprint)
	fmt.Println("seeded transport key fingerprint:", meta.IPsecTransportKey.Fingerprint)
}

func readFile(p string) []byte {
	data, err := os.ReadFile(p)
	if err != nil {
		panic(err)
	}
	return data
}
