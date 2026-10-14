package state

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/HiggsNet/photon/pkg/core/zone"
	bolt "go.etcd.io/bbolt"
)

// Schema 2 keeps identity/global metadata separate from each zone. The path
// manifest detects missing or orphaned zone payloads during read-only loads.
func loadBoltVerified(bucket *bolt.Bucket, version uint64) (*persistedVerifiedState, error) {
	var persisted persistedVerifiedState
	if err := decodeRequiredJSON(bucket, keyPayload, &persisted); err != nil {
		return nil, err
	}
	if version == legacyBoltSchemaVersion {
		if persisted.Network == nil || bucket.Bucket(bucketVerifiedZones) != nil {
			return nil, fmt.Errorf("%w: invalid legacy verified layout", ErrBoltStateCorrupt)
		}
		return &persisted, nil
	}
	zones := bucket.Bucket(bucketVerifiedZones)
	if persisted.Network != nil || zones == nil || len(persisted.ZonePaths) == 0 {
		return nil, fmt.Errorf("%w: invalid verified zone layout", ErrBoltStateCorrupt)
	}
	network := &zone.NetworkState{Zones: make(map[zone.ZonePath]*zone.ZoneState, len(persisted.ZonePaths)), GlobalRoot: persisted.GlobalRoot}
	for _, path := range persisted.ZonePaths {
		if !path.Valid() {
			return nil, fmt.Errorf("%w: invalid verified zone path", ErrBoltStateCorrupt)
		}
		if _, exists := network.Zones[path]; exists {
			return nil, fmt.Errorf("%w: duplicate verified zone path", ErrBoltStateCorrupt)
		}
		var zs *zone.ZoneState
		if err := decodeRequiredJSON(zones, []byte(path), &zs); err != nil {
			return nil, err
		}
		if zs != nil && zs.Path != path {
			return nil, fmt.Errorf("%w: verified zone path mismatch", ErrBoltStateCorrupt)
		}
		network.Zones[path] = zs
	}
	if err := zones.ForEach(func(k, v []byte) error {
		if _, exists := network.Zones[zone.ZonePath(k)]; !exists || v == nil {
			return fmt.Errorf("%w: unexpected verified zone entry", ErrBoltStateCorrupt)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	persisted.Network = network
	return &persisted, nil
}

type encodedVerifiedState struct {
	payload []byte
	zones   map[zone.ZonePath][]byte
}

func encodeBoltVerified(state *VerifiedState) (encodedVerifiedState, error) {
	root := persistedVerifiedState{
		ManagedZone: state.ManagedZone, GlobalRoot: state.Network.GlobalRoot,
		TrustedRootPublicKey: state.TrustedRootPublicKey,
		RootPrivateKey:       state.RootPrivateKey, IdentityPrivateKey: state.IdentityPrivateKey,
	}
	out := encodedVerifiedState{zones: make(map[zone.ZonePath][]byte, len(state.Network.Zones))}
	for path, zs := range state.Network.Zones {
		if !path.Valid() || (zs != nil && zs.Path != path) {
			return out, fmt.Errorf("%w: invalid verified zone path", ErrInvalidStateRoot)
		}
		data, err := json.Marshal(zs)
		if err != nil {
			return out, err
		}
		out.zones[path] = data
		root.ZonePaths = append(root.ZonePaths, path)
	}
	sort.Slice(root.ZonePaths, func(i, j int) bool { return root.ZonePaths[i] < root.ZonePaths[j] })
	var err error
	out.payload, err = json.Marshal(root)
	return out, err
}

func (encoded encodedVerifiedState) differsFrom(bucket *bolt.Bucket) (bool, error) {
	zones := bucket.Bucket(bucketVerifiedZones)
	if zones == nil {
		return false, fmt.Errorf("%w: verified zones are missing", ErrBoltStateCorrupt)
	}
	changed := !bytes.Equal(bucket.Get(keyPayload), encoded.payload)
	count := 0
	if err := zones.ForEach(func(k, v []byte) error {
		if v == nil {
			return fmt.Errorf("%w: invalid verified zone entry", ErrBoltStateCorrupt)
		}
		count++
		data, exists := encoded.zones[zone.ZonePath(k)]
		changed = changed || !exists || !bytes.Equal(v, data)
		return nil
	}); err != nil {
		return false, err
	}
	return changed || count != len(encoded.zones), nil
}

func (encoded encodedVerifiedState) save(bucket *bolt.Bucket) (bool, error) {
	zones, changed, err := createNestedBucketIfMissing(bucket, bucketVerifiedZones)
	if err != nil {
		return false, err
	}
	var remove [][]byte
	if err := zones.ForEach(func(k, _ []byte) error {
		if _, exists := encoded.zones[zone.ZonePath(k)]; !exists {
			remove = append(remove, append([]byte(nil), k...))
		}
		return nil
	}); err != nil {
		return false, err
	}
	for _, key := range remove {
		if err := zones.Delete(key); err != nil {
			return false, err
		}
		changed = true
	}
	paths := make([]zone.ZonePath, 0, len(encoded.zones))
	for path := range encoded.zones {
		paths = append(paths, path)
	}
	sort.Slice(paths, func(i, j int) bool { return paths[i] < paths[j] })
	for _, path := range paths {
		wrote, err := putBytesIfChanged(zones, []byte(path), encoded.zones[path])
		if err != nil {
			return false, err
		}
		changed = changed || wrote
	}
	wrote, err := putBytesIfChanged(bucket, keyPayload, encoded.payload)
	return changed || wrote, err
}
