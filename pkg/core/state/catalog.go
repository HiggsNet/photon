package state

import (
	"bytes"
	"sort"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

// ZoneDigest is the detached verified-state identity advertised for one zone.
type ZoneDigest struct {
	Zone     zone.ZonePath `json:"zone" msgpack:"z"`
	RootHash []byte        `json:"root_hash" msgpack:"h"`
}

// CatalogSummary identifies a complete ordered zone-digest projection.
type CatalogSummary struct {
	CatalogRoot []byte `json:"catalog_root" msgpack:"r"`
	ZoneCount   int    `json:"zone_count" msgpack:"z"`
}

// CatalogPage is a detached slice of a catalog projection. Pagination and
// wire-size packing are protocol concerns owned by pkg/core/gossip.
type CatalogPage struct {
	CatalogRoot []byte       `json:"catalog_root" msgpack:"r"`
	Entries     []ZoneDigest `json:"entries" msgpack:"e"`
	NextCursor  string       `json:"next_cursor,omitempty" msgpack:"c,omitempty"`
}

// ZoneDigests returns a deterministic detached digest projection of verified
// state, excluding zones that are currently revoked.
func ZoneDigests(ns *zone.NetworkState) []ZoneDigest {
	if ns == nil {
		return nil
	}
	out := make([]ZoneDigest, 0, len(ns.Zones))
	for path, zs := range ns.Zones {
		if zs == nil || ns.IsZoneRevoked(path, time.Now()) {
			continue
		}
		out = append(out, ZoneDigest{Zone: path, RootHash: ZoneRoot(zs)})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Zone < out[j].Zone
	})
	return out
}

// ZoneRoot returns the deterministic identity of one verified zone.
func ZoneRoot(zs *zone.ZoneState) []byte {
	if zs == nil {
		return nil
	}
	parts := make([][]byte, 0, 1+len(zs.Delegations)+len(zs.Revocations)+len(zs.Records))
	parts = append(parts, photoncrypto.AuthorityHash(zs.Authority))

	delegationZones := make([]string, 0, len(zs.Delegations))
	for path := range zs.Delegations {
		delegationZones = append(delegationZones, path.String())
	}
	sort.Strings(delegationZones)
	for _, path := range delegationZones {
		delegation := zs.Delegations[zone.ZonePath(path)]
		if delegation == nil {
			continue
		}
		parts = append(parts, photoncrypto.Hash(
			[]byte("delegation"),
			[]byte(path),
			delegation.AuthorityHash,
			delegation.Signature,
		))
	}

	revocationZones := make([]string, 0, len(zs.Revocations))
	for path := range zs.Revocations {
		revocationZones = append(revocationZones, path.String())
	}
	sort.Strings(revocationZones)
	for _, path := range revocationZones {
		revocation := zs.Revocations[zone.ZonePath(path)]
		if revocation == nil {
			continue
		}
		parts = append(parts, photoncrypto.Hash(
			[]byte("revocation"),
			[]byte(path),
			revocation.RevokedAuthorityHash,
			revocation.Signature,
		))
	}

	recordKeys := make([]string, 0, len(zs.Records))
	for key := range zs.Records {
		recordKeys = append(recordKeys, key)
	}
	sort.Strings(recordKeys)
	for _, key := range recordKeys {
		record := zs.Records[key]
		if record == nil {
			continue
		}
		parts = append(parts, photoncrypto.Hash(
			[]byte("record"),
			[]byte(key),
			photoncrypto.RecordHash(record),
		))
	}
	return photoncrypto.Hash(parts...)
}

// CatalogRoot returns the deterministic identity of an ordered digest list.
func CatalogRoot(entries []ZoneDigest) []byte {
	parts := make([][]byte, 0, 1+len(entries)*2)
	parts = append(parts, []byte("photon.catalog.v1"))
	for _, entry := range entries {
		parts = append(parts, []byte(entry.Zone), entry.RootHash)
	}
	return photoncrypto.Hash(parts...)
}

// CatalogSummaryFor projects a catalog summary from verified state.
func CatalogSummaryFor(ns *zone.NetworkState) *CatalogSummary {
	return CatalogSummaryForDigests(ZoneDigests(ns))
}

// CatalogSummaryForDigests builds a summary from an already computed digest
// projection so callers needing both do not hash every zone twice.
func CatalogSummaryForDigests(entries []ZoneDigest) *CatalogSummary {
	return &CatalogSummary{CatalogRoot: CatalogRoot(entries), ZoneCount: len(entries)}
}

// CatalogDiff returns valid remote entries absent from or different to local.
func CatalogDiff(local, remote []ZoneDigest) []ZoneDigest {
	localByZone := make(map[zone.ZonePath][]byte, len(local))
	for _, entry := range local {
		localByZone[entry.Zone] = entry.RootHash
	}
	var out []ZoneDigest
	for _, entry := range remote {
		if !entry.Zone.Valid() {
			continue
		}
		if !bytes.Equal(localByZone[entry.Zone], entry.RootHash) {
			out = append(out, entry)
		}
	}
	return out
}
