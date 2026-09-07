package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/HiggsNet/photon/internal/inspect"
	"github.com/HiggsNet/photon/pkg/core/zone"
	bolt "go.etcd.io/bbolt"
)

func dbDump(filter string) error {
	path, err := configuredStatePath()
	if err != nil {
		return err
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{ReadOnly: true})
	if err != nil {
		return err
	}
	defer db.Close()

	fmt.Printf("database: %s\n", path)
	return db.View(func(tx *bolt.Tx) error {
		if meta := tx.Bucket([]byte("_meta")); meta != nil {
			if err := dumpMetaBucket(meta); err != nil {
				return err
			}
		}

		zones := make([]string, 0)
		err := tx.ForEach(func(name []byte, b *bolt.Bucket) error {
			bucketName := string(name)
			if after, ok := strings.CutPrefix(bucketName, "zone:"); ok {
				zoneName := after
				if filter == "" || filter == zoneName {
					zones = append(zones, zoneName)
				}
				return nil
			}
			if bucketName != "_meta" && filter == "" {
				fmt.Printf("\nbucket %s\n", bucketName)
				return dumpRawBucket(b, "  ")
			}
			return nil
		})
		if err != nil {
			return err
		}
		inspect.SortZoneStrings(zones)
		for _, zoneName := range zones {
			if err := dumpZoneBucket(zone.ZonePath(zoneName), tx.Bucket([]byte("zone:"+zoneName))); err != nil {
				return err
			}
		}
		return nil
	})
}

func dbStats() error {
	path, err := configuredStatePath()
	if err != nil {
		return err
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{ReadOnly: true})
	if err != nil {
		return err
	}
	defer db.Close()

	var totalKeys int
	var totalSize int64

	err = db.View(func(tx *bolt.Tx) error {
		return tx.ForEach(func(name []byte, b *bolt.Bucket) error {
			bucketName := string(name)
			bucketKeys := 0
			var bucketSize int64
			b.ForEach(func(k, v []byte) error {
				totalKeys++
				bucketKeys++
				bucketSize += int64(len(k)) + int64(len(v))
				return nil
			})
			totalSize += bucketSize
			fmt.Printf("bucket %-20s keys=%4d size=%8d bytes\n", bucketName+":", bucketKeys, bucketSize)
			return nil
		})
	})
	if err != nil {
		return err
	}
	fmt.Printf("%-27s keys=%4d size=%8d bytes\n", "total:", totalKeys, totalSize)
	return nil
}

func dumpMetaBucket(bucket *bolt.Bucket) error {
	fmt.Printf("\nmeta\n")
	return bucket.ForEach(func(k, v []byte) error {
		switch string(k) {
		case "global_root":
			var root []byte
			if err := json.Unmarshal(v, &root); err != nil {
				return dumpRawEntry(k, v, "  ")
			}
			fmt.Printf("  global_root: %s\n", formatBytes(root))
		case cliMetaKey:
			var meta stateMeta
			if err := json.Unmarshal(v, &meta); err != nil {
				return dumpRawEntry(k, v, "  ")
			}
			fmt.Printf("  managed_zone: %s\n", valueOrDash(meta.ManagedZone.String()))
			fmt.Printf("  root_private_key: %s\n", present(len(meta.RootPrivateKey) == ed25519.PrivateKeySize))
			fmt.Printf("  zone_private_key: %s\n", present(len(meta.ZonePrivateKey) == ed25519.PrivateKeySize))
			dumpSyncPeers(meta.SyncPeers)
		default:
			return dumpRawEntry(k, v, "  ")
		}
		return nil
	})
}

func dumpZoneBucket(path zone.ZonePath, bucket *bolt.Bucket) error {
	if bucket == nil {
		return nil
	}
	fmt.Printf("\nzone %s\n", path)
	if err := dumpAuthority(bucket.Get([]byte("authority"))); err != nil {
		return err
	}
	if err := dumpParentProof(bucket.Get([]byte("parent_proof"))); err != nil {
		return err
	}
	if err := dumpDelegations(bucket.Get([]byte("delegations"))); err != nil {
		return err
	}
	if err := dumpRevocations(bucket.Get([]byte("revocations"))); err != nil {
		return err
	}
	if err := dumpRecords("records", bucket.Get([]byte("records"))); err != nil {
		return err
	}
	if err := dumpRecordHistory(bucket.Get([]byte("record_history"))); err != nil {
		return err
	}
	if err := dumpMerkleRoot(bucket.Get([]byte("merkle_root"))); err != nil {
		return err
	}

	known := map[string]bool{
		"authority":      true,
		"parent_proof":   true,
		"delegations":    true,
		"revocations":    true,
		"records":        true,
		"record_history": true,
		"merkle_root":    true,
	}
	return bucket.ForEach(func(k, v []byte) error {
		if known[string(k)] {
			return nil
		}
		return dumpRawEntry(k, v, "  ")
	})
}

func dumpAuthority(data []byte) error {
	var authority *zone.ZoneAuthority
	if err := unmarshalOptional(data, &authority); err != nil {
		return dumpRawNamed("authority", data, "  ")
	}
	if authority == nil {
		fmt.Printf("  authority: -\n")
		return nil
	}
	fmt.Printf("  authority: epoch=%d threshold=%d keys=%d\n", authority.Epoch, authority.Threshold, len(authority.Keys))
	dumpAuthorizedKeys(authority.Keys, "    ")
	return nil
}

func dumpParentProof(data []byte) error {
	var proof []*zone.Delegation
	if err := unmarshalOptional(data, &proof); err != nil {
		return dumpRawNamed("parent_proof", data, "  ")
	}
	fmt.Printf("  parent_proof: %d\n", len(proof))
	for i, delegation := range proof {
		fmt.Printf("    [%d] ", i)
		dumpDelegationLine(delegation)
	}
	return nil
}

func dumpDelegations(data []byte) error {
	var delegations map[zone.ZonePath]*zone.Delegation
	if err := unmarshalOptional(data, &delegations); err != nil {
		return dumpRawNamed("delegations", data, "  ")
	}
	fmt.Printf("  delegations: %d\n", len(delegations))
	keys := sortedZoneKeys(delegations)
	for _, key := range keys {
		fmt.Printf("    %s: ", key)
		dumpDelegationLine(delegations[key])
	}
	return nil
}

func dumpRevocations(data []byte) error {
	var revocations map[zone.ZonePath]*zone.DelegationRevocation
	if err := unmarshalOptional(data, &revocations); err != nil {
		return dumpRawNamed("revocations", data, "  ")
	}
	fmt.Printf("  revocations: %d\n", len(revocations))
	keys := sortedZoneKeys(revocations)
	for _, key := range keys {
		revocation := revocations[key]
		if revocation == nil {
			fmt.Printf("    %s: -\n", key)
			continue
		}
		fmt.Printf("    %s: parent=%s epoch=%d reason=%s revoked_at=%s signed_by=%s signature=%s\n",
			key,
			revocation.ParentZone,
			revocation.RevokedAuthorityEpoch,
			valueOrDash(revocation.Reason),
			formatUnix(revocation.RevokedAt),
			shortKey(revocation.SignedBy),
			shortBytes(revocation.Signature),
		)
	}
	return nil
}

func dumpRecords(label string, data []byte) error {
	var records map[string]*zone.Record
	if err := unmarshalOptional(data, &records); err != nil {
		return dumpRawNamed(label, data, "  ")
	}
	fmt.Printf("  %s: %d\n", label, len(records))
	keys := sortedStringKeys(records)
	for _, key := range keys {
		dumpRecord(key, records[key], "    ")
	}
	return nil
}

func dumpRecordHistory(data []byte) error {
	var history map[string][]*zone.Record
	if err := unmarshalOptional(data, &history); err != nil {
		return dumpRawNamed("record_history", data, "  ")
	}
	total := countRecordLists(history)
	fmt.Printf("  record_history: %d keys, %d records\n", len(history), total)
	for _, key := range sortedStringKeys(history) {
		fmt.Printf("    %s: %d versions\n", key, len(history[key]))
		for _, record := range history[key] {
			dumpRecord("", record, "      ")
		}
	}
	return nil
}

func dumpMerkleRoot(data []byte) error {
	var root []byte
	if err := unmarshalOptional(data, &root); err != nil {
		return dumpRawNamed("merkle_root", data, "  ")
	}
	fmt.Printf("  merkle_root: %s\n", formatBytes(root))
	return nil
}

func dumpAuthorizedKeys(keys []zone.AuthorizedKey, indent string) {
	for i, key := range keys {
		fmt.Printf("%skey[%d]: %s\n", indent, i, formatPublicKey(key.Key))
		if key.NotBefore != 0 || key.NotAfter != 0 {
			fmt.Printf("%s  valid: %s..%s\n", indent, formatUnix(key.NotBefore), formatUnix(key.NotAfter))
		}
		for _, capability := range key.Capabilities {
			prefix := valueOrDash(capability.KeyPrefix)
			fmt.Printf("%s  capability: permissions=%s key_prefix=%s\n", indent, permissions(capability.Permissions), prefix)
		}
	}
}

func dumpDelegationLine(delegation *zone.Delegation) {
	if delegation == nil {
		fmt.Printf("-\n")
		return
	}
	expires := "never"
	if delegation.ExpiresAt != nil {
		expires = delegation.ExpiresAt.UTC().Format(time.RFC3339)
	}
	fmt.Printf("zone=%s scope=%s authority_epoch=%d signed_by=%s expires=%s\n",
		delegation.ZoneName,
		delegation.Scope,
		delegation.AuthorityEpoch,
		shortKey(delegation.SignedBy),
		expires,
	)
	fmt.Printf("      authority: epoch=%d threshold=%d keys=%d hash=%s signature=%s\n",
		delegation.Authority.Epoch,
		delegation.Authority.Threshold,
		len(delegation.Authority.Keys),
		formatBytes(delegation.AuthorityHash),
		shortBytes(delegation.Signature),
	)
}

func dumpRecord(mapKey string, record *zone.Record, indent string) {
	if record == nil {
		fmt.Printf("%s%s-\n", indent, recordLabel(mapKey))
		return
	}
	label := recordLabel(mapKey)
	fmt.Printf("%s%szone=%s type=%s version=%d signed_by=%s timestamp=%s\n",
		indent,
		label,
		record.Zone,
		valueOrDash(record.Type),
		record.Version,
		shortKey(record.SignedBy),
		formatUnix(record.Timestamp),
	)
	fmt.Printf("%s  value: %s\n", indent, formatRecordValue(record.Value))
	fmt.Printf("%s  prev_hash=%s value_hash=%s signature=%s\n",
		indent,
		formatBytes(record.PrevHash),
		formatBytes(record.ValueHash),
		shortBytes(record.Signature),
	)
}

func dumpSyncPeers(peers map[string]syncPeerState) {
	if len(peers) == 0 {
		fmt.Printf("  sync_peers: 0\n")
		return
	}
	keys := make([]string, 0, len(peers))
	for key := range peers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	fmt.Printf("  sync_peers: %d\n", len(keys))
	for _, key := range keys {
		peer := peers[key]
		lastSync := "never"
		if peer.LastSyncUnix != 0 {
			lastSync = formatUnix(peer.LastSyncUnix)
		}
		lastError := valueOrDash(peer.LastError)
		fmt.Printf("    %s: last_sync=%s last_error=%s\n", key, lastSync, lastError)
	}
}

func dumpRawBucket(bucket *bolt.Bucket, indent string) error {
	return bucket.ForEach(func(k, v []byte) error {
		return dumpRawEntry(k, v, indent)
	})
}

func dumpRawNamed(name string, data []byte, indent string) error {
	return dumpRawEntry([]byte(name), data, indent)
}

func dumpRawEntry(k, v []byte, indent string) error {
	fmt.Printf("%s%s: ", indent, string(k))
	var data any
	if err := json.Unmarshal(v, &data); err == nil {
		pretty, _ := json.MarshalIndent(data, indent, "  ")
		fmt.Printf("\n%s\n", pretty)
		return nil
	}
	s := string(v)
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	fmt.Printf("%s\n", s)
	return nil
}

func unmarshalOptional(data []byte, out any) error {
	if data == nil {
		return nil
	}
	return json.Unmarshal(data, out)
}

func sortedStringKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedZoneKeys[V any](values map[zone.ZonePath]V) []zone.ZonePath {
	keys := make([]zone.ZonePath, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	inspect.SortZonePaths(keys)
	return keys
}

func countRecordLists(records map[string][]*zone.Record) int {
	total := 0
	for _, list := range records {
		total += len(list)
	}
	return total
}

func permissions(values []zone.Permission) string {
	if len(values) == 0 {
		return "-"
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, string(value))
	}
	return strings.Join(out, ",")
}

func recordLabel(key string) string {
	if key == "" {
		return ""
	}
	return key + ": "
}

func formatRecordValue(value []byte) string {
	if len(value) == 0 {
		return "-"
	}
	if utf8.Valid(value) && isPrintable(value) {
		return fmt.Sprintf("%q", string(value))
	}
	return "base64:" + formatPublicKey(value)
}

func isPrintable(value []byte) bool {
	for _, r := range string(value) {
		if r < 0x20 && r != '\n' && r != '\t' {
			return false
		}
	}
	return true
}

func formatBytes(value []byte) string {
	if len(value) == 0 {
		return "-"
	}
	return hex.EncodeToString(value)
}

func shortBytes(value []byte) string {
	full := formatBytes(value)
	if len(full) <= 16 {
		return full
	}
	return full[:16] + "..."
}

func shortKey(key ed25519.PublicKey) string {
	if len(key) == 0 {
		return "-"
	}
	full := formatPublicKey(key)
	if len(full) <= 12 {
		return full
	}
	return full[:12] + "..."
}

func formatUnix(value int64) string {
	if value == 0 {
		return "-"
	}
	return time.Unix(value, 0).UTC().Format(time.RFC3339)
}

func valueOrDash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

func present(ok bool) string {
	if ok {
		return "present"
	}
	return "-"
}
