package state

import "github.com/HiggsNet/photon/pkg/core/zone"

// PeerObservedGraceAddrState and PeerRejectedDigest are also part of the current
// inspect response schema; they are not exclusive to legacy database migration.
type PeerObservedGraceAddrState struct {
	Addr      string `json:"addr,omitempty"`
	UntilUnix int64  `json:"until_unix,omitempty"`
}

type PeerRejectedDigest struct {
	Zone           zone.ZonePath `json:"zone"`
	Object         string        `json:"object,omitempty"`
	Key            string        `json:"key,omitempty"`
	RootHashHex    string        `json:"root_hash_hex"`
	ObjectHashHex  string        `json:"object_hash_hex,omitempty"`
	Reason         string        `json:"reason"`
	RejectedAtUnix int64         `json:"rejected_at_unix"`
	UntilUnix      int64         `json:"until_unix"`
}
