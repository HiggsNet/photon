package main

import (
	"bytes"
	"encoding/binary"
	"errors"

	"os"
	"path/filepath"

	"testing"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	bolt "go.etcd.io/bbolt"
)

func TestOpenStateRejectsOldDatabasesWithoutWriting(t *testing.T) {
	verified, checkpoint, linux, _ := buildTestRoutingOwners(t)
	for _, schema := range []string{"aggregate database", "schema 1"} {
		t.Run(schema, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "photon.db")
			if schema == "aggregate database" {
				db, err := bolt.Open(path, 0o600, nil)
				if err != nil {
					t.Fatal(err)
				}
				if err := db.Update(func(tx *bolt.Tx) error {
					_, err := tx.CreateBucket([]byte("zone:."))
					return err
				}); err != nil {
					_ = db.Close()
					t.Fatal(err)
				}
				if err := db.Close(); err != nil {
					t.Fatal(err)
				}
			} else {
				seedPartitionedStateDB(t, path, verified, checkpoint, linux)
				db, err := bolt.Open(path, 0o600, nil)
				if err != nil {
					t.Fatal(err)
				}
				if err := db.Update(func(tx *bolt.Tx) error {
					var version [8]byte
					binary.BigEndian.PutUint64(version[:], 1)
					return tx.Bucket([]byte("photon:common-state")).Bucket([]byte("meta")).Put([]byte("schema-version"), version[:])
				}); err != nil {
					_ = db.Close()
					t.Fatal(err)
				}
				if err := db.Close(); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			config := defaultAppConfig()
			config.StatePath = path
			if _, err := openState(config); !errors.Is(err, corestate.ErrBoltSchemaUnsupported) {
				t.Fatalf("open old database: %v", err)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("rejected database changed: %v", err)
			}
		})
	}
}
