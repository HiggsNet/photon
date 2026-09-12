package photonlinux

import (
	"encoding/binary"
	"errors"
	"testing"

	photonstate "github.com/HiggsNet/photon/internal/state"
	bolt "go.etcd.io/bbolt"
)

func TestLinuxStateCodecRoundTripAndByteNoop(t *testing.T) {
	db, err := bolt.Open(t.TempDir()+"/runtime.db", 0o600, nil)
	if err != nil {
		t.Fatalf("bolt.Open: %v", err)
	}
	defer db.Close()
	if err := db.Update(func(tx *bolt.Tx) error {
		if _, err := SaveLinuxStateTx(tx, nil); err == nil {
			t.Fatal("nil Linux state save succeeded")
		}
		return nil
	}); err != nil {
		t.Fatalf("nil save transaction: %v", err)
	}
	want := &LinuxState{
		EndpointACLs: map[string]photonstate.EndpointACL{
			"api": {Name: "api", Selectors: []string{"zone:catofes."}},
		},
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		changed, err := SaveLinuxStateTx(tx, want)
		if err == nil && !changed {
			t.Fatal("first save reported no-op")
		}
		return err
	}); err != nil {
		t.Fatalf("first save: %v", err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		changed, err := SaveLinuxStateTx(tx, want)
		if err == nil && changed {
			t.Fatal("identical save reported change")
		}
		return err
	}); err != nil {
		t.Fatalf("identical save: %v", err)
	}
	if err := db.View(func(tx *bolt.Tx) error {
		got, found, err := LoadLinuxStateTx(tx)
		if err != nil {
			return err
		}
		if !found || got.EndpointACLs["api"].Selectors[0] != "zone:catofes." {
			t.Fatalf("loaded runtime = found %v state %#v", found, got)
		}
		return nil
	}); err != nil {
		t.Fatalf("load: %v", err)
	}
}

func TestLinuxStateCodecFailsClosedOnCorruption(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(*bolt.Bucket) error
	}{
		{name: "missing schema", prepare: func(bucket *bolt.Bucket) error {
			return bucket.Put(linuxStatePayloadKey, []byte("{}"))
		}},
		{name: "unsupported schema", prepare: func(bucket *bolt.Bucket) error {
			var version [8]byte
			binary.BigEndian.PutUint64(version[:], linuxStateSchemaVersion+1)
			if err := bucket.Put(linuxStateSchemaKey, version[:]); err != nil {
				return err
			}
			return bucket.Put(linuxStatePayloadKey, []byte("{}"))
		}},
		{name: "missing payload", prepare: func(bucket *bolt.Bucket) error {
			var version [8]byte
			binary.BigEndian.PutUint64(version[:], linuxStateSchemaVersion)
			return bucket.Put(linuxStateSchemaKey, version[:])
		}},
		{name: "null payload", prepare: func(bucket *bolt.Bucket) error {
			var version [8]byte
			binary.BigEndian.PutUint64(version[:], linuxStateSchemaVersion)
			if err := bucket.Put(linuxStateSchemaKey, version[:]); err != nil {
				return err
			}
			return bucket.Put(linuxStatePayloadKey, []byte("null"))
		}},
		{name: "malformed payload", prepare: func(bucket *bolt.Bucket) error {
			var version [8]byte
			binary.BigEndian.PutUint64(version[:], linuxStateSchemaVersion)
			if err := bucket.Put(linuxStateSchemaKey, version[:]); err != nil {
				return err
			}
			return bucket.Put(linuxStatePayloadKey, []byte("{"))
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			db, err := bolt.Open(t.TempDir()+"/runtime.db", 0o600, nil)
			if err != nil {
				t.Fatalf("bolt.Open: %v", err)
			}
			defer db.Close()
			if err := db.Update(func(tx *bolt.Tx) error {
				bucket, err := tx.CreateBucket(linuxStateBucket)
				if err != nil {
					return err
				}
				return test.prepare(bucket)
			}); err != nil {
				t.Fatalf("prepare: %v", err)
			}
			if err := db.View(func(tx *bolt.Tx) error {
				_, found, err := LoadLinuxStateTx(tx)
				if !found || !errors.Is(err, ErrLinuxStateCorrupt) {
					t.Fatalf("load = found %v err %v", found, err)
				}
				return nil
			}); err != nil {
				t.Fatalf("view: %v", err)
			}
		})
	}
}
