package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/urfave/cli/v3"
	bolt "go.etcd.io/bbolt"
)

func cmdDB() *cli.Command {
	return &cli.Command{
		Name:  "db",
		Usage: "Low-level database inspection commands",
		Commands: []*cli.Command{
			{
				Name:      "dump",
				Usage:     "Dump all database buckets and keys",
				UsageText: "photon debug db dump [zone]",
				Description: "Print every bucket and key in the state database.\n" +
					"If a zone is provided, show it from the current VerifiedState layout.",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() > 1 {
						return cli.Exit("usage: photon debug db dump [zone]", 1)
					}
					filter := ""
					if cmd.Args().Len() > 0 {
						filter = cmd.Args().First()
					}
					return debugDBDump(filter)
				},
			},
			{
				Name:        "stats",
				Usage:       "Show database bucket statistics",
				Description: "Print the number of keys and total size per bucket.",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 0 {
						return cli.Exit("usage: photon debug db stats", 1)
					}
					return debugDBStats()
				},
			},
		},
	}
}

func openDebugDB(path string) (*bolt.DB, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{ReadOnly: true, Timeout: daemonBoltLockTimeout})
	if errors.Is(err, bolt.ErrTimeout) {
		return nil, fmt.Errorf("database is locked; stop daemon or inspect a database copy: %w", err)
	}
	return db, err
}

func debugDBDump(filter string) error {
	path, err := configuredStatePath()
	if err != nil {
		return err
	}
	db, err := openDebugDB(path)
	if err != nil {
		return err
	}
	defer db.Close()

	fmt.Printf("database: %s\n", path)
	return db.View(func(tx *bolt.Tx) error {
		return dumpDBTx(tx, filter)
	})
}

func dumpDBTx(tx *bolt.Tx, filter string) error {
	if filter != "" {
		candidate, revision, report, found, err := corestate.LoadBoltState(tx)
		if err != nil {
			return err
		}
		if !found {
			return errors.New("zone filtering requires the current database layout")
		}
		fmt.Printf("common: revision=%d gossip_checkpoint_discarded=%t\n", revision, report.GossipCheckpointDiscarded)
		zs := candidate.Verified.Network.Zones[zone.ZonePath(filter)]
		if zs == nil {
			return fmt.Errorf("%w: %s", zone.ErrZoneNotFound, filter)
		}
		data, err := json.Marshal(zs)
		if err != nil {
			return err
		}
		return dumpRawEntry([]byte("zone "+filter), data, "")
	}
	return tx.ForEach(func(name []byte, bucket *bolt.Bucket) error {
		fmt.Printf("\nbucket %s\n", name)
		return dumpRawBucket(bucket, "  ")
	})
}

func debugDBStats() error {
	path, err := configuredStatePath()
	if err != nil {
		return err
	}
	db, err := openDebugDB(path)
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
			var count func(*bolt.Bucket) error
			count = func(bucket *bolt.Bucket) error {
				return bucket.ForEach(func(k, v []byte) error {
					if v == nil {
						return count(bucket.Bucket(k))
					}
					totalKeys++
					bucketKeys++
					bucketSize += int64(len(k) + len(v))
					return nil
				})
			}
			if err := count(b); err != nil {
				return err
			}
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

func dumpRawBucket(bucket *bolt.Bucket, indent string) error {
	return bucket.ForEach(func(k, v []byte) error {
		if v == nil {
			fmt.Printf("%s bucket %s\n", indent, k)
			return dumpRawBucket(bucket.Bucket(k), indent+"  ")
		}
		return dumpRawEntry(k, v, indent)
	})
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
