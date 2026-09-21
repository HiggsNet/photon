package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/photonlinux"
	photonstate "github.com/HiggsNet/photon/internal/state"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	bolt "go.etcd.io/bbolt"
)

func TestOpenStatePersistsCommonAndLinuxPartitions(t *testing.T) {
	rt, _ := buildIPAMTestRuntime(t)
	state, err := openState(rt)
	if err != nil {
		t.Fatalf("openState: %v", err)
	}
	before := state.Common.ReadView()
	if _, err := state.Common.UpdatePeerCheckpoint(context.Background(), "peer.catofes.", corestate.PeerCheckpointPatch{
		BackoffUntilUnix: corestate.PatchField[int64]{Set: true, Value: 42},
	}); err != nil {
		t.Fatalf("UpdatePeerCheckpoint: %v", err)
	}
	if committed, err := state.ReplaceEndpointACLsIfRevision(before.Revision, map[string]photonstate.EndpointACL{
		"api": {Name: "api"},
	}); err != nil || !committed {
		t.Fatalf("ReplaceEndpointACLsIfRevision = committed %v err %v", committed, err)
	}
	if err := state.Close(); err != nil {
		t.Fatalf("Close State: %v", err)
	}

	reopened, err := openState(rt)
	if err != nil {
		t.Fatalf("reopen State: %v", err)
	}
	defer reopened.Close()
	common := reopened.Common.ReadView()
	linux := reopened.ReadLinux()
	if common.Revision != before.Revision {
		t.Fatalf("partition-only writes advanced verified revision from %d to %d", before.Revision, common.Revision)
	}
	if common.Gossip.Peers["peer.catofes."].BackoffUntilUnix != 42 {
		t.Fatalf("reopened checkpoint = %+v", common.Gossip.Peers["peer.catofes."])
	}
	if linux.EndpointACLs["api"].Name != "api" {
		t.Fatalf("reopened Linux state = %+v", linux)
	}
}

func TestOpenStateOwnsBoltLifecycle(t *testing.T) {
	rt, _ := buildIPAMTestRuntime(t)
	state, err := openState(rt)
	if err != nil {
		t.Fatalf("openState: %v", err)
	}
	started := time.Now()
	competing, err := corestate.OpenBoltStore(rt.StatePath, 0o600, 25*time.Millisecond)
	if competing != nil {
		_ = competing.Close()
	}
	if !errors.Is(err, bolt.ErrTimeout) {
		t.Fatalf("second open error = %v, want bbolt timeout", err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("external lock conflict did not respect timeout")
	}
	if err := state.Close(); err != nil {
		t.Fatalf("Close State: %v", err)
	}
	reopened, err := openState(rt)
	if err != nil {
		t.Fatalf("reopen after Close: %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatalf("Close reopened State: %v", err)
	}
}

func TestStateRejectsLinuxCommitAfterDiskRevisionDiverges(t *testing.T) {
	rt, _ := buildIPAMTestRuntime(t)
	state, err := openState(rt)
	if err != nil {
		t.Fatalf("openState: %v", err)
	}
	defer state.Close()

	before := state.Common.ReadView()
	detached := corestate.NewStoreWithCheckpoint(before.State, before.Gossip, nil)
	if _, err := advanceTestVerifiedRevision(detached, time.Unix(1, 0)); err != nil {
		t.Fatalf("advance detached verified revision: %v", err)
	}
	disk := detached.ReadView()
	if err := state.db.CommitCommon(context.Background(), &corestate.CommitCandidate{
		Verified: disk.State,
		Gossip:   disk.Gossip,
	}, corestate.ChangeSet{
		VerifiedRevision: disk.Revision,
		NetworkChanged:   true,
	}); err != nil {
		t.Fatalf("advance disk revision: %v", err)
	}

	committed, err := state.ReplaceEndpointACLsIfRevision(before.Revision, map[string]photonstate.EndpointACL{
		"stale": {Name: "stale"},
	})
	if !errors.Is(err, photonlinux.ErrLinuxStateSourceRevisionMismatch) || committed {
		t.Fatalf("stale disk Linux commit = committed %v err %v", committed, err)
	}
	if _, ok := state.ReadLinux().EndpointACLs["stale"]; ok {
		t.Fatal("rejected Linux state was published in memory")
	}
}

func TestOpenStateChecksExplicitRootWithoutWriting(t *testing.T) {
	rt := &AppContext{Config: defaultAppConfig(), StatePath: filepath.Join(t.TempDir(), "state.db")}
	root, err := initializeRootState(rt)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(rt.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	wrong := append(ed25519.PublicKey(nil), root...)
	wrong[0] ^= 0xff
	rt.Config.TrustedRootPublicKey = wrong
	state, err := openState(rt)
	if state != nil {
		state.Close()
		t.Fatal("opened state with wrong trust")
	}
	if err == nil || !strings.Contains(err.Error(), "does not match persisted state") {
		t.Fatalf("error = %v", err)
	}
	after, err := os.ReadFile(rt.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("rejected open changed database")
	}
	for _, key := range []ed25519.PublicKey{nil, root} {
		rt.Config.TrustedRootPublicKey = key
		state, err := openState(rt)
		if err != nil {
			t.Fatal(err)
		}
		if err := state.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
