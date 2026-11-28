package photonproxy

import (
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestV2ReplayPersistsAcrossRestartAndClockRollback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	now := time.Unix(1800000000, 0)
	open := func(at time.Time) *v2Replay {
		t.Helper()
		db, _, err := openRouteState(path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if replay, err := newV2Replay(db, at, false); err == nil {
			return replay
		} else {
			_ = db.Close()
			t.Fatal(err)
		}
		return nil
	}
	grant := v2Grant{origin: "sender.catofes.", nonce: "first", issued: now, expires: now.Add(v2Lifetime)}
	r := open(now)
	assertV2Replay(t, r, grant, now, true)
	if err := r.db.Close(); err != nil {
		t.Fatal(err)
	}
	intoGrace := grant.expires.Add(time.Second)
	r = open(intoGrace)
	assertV2Replay(t, r, grant, intoGrace, false)
	newer := v2Grant{origin: grant.origin, nonce: "second", issued: intoGrace, expires: intoGrace.Add(v2Lifetime)}
	assertV2Replay(t, r, newer, grant.acceptUntil(), true)
	if err := r.db.Close(); err != nil {
		t.Fatal(err)
	}
	r = open(intoGrace)
	defer r.db.Close()
	assertV2Replay(t, r, grant, intoGrace, false)
	assertV2Replay(t, r, newer, intoGrace, false)
}

func TestV2ReplayUpgradeCutoffAndConcurrentDuplicate(t *testing.T) {
	db, _, err := openRouteState(filepath.Join(t.TempDir(), "state.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Unix(1800000000, 0)
	r, err := newV2Replay(db, now, true)
	if err != nil {
		t.Fatal(err)
	}
	grant := v2Grant{origin: "sender.catofes.", nonce: "same", issued: now.Add(2 * time.Second), expires: now.Add(v2Lifetime)}
	assertV2Replay(t, r, grant, now, false)
	grant.issued = grant.issued.Add(time.Millisecond)
	var successes atomic.Int32
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			accepted, err := r.consume(grant, now)
			if err != nil {
				t.Error(err)
			}
			if accepted {
				successes.Add(1)
			}
		})
	}
	workers.Wait()
	if successes.Load() != 1 {
		t.Fatalf("accepted the same authorization %d times", successes.Load())
	}
}

func assertV2Replay(t *testing.T, replay *v2Replay, grant v2Grant, now time.Time, want bool) {
	t.Helper()
	if accepted, err := replay.consume(grant, now); err != nil || accepted != want {
		t.Fatalf("consume returned %t, %v, want %t", accepted, err, want)
	}
}
