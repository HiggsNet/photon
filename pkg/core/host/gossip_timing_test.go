package host

import (
	"testing"
	"time"
)

func TestGossipSlowOperationRateLimitPreservesWorstSample(t *testing.T) {
	var logs []GossipDriverLog
	driver := NewGossipDriver(nil, 64, nil, GossipDriverConfig{})
	defer driver.Stop()
	driver.gossipConfig.Log = func(event GossipDriverLog) {
		// Logging must not hold the driver lock.
		_ = driver.GossipConfig()
		logs = append(logs, event)
	}
	now := time.Unix(100, 0)
	driver.logSlowOperation("snapshot_apply", 150*time.Millisecond, now, 3)
	driver.logSlowOperation("snapshot_apply", 2*time.Second, now.Add(time.Second), 64)
	driver.logSlowOperation("snapshot_apply", 200*time.Millisecond, now.Add(2*time.Second), 8)
	if len(logs) != 1 {
		t.Fatalf("burst emitted %d logs, want 1", len(logs))
	}
	// A slow checkpoint must not hide another stage's slow sample.
	driver.logSlowOperation("observed_checkpoint", 300*time.Millisecond, now.Add(2*time.Second), 10)
	if len(logs) != 2 || logs[1].Phase != "observed_checkpoint" {
		t.Fatalf("independent stage logs = %#v", logs)
	}
	driver.events <- GossipPacketReceived{}
	driver.logSlowOperation("snapshot_apply", 120*time.Millisecond, now.Add(30*time.Second), 4)
	if len(logs) != 3 {
		t.Fatalf("logs = %d, want 3", len(logs))
	}
	got := logs[2]
	if got.Event != "slow_operation" || got.Level != "warn" || got.Phase != "snapshot_apply" {
		t.Fatalf("unexpected event: %#v", got)
	}
	want := map[string]any{
		"elapsed_ms": int64(120), "max_elapsed_ms": int64(2000), "suppressed": 2,
		"queue_before": 4, "queue_after": 1, "queue_capacity": 64, "max_sampled_queue": 64,
	}
	for key, value := range want {
		if got.Fields[key] != value {
			t.Errorf("%s = %v, want %v", key, got.Fields[key], value)
		}
	}
	driver.logSlowOperation("snapshot_apply", 110*time.Millisecond, now.Add(time.Minute), 2)
	if logs[3].Fields["suppressed"] != 0 || logs[3].Fields["max_elapsed_ms"] != int64(110) {
		t.Fatalf("aggregation did not reset: %#v", logs[3])
	}
}

func TestGossipOperationTimingFastPathDoesNotAllocate(t *testing.T) {
	driver := NewGossipDriver(nil, 64, nil, GossipDriverConfig{Log: func(event GossipDriverLog) {
		t.Errorf("fast operation logged: %#v", event)
	}})
	defer driver.Stop()
	allocs := testing.AllocsPerRun(1000, func() {
		defer driver.LogSlowOperation("host_event", time.Now(), driver.PendingEventCount())
	})
	if allocs != 0 || driver.slowOperations != nil {
		t.Fatalf("fast path allocations=%v, aggregation=%v", allocs, driver.slowOperations)
	}
}

func BenchmarkGossipOperationTiming(b *testing.B) {
	driver := NewGossipDriver(nil, 64, nil, GossipDriverConfig{Log: func(GossipDriverLog) {}})
	defer driver.Stop()
	b.ReportAllocs()
	for b.Loop() {
		func() {
			defer driver.LogSlowOperation("host_event", time.Now(), driver.PendingEventCount())
		}()
	}
}
