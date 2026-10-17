package health

import (
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestRollingWindowSnapshotAfterReset(t *testing.T) {
	w := NewRollingWindow(2)
	if w.Snapshot() != (WindowSnapshot{}) {
		t.Fatal("new window is not empty")
	}
	now := time.Unix(1000, 0)
	w.Record(now, 10*time.Millisecond, true)
	snap := w.Snapshot()
	snap.Sent = 999
	if w.Snapshot().Sent != 1 {
		t.Fatal("snapshot aliases window")
	}
	w.Reset()
	if got := w.Snapshot(); got != (WindowSnapshot{}) {
		t.Fatalf("reset retained statistics: %+v", got)
	}
	w.RecordProbe(now.Add(time.Second), ProbeResult{Sent: 4, Received: 1, Lost: 3, RTT: 20 * time.Millisecond})
	got := w.Snapshot()
	if got.Bursts != 1 || got.Sent != 4 || got.Received != 1 || got.Lost != 3 || got.EWMARTT != 20*time.Millisecond || got.MinRTT != 20*time.Millisecond {
		t.Fatalf("new burst did not replace reset statistics: %+v", got)
	}
}

func TestRollingWindowConcurrentSnapshots(t *testing.T) {
	w := NewRollingWindow(20)
	now := time.Unix(1000, 0)
	var readers sync.WaitGroup
	for range 4 {
		readers.Go(func() {
			for range 200 {
				snap := w.Snapshot()
				if snap.Sent != snap.Received+snap.Lost || snap.Bursts > 20 {
					t.Errorf("inconsistent snapshot: %+v", snap)
				}
			}
		})
	}
	for i := range 200 {
		w.Record(now.Add(time.Duration(i)*time.Second), time.Duration(i+1)*time.Millisecond, true)
	}
	readers.Wait()
	if got := w.Snapshot(); got.Bursts != 20 || got.LastRTT != 200*time.Millisecond {
		t.Fatalf("missing latest samples: %+v", got)
	}
}

func BenchmarkRollingWindowRecordAndSnapshot(b *testing.B) {
	w := NewRollingWindow(20)
	now := time.Unix(1000, 0)
	for i := range 20 {
		w.Record(now, time.Duration(i+1)*time.Millisecond, true)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.Record(now, time.Duration(i%37+1)*time.Millisecond, true)
		w.Snapshot()
	}
}

var managerSnapshotResult []LinkHealth

func BenchmarkManagerSnapshot38(b *testing.B) {
	for _, update := range []bool{false, true} {
		b.Run("update="+strconv.FormatBool(update), func(b *testing.B) {
			m := NewManager(ProbeConfig{LossWindow: 20}, DefaultHysteresisConfig(), nil)
			now := time.Unix(1000, 0)
			ids := make([]string, 38)
			for i := range ids {
				ids[i] = "link-" + strconv.Itoa(i)
				m.UpsertTarget(ProbeTarget{InstanceID: ids[i], State: "up"}, now)
				for j := range 20 {
					m.applyResult(ids[i], ProbeResult{Sent: 3, Received: 3, RTT: time.Duration((j*37)%101+1) * time.Millisecond, Success: true}, now)
				}
			}
			m.Snapshot(now)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if update {
					m.applyResult(ids[i%len(ids)], ProbeResult{Sent: 3, Received: 3, RTT: time.Duration(i%37+1) * time.Millisecond, Success: true}, now)
				}
				managerSnapshotResult = m.Snapshot(now)
			}
		})
	}
}
