package health

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func TestAsyncProbeCannotCompleteForReplacedTarget(t *testing.T) {
	for _, mode := range []string{"set", "upsert", "remove_recreate"} {
		t.Run(mode, func(t *testing.T) {
			cfg := ProbeConfig{Interval: time.Second, Timeout: time.Second, Burst: 1, LossWindow: 5, MaxConcurrent: 1}
			prober := newBlockingProber()
			m := NewManager(cfg, DefaultHysteresisConfig(), prober)
			ctx, cancel := context.WithCancel(t.Context())
			defer func() { cancel(); m.WaitAsync() }()
			defer close(prober.release)
			updates := m.StartAsync(ctx)
			now := time.Now()
			target := ProbeTarget{ProbeID: "link#staged", InstanceID: "link", InterfaceName: "old", Generation: 1, PeerTunnelAddr: netip.MustParseAddr("10.0.0.2"), State: "staged", Staged: true}
			m.UpsertTarget(target, now)
			if m.TickAsync(ctx, now.Add(2*time.Second)) != 1 {
				t.Fatal("old target was not probed")
			}
			select {
			case <-prober.started:
			case <-time.After(time.Second):
				t.Fatal("old probe did not start")
			}
			target.InterfaceName, target.Generation = "new", 2
			switch mode {
			case "set":
				m.SetTargets([]ProbeTarget{target}, now)
			case "upsert":
				m.UpsertTarget(target, now)
			case "remove_recreate":
				m.RemoveTarget(target.ProbeID)
				m.UpsertTarget(target, now)
			}
			// Complete only the old probe. A success must not open the
			// activation gate for the new staged interface under the same ID.
			prober.release <- struct{}{}
			select {
			case <-updates:
			case <-time.After(time.Second):
				t.Fatal("old probe did not finish")
			}
			got := m.Snapshot(time.Now())[0]
			if got.Sent != 0 || m.RotateActivationReadiness()["link"] {
				t.Fatalf("old probe contaminated the replacement target: %+v", got)
			}
			if m.TickAsync(ctx, now.Add(4*time.Second)) != 1 {
				t.Fatal("replacement target did not get its own probe")
			}
			prober.release <- struct{}{}
			select {
			case <-updates:
			case <-time.After(time.Second):
				t.Fatal("replacement probe did not finish")
			}
			if got := m.Snapshot(time.Now())[0]; got.Received != 1 || !m.RotateActivationReadiness()["link"] {
				t.Fatalf("fresh result did not belong to the replacement: %+v", got)
			}
		})
	}
}

func TestRemoveTargetKeepsRunningProbeInConcurrencyBudget(t *testing.T) {
	m := NewManager(ProbeConfig{Interval: time.Second, MaxConcurrent: 1}, DefaultHysteresisConfig(), nil)
	now := time.Now()
	m.UpsertTarget(ProbeTarget{InstanceID: "old", State: "up"}, now)
	if len(m.reserveDue(t.Context(), now.Add(2*time.Second))) != 1 {
		t.Fatal("old probe was not reserved")
	}
	m.RemoveTarget("old")
	m.UpsertTarget(ProbeTarget{InstanceID: "new", State: "up"}, now)
	if got := len(m.reserveDue(t.Context(), now.Add(2*time.Second))); got != 0 {
		t.Fatal("removing the target released a slot while its probe was still running")
	}
}

func TestProbeHistoryResetsOnlyForNewTargetIdentity(t *testing.T) {
	m := NewManager(ProbeConfig{Interval: time.Second, Burst: 1, LossWindow: 5}, DefaultHysteresisConfig(), &fakeProber{success: true})
	now := time.Now()
	target := ProbeTarget{InstanceID: "link", InterfaceName: "old", Generation: 1, State: "connecting"}
	m.UpsertTarget(target, now)
	m.Tick(t.Context(), now.Add(2*time.Second))
	target.State = "up"
	m.SetTargets([]ProbeTarget{target}, now)
	if got := m.Snapshot(now)[0].Received; got != 1 {
		t.Fatal("ordinary link state transition discarded usable probe history")
	}
	target.InterfaceName, target.Generation = "new", 2
	m.SetTargets([]ProbeTarget{target}, now)
	if got := m.Snapshot(now)[0].Received; got != 0 {
		t.Fatal("new interface inherited old interface's probe history")
	}
}
