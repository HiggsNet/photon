//go:build linux

package healthprobe

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestRawICMProberUsesWorkerAndPreservesBurstMajority(t *testing.T) {
	worker := &fakeRawICMPWorker{result: rawProbeResult{received: 2, lastRTT: 4 * time.Millisecond}}
	p := NewRawICMProber(nil)
	p.new = func(netns string) (rawICMPWorker, error) {
		if netns != "mesh-a" {
			t.Fatalf("worker netns = %q, want mesh-a", netns)
		}
		return worker, nil
	}
	target := ProbeTarget{InstanceID: "link-a", NetNS: "mesh-a", PeerTunnelAddr: netip.MustParseAddr("192.0.2.2")}
	got := p.Probe(context.Background(), target, ProbeConfig{Burst: 3})
	if !got.Success || got.RTT != 4*time.Millisecond || got.Err != nil {
		t.Fatalf("probe result = %+v, want successful majority result", got)
	}
	if worker.calls != 1 {
		t.Fatalf("worker calls = %d, want 1", worker.calls)
	}
	// The namespace worker is cached rather than recreated for every probe.
	_ = p.Probe(context.Background(), target, ProbeConfig{Burst: 3})
	if worker.calls != 2 {
		t.Fatalf("worker calls after second probe = %d, want 2", worker.calls)
	}
}

func TestRawICMProberReportsPacketCountsForEveryBurstOutcome(t *testing.T) {
	for _, received := range []int{3, 2, 1, 0} {
		t.Run(fmt.Sprintf("%d_of_3", received), func(t *testing.T) {
			worker := &fakeRawICMPWorker{result: rawProbeResult{sent: 3, received: received, lastRTT: 4 * time.Millisecond}}
			p := NewRawICMProber(nil)
			p.new = func(string) (rawICMPWorker, error) { return worker, nil }
			got := p.Probe(context.Background(), ProbeTarget{
				InstanceID:     "link-a",
				PeerTunnelAddr: netip.MustParseAddr("192.0.2.2"),
			}, ProbeConfig{Burst: 3})
			wantSuccess := received >= 2
			if got.Err != nil || got.Sent != 3 || got.Received != received || got.Lost != 3-received || got.Success != wantSuccess {
				t.Fatalf("probe result = %+v, want sent/received/lost=3/%d/%d success=%t", got, received, 3-received, wantSuccess)
			}
			if received == 0 && got.RTT != 0 {
				t.Fatalf("zero-reply RTT = %v, want zero", got.RTT)
			}
		})
	}
}

func TestRawICMProberUnansweredBurstIsReachabilityFailure(t *testing.T) {
	worker := &fakeRawICMPWorker{result: rawProbeResult{}}
	p := NewRawICMProber(nil)
	p.new = func(string) (rawICMPWorker, error) { return worker, nil }
	target := ProbeTarget{InstanceID: "link-a", PeerTunnelAddr: netip.MustParseAddr("192.0.2.2")}

	got := p.Probe(context.Background(), target, ProbeConfig{Burst: 3})
	if got.Success {
		t.Fatal("probe success = true, want false for an unanswered burst")
	}
	if got.Err != nil {
		t.Fatalf("probe error = %v, want ordinary packet loss to be a valid observation", got.Err)
	}
}

func TestRawICMProberFallsBackOnlyForUnavailableRawFailure(t *testing.T) {
	fallback := &countingRawFallback{}
	worker := &fakeRawICMPWorker{result: rawProbeResult{err: errors.New("operation not permitted"), unavailable: true}}
	var reportedTarget ProbeTarget
	var reportedErr error
	p := NewRawICMProber(fallback, func(target ProbeTarget, err error) {
		reportedTarget = target
		reportedErr = err
	})
	p.new = func(string) (rawICMPWorker, error) { return worker, nil }
	target := ProbeTarget{InstanceID: "link-a", PeerTunnelAddr: netip.MustParseAddr("192.0.2.2")}
	if got := p.Probe(context.Background(), target, ProbeConfig{}); !got.Success {
		t.Fatalf("fallback result = %+v, want success", got)
	}
	if fallback.calls != 1 {
		t.Fatalf("fallback calls = %d, want 1", fallback.calls)
	}
	if reportedTarget.InstanceID != target.InstanceID || reportedErr == nil || reportedErr.Error() != "operation not permitted" {
		t.Fatalf("fallback report = (%+v, %v), want target and raw setup error", reportedTarget, reportedErr)
	}

	worker.result = rawProbeResult{err: errors.New("network is unreachable")}
	reportedErr = nil
	got := p.Probe(context.Background(), target, ProbeConfig{})
	if got.Err == nil || got.Err.Error() != "network is unreachable" {
		t.Fatalf("network error = %v, want raw packet error", got.Err)
	}
	if fallback.calls != 1 {
		t.Fatalf("fallback calls after packet error = %d, want 1", fallback.calls)
	}
	if reportedErr != nil {
		t.Fatalf("packet error unexpectedly reported as fallback: %v", reportedErr)
	}

	worker.result = rawProbeResult{
		err:         fmt.Errorf("send raw ICMP echo: %w", unix.ENETUNREACH),
		unavailable: true,
		reopen:      true,
	}
	if got := p.Probe(context.Background(), target, ProbeConfig{}); !got.Success {
		t.Fatalf("stale-socket fallback result = %+v, want success", got)
	}
	if fallback.calls != 2 {
		t.Fatalf("fallback calls after stale socket = %d, want 2", fallback.calls)
	}
	if !errors.Is(reportedErr, unix.ENETUNREACH) {
		t.Fatalf("stale-socket fallback report = %v, want ENETUNREACH", reportedErr)
	}
}

func TestRawICMProberFallsBackWhenNamespaceWorkerCannotStart(t *testing.T) {
	fallback := &countingRawFallback{}
	p := NewRawICMProber(fallback)
	p.new = func(string) (rawICMPWorker, error) {
		return nil, errors.New("setns: operation not permitted")
	}
	target := ProbeTarget{InstanceID: "link-a", NetNS: "mesh-a", PeerTunnelAddr: netip.MustParseAddr("192.0.2.2")}
	if got := p.Probe(context.Background(), target, ProbeConfig{}); !got.Success {
		t.Fatalf("fallback result = %+v, want success", got)
	}
	if fallback.calls != 1 {
		t.Fatalf("fallback calls = %d, want 1", fallback.calls)
	}
}

func TestRawICMPNamespaceWorkerRunsDifferentSocketsConcurrently(t *testing.T) {
	started := make(chan string, 2)
	release := make(chan struct{})
	var nextFD atomic.Int32
	var active atomic.Int32
	var maxActive atomic.Int32
	worker := &rawICMPNamespaceWorker{
		jobs: make(chan rawICMPJob),
		done: make(chan struct{}),
		openSocket: func(rawSocketKey) (int, uint32, error) {
			return int(nextFD.Add(1)), 0, nil
		},
		closeSocket: func(int) error { return nil },
		probeSocket: func(_ rawICMPJob, key rawSocketKey, _ int, _ uint32) rawProbeResult {
			current := active.Add(1)
			for {
				previous := maxActive.Load()
				if current <= previous || maxActive.CompareAndSwap(previous, current) {
					break
				}
			}
			started <- key.iface
			<-release
			active.Add(-1)
			return rawProbeResult{received: 1}
		},
	}
	ready := make(chan error, 1)
	go worker.run(ready)
	if err := <-ready; err != nil {
		t.Fatalf("start raw worker: %v", err)
	}
	t.Cleanup(worker.close)

	var seq atomic.Uint32
	results := make(chan rawProbeResult, 2)
	for i, target := range []ProbeTarget{
		{InstanceID: "old", InterfaceName: "phx-old", LocalTunnelAddr: netip.MustParseAddr("fe80::1"), PeerTunnelAddr: netip.MustParseAddr("fe80::2")},
		{InstanceID: "active", InterfaceName: "phx-active", LocalTunnelAddr: netip.MustParseAddr("fe80::3"), PeerTunnelAddr: netip.MustParseAddr("fe80::4")},
	} {
		go func(i int, target ProbeTarget) {
			results <- worker.probe(context.Background(), target, ProbeConfig{Burst: 1}, uint16(i+1), &seq)
		}(i, target)
	}
	for range 2 {
		select {
		case <-started:
		case <-time.After(time.Second):
			close(release)
			worker.close()
			t.Fatal("different raw ICMP sockets did not start concurrently")
		}
	}
	gotMaxActive := maxActive.Load()
	close(release)
	for range 2 {
		if result := <-results; result.received != 1 || result.err != nil {
			t.Fatalf("probe result = %+v, want one reply", result)
		}
	}
	worker.close()
	if gotMaxActive != 2 {
		t.Fatalf("maximum active socket probes = %d, want 2", gotMaxActive)
	}
}

func TestRawICMPSocketSerializesSharedSocket(t *testing.T) {
	socket := newRawICMPSocket(1, 0)
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	var active atomic.Int32
	var maxActive atomic.Int32
	run := func(rawICMPJob, rawSocketKey, int, uint32) rawProbeResult {
		current := active.Add(1)
		for {
			previous := maxActive.Load()
			if current <= previous || maxActive.CompareAndSwap(previous, current) {
				break
			}
		}
		started <- struct{}{}
		<-release
		active.Add(-1)
		return rawProbeResult{received: 1}
	}
	results := make(chan rawProbeResult, 2)
	for range 2 {
		go func() {
			results <- socket.probe(rawICMPJob{ctx: context.Background()}, rawSocketKey{}, run)
		}()
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first shared-socket probe did not start")
	}
	select {
	case <-started:
		t.Fatal("shared-socket probes ran concurrently")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	for range 2 {
		if result := <-results; result.received != 1 || result.err != nil {
			t.Fatalf("probe result = %+v, want one reply", result)
		}
	}
	if got := maxActive.Load(); got != 1 {
		t.Fatalf("maximum active shared-socket probes = %d, want 1", got)
	}
}

func TestWaitRawICMPReturnsAsSoonAsBurstCompletes(t *testing.T) {
	started := time.Now()
	calls := 0
	err := waitRawICMP(context.Background(), -1, started.Add(time.Second), func() (bool, error) {
		calls++
		return true, nil
	})
	if err != nil {
		t.Fatalf("waitRawICMP: %v", err)
	}
	if calls != 1 {
		t.Fatalf("drain calls = %d, want 1", calls)
	}
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("completed burst waited %s, want immediate return", elapsed)
	}
}

func TestRawICMPNamespaceWorkerFallsBackAndRateLimitsStaleSocketReopen(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	var opens atomic.Int32
	var closes atomic.Int32
	var probes atomic.Int32
	worker := &rawICMPNamespaceWorker{
		jobs: make(chan rawICMPJob),
		done: make(chan struct{}),
		openSocket: func(rawSocketKey) (int, uint32, error) {
			return int(opens.Add(1)), 42, nil
		},
		closeSocket: func(int) error {
			closes.Add(1)
			return nil
		},
		probeSocket: func(_ rawICMPJob, _ rawSocketKey, _ int, _ uint32) rawProbeResult {
			if probes.Add(1) == 1 {
				return rawProbeResult{
					err:         fmt.Errorf("send raw ICMP echo: %w", unix.ENETUNREACH),
					unavailable: true,
					reopen:      true,
				}
			}
			return rawProbeResult{received: 1}
		},
		now: func() time.Time { return now },
	}
	ready := make(chan error, 1)
	go worker.run(ready)
	if err := <-ready; err != nil {
		t.Fatalf("start raw worker: %v", err)
	}
	t.Cleanup(worker.close)

	var seq atomic.Uint32
	target := ProbeTarget{
		InstanceID:      "link-a",
		InterfaceName:   "phx0",
		LocalTunnelAddr: netip.MustParseAddr("fe80::1"),
		PeerTunnelAddr:  netip.MustParseAddr("fe80::2"),
	}
	cfg := ProbeConfig{Burst: 1, Interval: 5 * time.Second}
	first := worker.probe(context.Background(), target, cfg, 1, &seq)
	if !first.unavailable || !first.reopen || !errors.Is(first.err, unix.ENETUNREACH) {
		t.Fatalf("first result = %+v, want recoverable send error", first)
	}
	if opens.Load() != 1 || closes.Load() != 1 || probes.Load() != 1 {
		t.Fatalf("after stale result opens/closes/probes = %d/%d/%d, want 1/1/1", opens.Load(), closes.Load(), probes.Load())
	}

	second := worker.probe(context.Background(), target, cfg, 1, &seq)
	if !second.unavailable || second.reopen {
		t.Fatalf("backoff result = %+v, want fallback without another reopen", second)
	}
	if opens.Load() != 1 || probes.Load() != 1 {
		t.Fatalf("backoff opened or probed again: opens/probes = %d/%d", opens.Load(), probes.Load())
	}

	now = now.Add(rawICMPSocketReopenDelay(cfg.Interval, 1))
	third := worker.probe(context.Background(), target, cfg, 1, &seq)
	if third.err != nil || third.received != 1 {
		t.Fatalf("reopened result = %+v, want one reply", third)
	}
	if opens.Load() != 2 || probes.Load() != 2 {
		t.Fatalf("after cooldown opens/probes = %d/%d, want 2/2", opens.Load(), probes.Load())
	}
}

func TestRawICMPSocketReopenDelayBacksOffAndCaps(t *testing.T) {
	interval := 5 * time.Second
	want := []time.Duration{15 * time.Second, 30 * time.Second, time.Minute, 2 * time.Minute, 2 * time.Minute}
	for i, expected := range want {
		if got := rawICMPSocketReopenDelay(interval, i+1); got != expected {
			t.Errorf("delay for failure %d = %s, want %s", i+1, got, expected)
		}
	}
}

func TestShouldReopenRawICMPSocket(t *testing.T) {
	for _, err := range []error{unix.ENETUNREACH, unix.ENODEV, unix.EADDRNOTAVAIL} {
		if !shouldReopenRawICMPSocket(fmt.Errorf("send: %w", err)) {
			t.Errorf("shouldReopenRawICMPSocket(%v) = false, want true", err)
		}
	}
	if shouldReopenRawICMPSocket(unix.EPERM) {
		t.Fatal("shouldReopenRawICMPSocket(EPERM) = true, want false")
	}
}

func TestRawDestinationUsesZoneCapturedInNamespace(t *testing.T) {
	target := ProbeTarget{
		InterfaceName:  "only-visible-inside-netns",
		PeerTunnelAddr: netip.MustParseAddr("fe80::2"),
	}
	destination, ok := rawDestination(target, unix.AF_INET6, 42).(*unix.SockaddrInet6)
	if !ok {
		t.Fatalf("destination type = %T, want IPv6", destination)
	}
	if destination.ZoneId != 42 {
		t.Fatalf("destination zone = %d, want 42", destination.ZoneId)
	}
}

func TestParseRawICMPReply(t *testing.T) {
	v4 := make([]byte, 20+8)
	v4[0] = 0x45
	v4[20] = 0 // echo reply
	v4[24], v4[25] = 0x12, 0x34
	v4[26], v4[27] = 0x00, 0x09
	if seq, ok := parseRawICMPReply(v4, 2, 0x1234); !ok || seq != 9 {
		t.Fatalf("IPv4 reply = (%d, %t), want (9, true)", seq, ok)
	}
	v6 := []byte{129, 0, 0, 0, 0xab, 0xcd, 0x00, 0x0a}
	if seq, ok := parseRawICMPReply(v6, 10, 0xabcd); !ok || seq != 10 {
		t.Fatalf("IPv6 reply = (%d, %t), want (10, true)", seq, ok)
	}
}

func TestMakeICMPEchoPacketHasValidIPv4Checksum(t *testing.T) {
	packet := makeICMPEchoPacket(2, 0x1234, 0x5678)
	if packet[0] != 8 || internetChecksum(packet) != 0 {
		t.Fatalf("IPv4 echo packet = %x, want echo request with valid checksum", packet)
	}
}

type fakeRawICMPWorker struct {
	result rawProbeResult
	calls  int
}

func (w *fakeRawICMPWorker) probe(context.Context, ProbeTarget, ProbeConfig, uint16, *atomic.Uint32) rawProbeResult {
	w.calls++
	return w.result
}

func (w *fakeRawICMPWorker) close() {}

type countingRawFallback struct{ calls int }

func (p *countingRawFallback) Probe(_ context.Context, target ProbeTarget, _ ProbeConfig) ProbeResult {
	p.calls++
	return ProbeResult{InstanceID: target.InstanceID, RTT: 2 * time.Millisecond, Success: true}
}

func (*countingRawFallback) Type() string { return ProbeTypeICMP }
