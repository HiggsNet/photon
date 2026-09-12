package healthprobe

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestICMProberScopedLinkLocalUsesPortablePing(t *testing.T) {
	runner := &recordingCommandRunner{}
	prober := NewICMProber(runner)
	target := ProbeTarget{
		InstanceID:      "link-1",
		NetNS:           "photontesth2",
		InterfaceName:   "phx431bcb9f",
		LocalTunnelAddr: netip.MustParseAddr("fe80::7888:86ec:66e0:2620"),
		PeerTunnelAddr:  netip.MustParseAddr("fe80::b09d:5f83:3e81:d064"),
		State:           "up",
	}

	result := prober.Probe(context.Background(), target, ProbeConfig{
		Timeout: 50 * time.Millisecond,
		Burst:   1,
	})
	if !result.Success {
		t.Fatalf("probe success = false, error=%v", result.Err)
	}
	if runner.name != "ip" {
		t.Fatalf("command name = %q, want ip", runner.name)
	}
	want := []string{
		"netns", "exec", "photontesth2",
		"ping", "-6", "-n", "-c", "1",
		"-W", "0.05",
		"-I", "fe80::7888:86ec:66e0:2620%phx431bcb9f",
		"fe80::b09d:5f83:3e81:d064%phx431bcb9f",
	}
	if !reflect.DeepEqual(runner.args, want) {
		t.Fatalf("command args = %#v, want %#v", runner.args, want)
	}
	for _, arg := range runner.args {
		if arg == "ping6" {
			t.Fatalf("command args include non-portable ping binary: %#v", runner.args)
		}
	}
}

func TestICMProberIncludesPingOutputInError(t *testing.T) {
	runner := &recordingCommandRunner{
		out: []byte("connect: Network is unreachable\n"),
		err: errors.New("exit status 2"),
	}
	prober := NewICMProber(runner)
	target := ProbeTarget{
		InstanceID:     "link-1",
		NetNS:          "photontesth2",
		InterfaceName:  "phx0",
		PeerTunnelAddr: netip.MustParseAddr("fe80::2"),
		State:          "up",
	}

	result := prober.Probe(context.Background(), target, ProbeConfig{
		Timeout: 50 * time.Millisecond,
		Burst:   1,
	})
	if result.Success {
		t.Fatal("probe success = true, want false")
	}
	if result.Err == nil || !strings.Contains(result.Err.Error(), "Network is unreachable") {
		t.Fatalf("probe error = %v, want ping output", result.Err)
	}
}

func TestICMProberRetriesScopedLinkLocalWithoutSourceOnBindInvalid(t *testing.T) {
	runner := &scriptedCommandRunner{
		results: []commandResult{
			{
				out: []byte("ping: bind icmp socket: Invalid argument\n"),
				err: errors.New("exit status 2"),
			},
			{},
		},
	}
	prober := NewICMProber(runner)
	target := ProbeTarget{
		InstanceID:      "link-1",
		NetNS:           "photontesth2",
		InterfaceName:   "phx0",
		LocalTunnelAddr: netip.MustParseAddr("fe80::1"),
		PeerTunnelAddr:  netip.MustParseAddr("fe80::2"),
		State:           "up",
	}

	result := prober.Probe(context.Background(), target, ProbeConfig{
		Timeout: 50 * time.Millisecond,
		Burst:   1,
	})
	if !result.Success {
		t.Fatalf("probe success = false, error=%v", result.Err)
	}
	want := [][]string{
		{
			"netns", "exec", "photontesth2",
			"ping", "-6", "-n", "-c", "1",
			"-W", "0.05",
			"-I", "fe80::1%phx0",
			"fe80::2%phx0",
		},
		{
			"netns", "exec", "photontesth2",
			"ping", "-6", "-n", "-c", "1",
			"-W", "0.05",
			"fe80::2%phx0",
		},
	}
	if !reflect.DeepEqual(runner.calls, want) {
		t.Fatalf("command calls = %#v, want %#v", runner.calls, want)
	}
}

func TestICMProberRunsBurstInOneProcess(t *testing.T) {
	runner := &recordingCommandRunner{out: []byte(`64 bytes from 192.0.2.2: icmp_seq=1 ttl=64 time=1.25 ms
64 bytes from 192.0.2.2: icmp_seq=2 ttl=64 time=2.50 ms
64 bytes from 192.0.2.2: icmp_seq=3 ttl=64 time=3.75 ms
3 packets transmitted, 3 received, 0% packet loss
`)}
	prober := NewICMProber(runner)
	target := ProbeTarget{
		InstanceID:     "link-1",
		NetNS:          "photontesth2",
		PeerTunnelAddr: netip.MustParseAddr("192.0.2.2"),
		State:          "up",
	}

	result := prober.Probe(context.Background(), target, ProbeConfig{Timeout: time.Second, Burst: 3})
	if !result.Success {
		t.Fatalf("probe success = false, error=%v", result.Err)
	}
	if result.RTT != 3750*time.Microsecond {
		t.Fatalf("probe RTT = %s, want 3.75ms", result.RTT)
	}
	want := []string{"netns", "exec", "photontesth2", "ping", "-n", "-c", "3", "-i", "0.2", "-W", "1", "192.0.2.2"}
	if !reflect.DeepEqual(runner.args, want) {
		t.Fatalf("command args = %#v, want %#v", runner.args, want)
	}
}

func TestICMProberUnansweredBurstIsReachabilityFailure(t *testing.T) {
	// With -W the ping process exits on its own with a loss summary instead of
	// lingering until the context deadline kills it ("signal: killed").
	runner := &recordingCommandRunner{
		out: []byte("3 packets transmitted, 0 received, 100% packet loss, time 2040ms\n"),
		err: errors.New("exit status 1"),
	}
	prober := NewICMProber(runner)
	target := ProbeTarget{InstanceID: "link-1", PeerTunnelAddr: netip.MustParseAddr("192.0.2.2"), State: "up"}

	result := prober.Probe(context.Background(), target, ProbeConfig{Timeout: time.Second, Burst: 3})
	if result.Success {
		t.Fatal("probe success = true, want false for an unanswered burst")
	}
	if result.Err != nil {
		t.Fatalf("probe error = %v, want ordinary packet loss to be a valid observation", result.Err)
	}
}

func TestICMProberBurstRequiresMajorityOfReplies(t *testing.T) {
	runner := &recordingCommandRunner{
		out: []byte(`64 bytes from 192.0.2.2: icmp_seq=1 ttl=64 time=1.25 ms
3 packets transmitted, 1 received, 66% packet loss
`),
		err: errors.New("exit status 1"),
	}
	prober := NewICMProber(runner)
	target := ProbeTarget{InstanceID: "link-1", PeerTunnelAddr: netip.MustParseAddr("192.0.2.2"), State: "up"}

	result := prober.Probe(context.Background(), target, ProbeConfig{Timeout: time.Second, Burst: 3})
	if result.Success {
		t.Fatal("probe success = true, want false for one reply in a three-packet burst")
	}
	if result.Err != nil {
		t.Fatalf("probe error = %v, want partial loss without a command error", result.Err)
	}
}

func TestICMProberReportsPacketCountsForEveryBurstOutcome(t *testing.T) {
	tests := []struct {
		name     string
		received int
		success  bool
	}{
		{name: "3_of_3", received: 3, success: true},
		{name: "2_of_3", received: 2, success: true},
		{name: "1_of_3", received: 1, success: false},
		{name: "0_of_3", received: 0, success: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output strings.Builder
			for seq := 1; seq <= tt.received; seq++ {
				fmt.Fprintf(&output, "64 bytes from 192.0.2.2: icmp_seq=%d ttl=64 time=%d ms\n", seq, seq)
			}
			fmt.Fprintf(&output, "3 packets transmitted, %d received, packet loss\n", tt.received)
			var runErr error
			if tt.received < 3 {
				runErr = errors.New("exit status 1")
			}
			runner := &recordingCommandRunner{out: []byte(output.String()), err: runErr}
			prober := NewICMProber(runner)
			result := prober.Probe(context.Background(), ProbeTarget{
				InstanceID:     "link-1",
				PeerTunnelAddr: netip.MustParseAddr("192.0.2.2"),
			}, ProbeConfig{Timeout: time.Second, Burst: 3})
			if result.Err != nil || result.Sent != 3 || result.Received != tt.received || result.Lost != 3-tt.received || result.Success != tt.success {
				t.Fatalf("probe result = %+v, want sent/received/lost=3/%d/%d success=%t", result, tt.received, 3-tt.received, tt.success)
			}
			if tt.received == 0 && result.RTT != 0 {
				t.Fatalf("zero-reply RTT = %v, want zero", result.RTT)
			}
		})
	}
}

func TestParsePingBurstOutput(t *testing.T) {
	received, lastRTT := parsePingBurstOutput([]byte(`3 packets transmitted, 2 packets received, 33% packet loss
64 bytes from 192.0.2.2: icmp_seq=1 ttl=64 time=0.125 ms
64 bytes from 192.0.2.2: icmp_seq=2 ttl=64 time<1 ms
`))
	if received != 2 {
		t.Fatalf("received = %d, want 2", received)
	}
	if lastRTT != time.Millisecond {
		t.Fatalf("last RTT = %s, want 1ms", lastRTT)
	}
}

func TestPingTargetAddressScopesLinkLocal(t *testing.T) {
	target := ProbeTarget{
		InstanceID:     "link-1",
		InterfaceName:  "phx0",
		PeerTunnelAddr: netip.MustParseAddr("fe80::2"),
		State:          "up",
	}

	if got := pingTargetAddress(target); got != "fe80::2%phx0" {
		t.Fatalf("ping target address = %q, want scoped link-local", got)
	}
}

func TestPingSourceAddressPrefersLocalTunnelAddressForLinkLocalTarget(t *testing.T) {
	target := ProbeTarget{
		InstanceID:      "link-1",
		InterfaceName:   "phx0",
		LocalTunnelAddr: netip.MustParseAddr("fe80::1"),
		PeerTunnelAddr:  netip.MustParseAddr("fe80::2"),
		State:           "up",
	}

	if got := pingSourceAddress(target); got != "fe80::1%phx0" {
		t.Fatalf("ping source address = %q, want scoped local tunnel address", got)
	}
}

func TestPingSourceAddressPrefersLocalTunnelAddressForNonLinkLocalTarget(t *testing.T) {
	target := ProbeTarget{
		InstanceID:      "link-1",
		InterfaceName:   "phx0",
		LocalTunnelAddr: netip.MustParseAddr("fd00::1"),
		PeerTunnelAddr:  netip.MustParseAddr("fd00::2"),
		State:           "up",
	}

	if got := pingSourceAddress(target); got != "fd00::1" {
		t.Fatalf("ping source address = %q, want local tunnel address", got)
	}
}

func TestPingSourceAddressFallsBackToInterface(t *testing.T) {
	target := ProbeTarget{
		InstanceID:     "link-1",
		InterfaceName:  "phx0",
		PeerTunnelAddr: netip.MustParseAddr("fe80::2"),
		State:          "up",
	}

	if got := pingSourceAddress(target); got != "phx0" {
		t.Fatalf("ping source address = %q, want interface fallback", got)
	}
}

type recordingCommandRunner struct {
	name string
	args []string
	out  []byte
	err  error
}

func (r *recordingCommandRunner) Run(ctx context.Context, name string, args []string) ([]byte, error) {
	r.name = name
	r.args = append([]string(nil), args...)
	return r.out, r.err
}

type commandResult struct {
	out []byte
	err error
}

type scriptedCommandRunner struct {
	calls   [][]string
	results []commandResult
}

func (r *scriptedCommandRunner) Run(ctx context.Context, name string, args []string) ([]byte, error) {
	r.calls = append(r.calls, append([]string(nil), args...))
	if len(r.results) == 0 {
		return nil, nil
	}
	result := r.results[0]
	r.results = r.results[1:]
	return result.out, result.err
}
