package healthprobe

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// CommandRunner abstracts running a command in a netns for testing.
type CommandRunner interface {
	Run(ctx context.Context, name string, args []string) ([]byte, error)
}

// ExecRunner runs commands via os/exec.
type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, name string, args []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.CombinedOutput()
}

// ICMProber implements Prober using ICMP echo. It requires CAP_NET_RAW (or
// a ping binary with the needed capability/setuid setup). Probes are dispatched
// in the target netns and bind to the source/interface when possible.
type ICMProber struct {
	runner CommandRunner
}

const pingBurstInterval = 200 * time.Millisecond

var (
	pingReplyTimePattern = regexp.MustCompile(`time[=<]([0-9]+(?:\.[0-9]+)?)\s*ms`)
	pingReceivedPattern  = regexp.MustCompile(`(?:^|[,\s])(\d+)\s+(?:packets?\s+)?received(?:[,\s]|$)`)
)

// NewICMProber creates the portable Linux exec-based ICMP prober.
func NewICMProber(runner CommandRunner) *ICMProber {
	if runner == nil {
		runner = ExecRunner{}
	}
	return &ICMProber{runner: runner}
}

func (p *ICMProber) Type() string { return ProbeTypeICMP }

// Probe sends a burst of ICMP echo requests and aggregates the result.
func (p *ICMProber) Probe(ctx context.Context, target ProbeTarget, cfg ProbeConfig) ProbeResult {
	if !target.PeerTunnelAddr.IsValid() {
		return ProbeResult{InstanceID: target.InstanceID, Err: errors.New("peer address missing")}
	}
	burst := cfg.Burst
	if burst <= 0 {
		burst = 3
	}
	received, lastRTT, err := p.pingBurstExec(ctx, target, cfg.Timeout, burst)
	if err != nil {
		return ProbeResult{InstanceID: target.InstanceID, Err: err}
	}
	if received < 0 {
		received = 0
	}
	if received > burst {
		received = burst
	}
	return ProbeResult{
		InstanceID: target.InstanceID,
		Sent:       burst,
		Received:   received,
		Lost:       burst - received,
		RTT:        lastRTT,
		Success:    received > burst-received,
	}
}

// pingBurstExec executes one ping process for a whole probe burst. Starting a
// separate `ip netns exec ping -c 1` process for every packet is expensive:
// each invocation forks, enters the netns and performs mount setup.
func (p *ICMProber) pingBurstExec(ctx context.Context, target ProbeTarget, timeout time.Duration, burst int) (int, time.Duration, error) {
	if timeout <= 0 {
		timeout = time.Second
	}
	if burst <= 0 {
		burst = 1
	}
	run := func(includeSource bool) (int, time.Duration, []byte, error) {
		// The old implementation allowed one timeout per ping. Keep that total
		// budget while issuing the burst through a single process.
		deadline, cancel := context.WithTimeout(ctx, timeout*time.Duration(burst))
		defer cancel()
		start := time.Now()
		out, err := p.runner.Run(deadline, "ip", pingArgsForCount(target, includeSource, burst, timeout))
		received, lastRTT := parsePingBurstOutput(out)
		if received == 0 && err == nil {
			// Successful ping implementations always report replies, but tolerate
			// wrappers whose stdout is intentionally suppressed.
			received = burst
			lastRTT = time.Since(start)
		}
		return received, lastRTT, out, err
	}
	received, lastRTT, out, err := run(true)
	if err != nil && shouldRetryWithoutPingSource(target, out) {
		received, lastRTT, out, err = run(false)
	}
	if received > 0 {
		return received, lastRTT, nil
	}
	if pingReceivedPattern.Match(out) {
		// ping exits non-zero for ordinary packet loss. The packet summary makes
		// that a valid probe result; reserve Error for invocation/setup faults.
		return 0, 0, nil
	}
	if err != nil {
		return 0, 0, pingExecError(err, out)
	}
	return 0, 0, fmt.Errorf("ping returned no replies")
}

func parsePingBurstOutput(out []byte) (int, time.Duration) {
	text := string(out)
	var lastRTT time.Duration
	replies := pingReplyTimePattern.FindAllStringSubmatch(text, -1)
	for _, match := range replies {
		milliseconds, err := strconv.ParseFloat(match[1], 64)
		if err != nil || milliseconds < 0 {
			continue
		}
		lastRTT = time.Duration(milliseconds * float64(time.Millisecond))
	}
	if matches := pingReceivedPattern.FindStringSubmatch(text); len(matches) == 2 {
		if received, err := strconv.Atoi(matches[1]); err == nil && received >= 0 {
			return received, lastRTT
		}
	}
	return len(replies), lastRTT
}

func pingArgsForCount(target ProbeTarget, includeSource bool, count int, replyWait time.Duration) []string {
	if count <= 0 {
		count = 1
	}
	args := []string{}
	if target.NetNS != "" {
		args = append(args, "netns", "exec", target.NetNS)
	}
	args = append(args, "ping")
	if target.PeerTunnelAddr.Is6() {
		args = append(args, "-6")
	}
	args = append(args, "-n", "-c", strconv.Itoa(count))
	if count > 1 {
		args = append(args, "-i", formatPingBurstInterval(pingBurstInterval))
	}
	// Bound the per-reply wait so ping exits on its own before the surrounding
	// context deadline kills it. Without this an unanswered burst lingers in
	// iputils' default wait and the process is SIGKILLed, surfacing the
	// misleading "signal: killed" instead of the packet-loss summary.
	if replyWait > 0 {
		args = append(args, "-W", formatPingBurstInterval(replyWait))
	}
	if source := pingSourceAddress(target); includeSource && source != "" {
		args = append(args, "-I", source)
	}
	args = append(args, pingTargetAddress(target))
	return args
}

func formatPingBurstInterval(interval time.Duration) string {
	return strconv.FormatFloat(interval.Seconds(), 'f', -1, 64)
}

func pingExecError(err error, out []byte) error {
	if msg := strings.TrimSpace(string(out)); msg != "" {
		return fmt.Errorf("%w: %s", err, msg)
	}
	return err
}

func shouldRetryWithoutPingSource(target ProbeTarget, out []byte) bool {
	return target.PeerTunnelAddr.Is6() &&
		target.PeerTunnelAddr.IsLinkLocalUnicast() &&
		target.InterfaceName != "" &&
		strings.Contains(string(out), "bind icmp socket: Invalid argument")
}

func pingTargetAddress(target ProbeTarget) string {
	addr := target.PeerTunnelAddr.String()
	if target.PeerTunnelAddr.Is6() && target.PeerTunnelAddr.IsLinkLocalUnicast() && target.InterfaceName != "" && !strings.Contains(addr, "%") {
		addr += "%" + target.InterfaceName
	}
	return addr
}

func pingSourceAddress(target ProbeTarget) string {
	if target.LocalTunnelAddr.IsValid() {
		addr := target.LocalTunnelAddr.String()
		if target.LocalTunnelAddr.Is6() && target.LocalTunnelAddr.IsLinkLocalUnicast() && target.InterfaceName != "" && !strings.Contains(addr, "%") {
			addr += "%" + target.InterfaceName
		}
		return addr
	}
	return target.InterfaceName
}
