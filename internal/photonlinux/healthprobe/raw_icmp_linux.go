//go:build linux

package healthprobe

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// RawICMProber sends echo requests through raw sockets. A worker is pinned to
// one OS thread for every target network namespace: switching a Go thread with
// setns is thread-local, so it must never be returned to the runtime pool.
// The worker creates and caches namespace-bound sockets by source/interface;
// probes on distinct sockets then run concurrently without another setns.
//
// If raw sockets or setns are unavailable, Probe delegates to fallback. This
// makes CAP_NET_RAW/CAP_SYS_ADMIN deployment mistakes non-disruptive while
// still making the efficient path the normal case.
type RawICMProber struct {
	fallback       Prober
	reportFallback RawICMPFallbackReporter

	mu      sync.Mutex
	workers map[string]rawICMPWorker
	new     func(string) (rawICMPWorker, error)
	nextSeq atomic.Uint32
	id      uint16
}

// RawICMPFallbackReporter observes local raw-ICMP setup failures before the
// portable fallback prober is used. Callers should rate-limit any logging.
type RawICMPFallbackReporter func(ProbeTarget, error)

type rawICMPWorker interface {
	probe(context.Context, ProbeTarget, ProbeConfig, uint16, *atomic.Uint32) rawProbeResult
	close()
}

type rawProbeResult struct {
	sent     int
	received int
	lastRTT  time.Duration
	err      error
	// unavailable is reserved for local setup failures. Packet send failures
	// normally do not cause a second exec-based probe, except for local route
	// errors that indicate a cached interface-bound socket has gone stale.
	unavailable bool
	// reopen asks the namespace worker to retire this socket and retry opening
	// it after a bounded backoff. It is only set for errors that can be caused
	// by deleting and recreating an interface behind SO_BINDTODEVICE.
	reopen bool
}

// NewRawICMProber creates the preferred in-process ICMP prober. fallback is
// normally NewICMProber; nil means setup errors are returned to the caller.
// The optional reporter observes fallback reasons for low-volume diagnostics.
func NewRawICMProber(fallback Prober, reporters ...RawICMPFallbackReporter) *RawICMProber {
	p := &RawICMProber{
		fallback: fallback,
		workers:  make(map[string]rawICMPWorker),
		new:      newRawICMPWorker,
		id:       uint16(time.Now().UnixNano()),
	}
	if len(reporters) > 0 {
		p.reportFallback = reporters[0]
	}
	return p
}

func (p *RawICMProber) Type() string { return ProbeTypeICMP }

func (p *RawICMProber) Probe(ctx context.Context, target ProbeTarget, cfg ProbeConfig) ProbeResult {
	if !target.PeerTunnelAddr.IsValid() {
		return ProbeResult{InstanceID: target.InstanceID, Err: errors.New("peer address missing")}
	}
	worker, err := p.worker(target.NetNS)
	if err != nil {
		return p.fallbackOrError(ctx, target, cfg, err)
	}
	result := worker.probe(ctx, target, cfg, p.id, &p.nextSeq)
	if result.unavailable {
		return p.fallbackOrError(ctx, target, cfg, result.err)
	}
	burst := cfg.Burst
	if burst <= 0 {
		burst = 3
	}
	sent := result.sent
	if sent == 0 && result.err == nil {
		// A completed raw worker result represents the configured burst. This
		// also preserves compatibility with worker implementations predating
		// explicit sent accounting.
		sent = burst
	}
	received := min(max(result.received, 0), sent)
	rtt := result.lastRTT
	if received == 0 {
		rtt = 0
	}
	probeResult := ProbeResult{
		InstanceID: target.InstanceID,
		Sent:       sent,
		Received:   received,
		Lost:       sent - received,
		RTT:        rtt,
		Success:    result.err == nil && received > sent-received,
	}
	if result.err != nil {
		probeResult.Err = result.err
	}
	return probeResult
}

func (p *RawICMProber) fallbackOrError(ctx context.Context, target ProbeTarget, cfg ProbeConfig, rawErr error) ProbeResult {
	if p.fallback != nil {
		if p.reportFallback != nil {
			p.reportFallback(target, rawErr)
		}
		return p.fallback.Probe(ctx, target, cfg)
	}
	return ProbeResult{InstanceID: target.InstanceID, Err: rawErr}
}

func (p *RawICMProber) worker(netns string) (rawICMPWorker, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if worker := p.workers[netns]; worker != nil {
		return worker, nil
	}
	worker, err := p.new(netns)
	if err != nil {
		return nil, err
	}
	p.workers[netns] = worker
	return worker, nil
}

// Close releases the cached raw sockets. It is mainly useful for tests and
// short-lived callers; the daemon process also releases them on exit.
func (p *RawICMProber) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, worker := range p.workers {
		worker.close()
	}
	p.workers = make(map[string]rawICMPWorker)
}

type rawICMPJob struct {
	ctx    context.Context
	target ProbeTarget
	cfg    ProbeConfig
	id     uint16
	seq    *atomic.Uint32
	result chan rawProbeResult
}

type rawICMPNamespaceWorker struct {
	netns       string
	jobs        chan rawICMPJob
	done        chan struct{}
	openSocket  func(rawSocketKey) (int, uint32, error)
	closeSocket func(int) error
	probeSocket func(rawICMPJob, rawSocketKey, int, uint32) rawProbeResult
	now         func() time.Time
	mu          sync.RWMutex
	once        sync.Once
}

func newRawICMPWorker(netns string) (rawICMPWorker, error) {
	w := &rawICMPNamespaceWorker{
		netns:       netns,
		jobs:        make(chan rawICMPJob),
		done:        make(chan struct{}),
		openSocket:  openRawICMPSocket,
		closeSocket: unix.Close,
		probeSocket: probeRawICMP,
		now:         time.Now,
	}
	ready := make(chan error, 1)
	go w.run(ready)
	if err := <-ready; err != nil {
		return nil, err
	}
	return w, nil
}

func (w *rawICMPNamespaceWorker) run(ready chan<- error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if w.now == nil {
		w.now = time.Now
	}

	var restoreFD, targetFD int = -1, -1
	var err error
	if w.netns != "" {
		restoreFD, err = unix.Open("/proc/self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err == nil {
			targetFD, err = unix.Open(netNSPath(w.netns), unix.O_RDONLY|unix.O_CLOEXEC, 0)
		}
		if err == nil {
			err = unix.Setns(targetFD, unix.CLONE_NEWNET)
		}
	}
	if err != nil {
		if targetFD >= 0 {
			_ = unix.Close(targetFD)
		}
		if restoreFD >= 0 {
			_ = unix.Close(restoreFD)
		}
		ready <- fmt.Errorf("enter network namespace %q for raw ICMP: %w", w.netns, err)
		close(w.done)
		return
	}
	ready <- nil

	sockets := make(map[rawSocketKey]*rawICMPSocketSlot)
	var probes sync.WaitGroup
	defer func() {
		probes.Wait()
		for _, slot := range sockets {
			slot.close()
		}
		if restoreFD >= 0 {
			_ = unix.Setns(restoreFD, unix.CLONE_NEWNET)
			_ = unix.Close(restoreFD)
		}
		if targetFD >= 0 {
			_ = unix.Close(targetFD)
		}
		close(w.done)
	}()

	for job := range w.jobs {
		key := rawSocketKeyForTarget(job.target)
		slot := sockets[key]
		if slot == nil {
			slot = &rawICMPSocketSlot{}
			sockets[key] = slot
		}
		socket, err := slot.acquire(w.now(), job.cfg.Interval, func() (*rawICMPSocket, error) {
			fd, zoneID, err := w.openSocket(key)
			if err != nil {
				return nil, err
			}
			return newRawICMPSocket(fd, zoneID, w.closeSocket), nil
		})
		if err != nil {
			job.result <- rawProbeResult{err: err, unavailable: true}
			continue
		}
		probes.Add(1)
		go func(job rawICMPJob, key rawSocketKey, slot *rawICMPSocketSlot, socket *rawICMPSocket) {
			defer probes.Done()
			result := socket.probe(job, key, w.probeSocket)
			if result.reopen {
				slot.invalidate(socket, w.now(), job.cfg.Interval, result.err)
			} else if result.err == nil {
				slot.markSuccess(socket)
			}
			job.result <- result
		}(job, key, slot, socket)
	}
}

func (w *rawICMPNamespaceWorker) probe(ctx context.Context, target ProbeTarget, cfg ProbeConfig, id uint16, seq *atomic.Uint32) rawProbeResult {
	// Do not let Close race a channel send. Holding the read lock through the
	// result also makes Close wait for the in-flight probe before closing its
	// cached raw socket.
	w.mu.RLock()
	defer w.mu.RUnlock()
	job := rawICMPJob{ctx: ctx, target: target, cfg: cfg, id: id, seq: seq, result: make(chan rawProbeResult, 1)}
	select {
	case w.jobs <- job:
	case <-ctx.Done():
		return rawProbeResult{err: ctx.Err()}
	case <-w.done:
		return rawProbeResult{err: fmt.Errorf("raw ICMP worker for network namespace %q stopped", w.netns), unavailable: true}
	}
	select {
	case result := <-job.result:
		return result
	case <-ctx.Done():
		return rawProbeResult{err: ctx.Err()}
	case <-w.done:
		return rawProbeResult{err: fmt.Errorf("raw ICMP worker for network namespace %q stopped", w.netns), unavailable: true}
	}
}

func (w *rawICMPNamespaceWorker) close() {
	w.once.Do(func() {
		w.mu.Lock()
		close(w.jobs)
		w.mu.Unlock()
		<-w.done
	})
}

type rawSocketKey struct {
	family int
	source netip.Addr
	iface  string
}

const (
	rawICMPReopenMinDelay = 15 * time.Second
	rawICMPReopenMaxDelay = 2 * time.Minute
)

// rawICMPSocketSlot retains retry state after its socket is retired. This
// prevents a persistent local routing fault from opening a new raw socket on
// every health interval while allowing exec-ping fallback during the backoff.
type rawICMPSocketSlot struct {
	mu                  sync.Mutex
	socket              *rawICMPSocket
	consecutiveFailures int
	retryAfter          time.Time
	lastErr             error
}

func (s *rawICMPSocketSlot) acquire(
	now time.Time,
	interval time.Duration,
	open func() (*rawICMPSocket, error),
) (*rawICMPSocket, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.socket != nil {
		return s.socket, nil
	}
	if now.Before(s.retryAfter) {
		return nil, fmt.Errorf("raw ICMP socket reopen backoff after: %w", s.lastErr)
	}
	socket, err := open()
	if err != nil {
		wrapped := fmt.Errorf("open raw ICMP socket: %w", err)
		s.recordFailure(now, interval, wrapped)
		return nil, wrapped
	}
	s.socket = socket
	return socket, nil
}

func (s *rawICMPSocketSlot) invalidate(socket *rawICMPSocket, now time.Time, interval time.Duration, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.socket != socket {
		return
	}
	s.socket = nil
	s.recordFailure(now, interval, err)
}

func (s *rawICMPSocketSlot) markSuccess(socket *rawICMPSocket) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.socket != socket {
		return
	}
	s.consecutiveFailures = 0
	s.retryAfter = time.Time{}
	s.lastErr = nil
}

func (s *rawICMPSocketSlot) recordFailure(now time.Time, interval time.Duration, err error) {
	s.consecutiveFailures++
	s.retryAfter = now.Add(rawICMPSocketReopenDelay(interval, s.consecutiveFailures))
	s.lastErr = err
}

func (s *rawICMPSocketSlot) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.socket != nil {
		s.socket.close()
		s.socket = nil
	}
}

func rawICMPSocketReopenDelay(interval time.Duration, failures int) time.Duration {
	base := min(max(3*interval, rawICMPReopenMinDelay), rawICMPReopenMaxDelay)
	delay := base
	for i := 1; i < failures && delay < rawICMPReopenMaxDelay; i++ {
		if delay > rawICMPReopenMaxDelay/2 {
			return rawICMPReopenMaxDelay
		}
		delay *= 2
	}
	if delay > rawICMPReopenMaxDelay {
		return rawICMPReopenMaxDelay
	}
	return delay
}

// rawICMPSocket serializes probes sharing one bound socket. Different
// source/interface keys have independent sockets and can be probed
// concurrently after the namespace worker creates them.
type rawICMPSocket struct {
	fd          int
	zoneID      uint32
	ready       chan struct{}
	closeSocket func(int) error
	closeOnce   sync.Once
	staleErr    error
}

func newRawICMPSocket(fd int, zoneID uint32, closers ...func(int) error) *rawICMPSocket {
	closeSocket := unix.Close
	if len(closers) > 0 && closers[0] != nil {
		closeSocket = closers[0]
	}
	socket := &rawICMPSocket{
		fd:          fd,
		zoneID:      zoneID,
		ready:       make(chan struct{}, 1),
		closeSocket: closeSocket,
	}
	socket.ready <- struct{}{}
	return socket
}

func (s *rawICMPSocket) probe(
	job rawICMPJob,
	key rawSocketKey,
	run func(rawICMPJob, rawSocketKey, int, uint32) rawProbeResult,
) rawProbeResult {
	select {
	case <-s.ready:
		defer func() { s.ready <- struct{}{} }()
	case <-job.ctx.Done():
		return rawProbeResult{err: job.ctx.Err()}
	}
	if s.staleErr != nil {
		return rawProbeResult{
			err:         fmt.Errorf("raw ICMP socket retired after: %w", s.staleErr),
			unavailable: true,
		}
	}
	result := run(job, key, s.fd, s.zoneID)
	if result.reopen {
		s.staleErr = result.err
		s.close()
	}
	return result
}

func (s *rawICMPSocket) close() {
	s.closeOnce.Do(func() {
		_ = s.closeSocket(s.fd)
	})
}

func rawSocketKeyForTarget(target ProbeTarget) rawSocketKey {
	key := rawSocketKey{source: target.LocalTunnelAddr, iface: target.InterfaceName}
	if target.PeerTunnelAddr.Is6() {
		key.family = unix.AF_INET6
	} else {
		key.family = unix.AF_INET
	}
	return key
}

func probeRawICMP(job rawICMPJob, key rawSocketKey, fd int, zoneID uint32) rawProbeResult {
	burst := job.cfg.Burst
	if burst <= 0 {
		burst = 3
	}
	timeout := job.cfg.Timeout
	if timeout <= 0 {
		timeout = time.Second
	}

	deadline := time.Now().Add(timeout * time.Duration(burst))
	if d, ok := job.ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	pending := make(map[uint16]time.Time, burst)
	var sent int
	var received int
	var lastRTT time.Duration
	drain := func() (bool, error) {
		for {
			seq, ok := readRawICMPReply(fd, key.family, job.id)
			if !ok {
				return sent == burst && len(pending) == 0, nil
			}
			if sent, known := pending[seq]; known {
				delete(pending, seq)
				received++
				lastRTT = time.Since(sent)
			}
		}
	}
	start := time.Now()
	for i := 0; i < burst; i++ {
		nextSend := start.Add(time.Duration(i) * pingBurstInterval)
		if err := waitRawICMP(job.ctx, fd, nextSend, drain); err != nil {
			return rawProbeResult{sent: sent, received: received, lastRTT: lastRTT, err: err}
		}
		sequence := uint16(job.seq.Add(1))
		packet := makeICMPEchoPacket(key.family, job.id, sequence)
		if err := unix.Sendto(fd, packet, 0, rawDestination(job.target, key.family, zoneID)); err != nil {
			reopen := shouldReopenRawICMPSocket(err)
			return rawProbeResult{
				sent:        sent,
				received:    received,
				lastRTT:     lastRTT,
				err:         fmt.Errorf("send raw ICMP echo: %w", err),
				unavailable: reopen,
				reopen:      reopen,
			}
		}
		sent++
		pending[sequence] = time.Now()
	}
	if err := waitRawICMP(job.ctx, fd, deadline, drain); err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return rawProbeResult{sent: sent, received: received, lastRTT: lastRTT}
		}
		return rawProbeResult{sent: sent, received: received, lastRTT: lastRTT, err: err}
	}
	return rawProbeResult{sent: sent, received: received, lastRTT: lastRTT}
}

func shouldReopenRawICMPSocket(err error) bool {
	return errors.Is(err, unix.ENETUNREACH) ||
		errors.Is(err, unix.ENODEV) ||
		errors.Is(err, unix.EADDRNOTAVAIL)
}

func openRawICMPSocket(key rawSocketKey) (int, uint32, error) {
	protocol := unix.IPPROTO_ICMP
	if key.family == unix.AF_INET6 {
		protocol = unix.IPPROTO_ICMPV6
	}
	fd, err := unix.Socket(key.family, unix.SOCK_RAW|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, protocol)
	if err != nil {
		return -1, 0, err
	}
	closeOnError := func(err error) (int, uint32, error) {
		_ = unix.Close(fd)
		return -1, 0, err
	}
	if key.iface != "" {
		if err := unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, key.iface); err != nil {
			return closeOnError(err)
		}
	}
	if key.family == unix.AF_INET6 {
		// Linux calculates the ICMPv6 pseudo-header checksum at byte offset 2.
		// ICMPv6 raw sockets reject IPV6_CHECKSUM at the IPPROTO_IPV6 level;
		// Linux requires the SOL_RAW/IPPROTO_RAW level for this socket type.
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_RAW, unix.IPV6_CHECKSUM, 2); err != nil {
			return closeOnError(err)
		}
		addr := unix.SockaddrInet6{}
		if key.source.IsValid() {
			addr.Addr = key.source.As16()
		}
		var zoneID uint32
		if key.iface != "" {
			iface, err := interfaceIndex(key.iface)
			if err != nil {
				return closeOnError(err)
			}
			zoneID = uint32(iface)
			addr.ZoneId = zoneID
		}
		if err := unix.Bind(fd, &addr); err != nil {
			return closeOnError(err)
		}
		return fd, zoneID, nil
	}
	addr := unix.SockaddrInet4{}
	if key.source.IsValid() {
		addr.Addr = key.source.As4()
	}
	if err := unix.Bind(fd, &addr); err != nil {
		return closeOnError(err)
	}
	return fd, 0, nil
}

func rawDestination(target ProbeTarget, family int, zoneID uint32) unix.Sockaddr {
	if family == unix.AF_INET6 {
		addr := unix.SockaddrInet6{Addr: target.PeerTunnelAddr.As16()}
		if target.PeerTunnelAddr.IsLinkLocalUnicast() {
			addr.ZoneId = zoneID
		}
		return &addr
	}
	return &unix.SockaddrInet4{Addr: target.PeerTunnelAddr.As4()}
}

func interfaceIndex(name string) (int, error) {
	iface, err := netInterfaceByName(name)
	if err != nil {
		return 0, err
	}
	return iface, nil
}

// netInterfaceByName is isolated to keep the raw socket code testable without
// a real namespace or privileged interface setup. net.InterfaceByName uses a
// netlink query, so after setns it resolves the interface in the worker's
// target network namespace (unlike relying on how /sys happens to be mounted).
var netInterfaceByName = func(name string) (int, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return 0, err
	}
	if iface.Index <= 0 {
		return 0, fmt.Errorf("invalid ifindex for %q", name)
	}
	return iface.Index, nil
}

func makeICMPEchoPacket(family int, id, seq uint16) []byte {
	packet := make([]byte, 8)
	if family == unix.AF_INET6 {
		packet[0] = 128 // ICMPv6 Echo Request
	} else {
		packet[0] = 8 // ICMP Echo Request
	}
	binary.BigEndian.PutUint16(packet[4:6], id)
	binary.BigEndian.PutUint16(packet[6:8], seq)
	if family == unix.AF_INET {
		binary.BigEndian.PutUint16(packet[2:4], internetChecksum(packet))
	}
	return packet
}

func internetChecksum(packet []byte) uint16 {
	var sum uint32
	for len(packet) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(packet[:2]))
		packet = packet[2:]
	}
	if len(packet) == 1 {
		sum += uint32(packet[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// readRawICMPReply returns one matching echo sequence. The socket is
// non-blocking; false means no more packets are currently available.
func readRawICMPReply(fd, family int, id uint16) (uint16, bool) {
	buf := make([]byte, 1500)
	for {
		n, _, err := unix.Recvfrom(fd, buf, unix.MSG_DONTWAIT)
		if err != nil || n == 0 {
			return 0, false
		}
		if seq, ok := parseRawICMPReply(buf[:n], family, id); ok {
			return seq, true
		}
	}
}

func parseRawICMPReply(packet []byte, family int, id uint16) (uint16, bool) {
	if family == unix.AF_INET && len(packet) >= 20 && packet[0]>>4 == 4 {
		headerLen := int(packet[0]&0x0f) * 4
		if headerLen > len(packet) {
			return 0, false
		}
		packet = packet[headerLen:]
	}
	if len(packet) < 8 {
		return 0, false
	}
	wantType := byte(0)
	if family == unix.AF_INET6 {
		wantType = 129
	}
	if packet[0] != wantType || packet[1] != 0 || binary.BigEndian.Uint16(packet[4:6]) != id {
		return 0, false
	}
	return binary.BigEndian.Uint16(packet[6:8]), true
}

func waitRawICMP(ctx context.Context, fd int, until time.Time, drain func() (bool, error)) error {
	for {
		done, err := drain()
		if err != nil {
			return err
		}
		if done {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		remaining := time.Until(until)
		if remaining <= 0 {
			return nil
		}
		milliseconds := max(int((remaining+time.Millisecond-1)/time.Millisecond), 1)
		_, err = unix.Poll([]unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}, milliseconds)
		if err != nil && !errors.Is(err, syscall.EINTR) {
			return err
		}
	}
}

func netNSPath(netns string) string {
	if strings.ContainsRune(netns, '/') {
		return filepath.Clean(netns)
	}
	return filepath.Join("/var/run/netns", netns)
}
