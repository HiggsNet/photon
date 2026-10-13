// udp-perf is a bounded fixture tool, not a Photon product command.
package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type options struct {
	mode, local, remote, output, ready                                 string
	port, flows, window, payload, seconds, deadlineMS, pid, maxPackets int
	threadCPU                                                          bool
}

// Thread counters are cumulative for (process creation, TID, thread creation).
// Missing/exited threads prevent reconstructing complete process CPU from them.
type threadSample struct {
	TID                                    uint32
	StartToken                             string
	UserSeconds, KernelSeconds, CPUSeconds float64
	ObservedSeconds                        float64
	FirstSeen                              bool
	Exited                                 bool
	Error                                  string `json:",omitempty"`
	ErrorCode                              uint32 `json:",omitempty"`
}

type affinitySample struct {
	ProcessMask, SystemMask             string   `json:",omitempty"`
	CPUs                                []int    `json:",omitempty"`
	ProcessGroupIDs                     []uint16 `json:",omitempty"`
	ProcessGroupCount, SystemGroupCount int
	CPUCountLowerBound                  int
	CPUCountUpperBound                  int
	Complete                            bool
	Error                               string `json:",omitempty"`
}

type threadObservation struct {
	Enumerated, Limit   int
	EnumerationComplete bool
	Errors              []string `json:",omitempty"`
	Threads             []threadSample
	Missing             []threadIdentity `json:",omitempty"`
}

type threadIdentity struct {
	TID        uint32
	StartToken string
}

type threadHistory struct {
	seen     map[threadIdentity]bool
	previous map[threadIdentity]bool
}

func (h *threadHistory) observe(sample *processSample) {
	if sample.Threads == nil {
		return
	}
	if h.seen == nil {
		h.seen = make(map[threadIdentity]bool)
	}
	current := make(map[threadIdentity]bool)
	for i := range sample.Threads.Threads {
		t := &sample.Threads.Threads[i]
		if t.Error != "" || t.StartToken == "" {
			continue
		}
		identity := threadIdentity{t.TID, t.StartToken}
		t.FirstSeen = !h.seen[identity]
		h.seen[identity], current[identity] = true, true
	}
	for identity := range h.previous {
		if !current[identity] {
			sample.Threads.Missing = append(sample.Threads.Missing, identity)
		}
	}
	// Missing means not observed with valid counters; it is not proof of exit.
	h.previous = current
}

type processSample struct {
	Seconds, CPUSeconds           float64
	PrivateBytes, WorkingSetBytes uint64
	StartToken                    uint64
	Affinity                      *affinitySample    `json:",omitempty"`
	Threads                       *threadObservation `json:",omitempty"`
}

type flowResult struct {
	Flow                                                                                        int
	Sent, Echoed, OnTime, Expired, LateEchoed, Duplicates, Corrupt, Foreign, Unsent, SendErrors uint64
	RTTCount, RTTNanoseconds                                                                    uint64
	RTTBuckets                                                                                  [12]uint64
	PacketLimitReached                                                                          bool
}

type result struct {
	SchemaVersion                                                                                            int
	Mode, Local, Remote, OS, Architecture, GoVersion, StartedUTC, Unit, WindowSemantics                      string
	Port, Flows, WindowPerFlow, PayloadBytes, SendSeconds, DeadlineMS                                        int
	MaxPackets, LogicalCPUs                                                                                  int
	GeneratorGOMAXPROCS, SampleIntervalMS                                                                    int
	GeneratorAffinity                                                                                        affinitySample
	ThreadCPUSampling                                                                                        bool
	Seconds, GoodputMbps, DeadlineGoodputMbps, EchoLossPercent, DeadlineMissPercent, GeneratorCPUCorePercent float64
	Totals                                                                                                   flowResult
	FlowResults                                                                                              []flowResult
	Samples                                                                                                  []processSample
	ServiceCPUCorePercent                                                                                    float64
	Error                                                                                                    string `json:",omitempty"`
	Completed                                                                                                bool
}

func (o options) validate() error {
	if o.mode != "client" && o.mode != "echo" {
		return errors.New("mode must be client or echo")
	}
	if net.ParseIP(o.local) == nil || o.port < 1024 || o.flows < 1 || o.flows > 16 || o.port+o.flows > 65536 {
		return errors.New("explicit local IP, port >=1024 and 1..16 flows required")
	}
	if o.seconds < 1 || o.seconds > 900 {
		return errors.New("seconds must be 1..900")
	}
	if o.threadCPU && (o.mode != "client" || o.pid <= 0) {
		return errors.New("thread CPU sampling requires client mode and a service PID")
	}
	if o.mode == "client" && (net.ParseIP(o.remote) == nil || o.seconds > 30 || o.window < 1 || o.window > 16384 || o.payload < 40 || o.payload > 1400 || o.deadlineMS < 10 || o.deadlineMS > 3000 || o.maxPackets < o.flows || o.maxPackets > 16000000) {
		return errors.New("client requires explicit remote IP, <=30 seconds, window 1..16384, payload 40..1400, deadline 10..3000 ms, bounded packet budget")
	}
	return nil
}

func main() {
	o := options{}
	flag.StringVar(&o.mode, "mode", "client", "client or echo")
	flag.StringVar(&o.local, "local", "", "explicit local IP")
	flag.StringVar(&o.remote, "remote", "", "explicit remote IP")
	flag.StringVar(&o.output, "output", "", "JSON output file (exclusive create)")
	flag.StringVar(&o.ready, "ready", "", "echo ready marker (exclusive create)")
	flag.IntVar(&o.port, "port", 19100, "first UDP port; each flow uses the next port")
	flag.IntVar(&o.flows, "flows", 1, "parallel independent UDP sockets, 1..16")
	flag.IntVar(&o.window, "window", 64, "maximum pending requests per flow")
	flag.IntVar(&o.payload, "payload", 1200, "application payload bytes, 40..1400")
	flag.IntVar(&o.seconds, "seconds", 15, "client sending seconds <=30, echo lifetime <=900")
	flag.IntVar(&o.deadlineMS, "deadline-ms", 1000, "per-packet echo deadline")
	flag.IntVar(&o.pid, "service-pid", 0, "Windows service PID to sample; 0 disables")
	flag.IntVar(&o.maxPackets, "max-packets", 8000000, "bounded total sequence tracking budget")
	flag.BoolVar(&o.threadCPU, "thread-cpu", false, "opt-in Windows service thread CPU/identity/affinity samples at 250 ms")
	flag.Parse()
	if err := o.validate(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	var r result
	var err error
	if o.mode == "echo" {
		r, err = runEcho(o)
	} else {
		r, err = runClient(o)
	}
	if err != nil {
		r.Error = err.Error()
	}
	data, marshalErr := json.MarshalIndent(r, "", "  ")
	if marshalErr != nil {
		panic(marshalErr)
	}
	if o.output != "" {
		err = errors.Join(err, writeExclusive(o.output, append(data, '\n')))
	}
	fmt.Println(string(data))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func writeExclusive(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	return errors.Join(err, f.Close())
}

func metadata(o options) result {
	r := result{SchemaVersion: 1, Mode: o.mode, Local: o.local, Remote: o.remote, OS: runtime.GOOS, Architecture: runtime.GOARCH, GoVersion: runtime.Version(), StartedUTC: time.Now().UTC().Format(time.RFC3339Nano), Unit: "unique fully validated UDP echo application payload Mbps per direction; two traversals per echo", WindowSemantics: "pending request credits; completed requests immediately release one credit independently of sequence positions", Port: o.port, Flows: o.flows, WindowPerFlow: o.window, PayloadBytes: o.payload, SendSeconds: o.seconds, DeadlineMS: o.deadlineMS, MaxPackets: o.maxPackets, LogicalCPUs: runtime.NumCPU(), GeneratorGOMAXPROCS: runtime.GOMAXPROCS(0), GeneratorAffinity: currentAffinity(), ThreadCPUSampling: o.threadCPU}
	if o.pid != 0 {
		r.SampleIntervalMS = 250
	}
	return r
}

type reply struct {
	seq  uint64
	at   time.Duration
	kind int
}
type tracker struct {
	window   int
	seen     []uint64
	sentAt   []time.Duration
	oldest   uint64
	pending  int
	deadline time.Duration
	r        flowResult
}

func newTracker(window, max int, deadline time.Duration) *tracker {
	return &tracker{window: window, seen: make([]uint64, (max+64)/64), sentAt: make([]time.Duration, max+1), oldest: 1, deadline: deadline}
}

func (t *tracker) canSend() bool {
	return t.pending < t.window
}
func (t *tracker) sent(at time.Duration) uint64 {
	t.r.Sent++
	id := t.r.Sent
	t.sentAt[id] = at
	t.pending++
	return id
}
func (t *tracker) expire(now time.Duration) {
	for t.oldest <= t.r.Sent {
		if t.seen[t.oldest/64]&(uint64(1)<<(t.oldest%64)) != 0 {
			t.oldest++
			continue
		}
		if now-t.sentAt[t.oldest] < t.deadline {
			break
		}
		t.pending--
		t.r.Expired++
		t.oldest++
	}
}

var rttBounds = [...]time.Duration{10 * time.Microsecond, 50 * time.Microsecond, 100 * time.Microsecond, 250 * time.Microsecond, 500 * time.Microsecond, time.Millisecond, 2 * time.Millisecond, 5 * time.Millisecond, 10 * time.Millisecond, 100 * time.Millisecond, time.Second}

func (t *tracker) receive(a reply) {
	if a.kind == 1 {
		t.r.Corrupt++
		return
	}
	if a.kind == 2 {
		t.r.Foreign++
		return
	}
	if a.seq == 0 || a.seq > t.r.Sent {
		t.r.Unsent++
		return
	}
	word, bit := a.seq/64, uint64(1)<<(a.seq%64)
	if t.seen[word]&bit != 0 {
		t.r.Duplicates++
		return
	}
	t.seen[word] |= bit
	t.r.Echoed++
	wasPending := a.seq >= t.oldest
	if wasPending {
		t.pending--
	}
	// The receive goroutine timestamps the read. Sender scheduling or a reused
	// expiry cursor must not turn an already timely reply into a miss.
	rtt := a.at - t.sentAt[a.seq]
	if rtt >= t.deadline {
		if wasPending {
			t.r.Expired++
		}
		t.r.LateEchoed++
	} else {
		if !wasPending {
			t.r.Expired--
		}
		t.r.OnTime++
	}
	if rtt >= 0 {
		t.r.RTTCount++
		t.r.RTTNanoseconds += uint64(rtt)
		bucket := len(rttBounds)
		for i, bound := range rttBounds {
			if rtt <= bound {
				bucket = i
				break
			}
		}
		t.r.RTTBuckets[bucket]++
	}
}

func makePayload(size, flow int) []byte {
	b := make([]byte, size)
	if _, err := rand.Read(b[:16]); err != nil {
		panic(err)
	}
	binary.LittleEndian.PutUint32(b[24:28], uint32(flow))
	for i := 28; i < size; i++ {
		b[i] = byte(i*31 + flow*17)
	}
	return b
}
func validatePayload(receive, template []byte) (uint64, int) {
	if len(receive) != len(template) {
		return 0, 1
	}
	for i := 0; i < 16; i++ {
		if receive[i] != template[i] {
			return 0, 2
		}
	}
	for i := 24; i < len(receive); i++ {
		if receive[i] != template[i] {
			return 0, 1
		}
	}
	return binary.LittleEndian.Uint64(receive[16:24]), 0
}

func runFlow(o options, flow int, start time.Time) (flowResult, error) {
	addr := &net.UDPAddr{IP: net.ParseIP(o.local)}
	peer := &net.UDPAddr{IP: net.ParseIP(o.remote), Port: o.port + flow}
	conn, err := net.DialUDP("udp", addr, peer)
	if err != nil {
		return flowResult{Flow: flow}, err
	}
	defer conn.Close()
	if err = conn.SetReadBuffer(4 << 20); err != nil {
		return flowResult{Flow: flow}, err
	}
	if err = conn.SetWriteBuffer(4 << 20); err != nil {
		return flowResult{Flow: flow}, err
	}
	deadline := time.Duration(o.deadlineMS) * time.Millisecond
	end := time.Duration(o.seconds) * time.Second
	stopAt := end + deadline + 100*time.Millisecond
	if err = conn.SetDeadline(start.Add(stopAt)); err != nil {
		return flowResult{Flow: flow}, err
	}
	payload := makePayload(o.payload, flow)
	acks := make(chan reply, o.window+64)
	recvDone := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 65536)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				recvDone <- err
				return
			}
			at := time.Since(start)
			seq, kind := validatePayload(buf[:n], payload)
			select {
			case acks <- reply{seq, at, kind}:
			case <-done:
				recvDone <- nil
				return
			}
		}
	}()
	t := newTracker(o.window, o.maxPackets/o.flows, deadline)
	t.r.Flow = flow
	max := uint64(o.maxPackets / o.flows)
	var recvErr error
	var loopErr error
	timer := time.NewTimer(time.Millisecond)
	defer timer.Stop()
loop:
	for {
		for i := 0; i < 64; i++ {
			select {
			case a := <-acks:
				t.receive(a)
			case recvErr = <-recvDone:
				break loop
			default:
				i = 64
			}
		}
		now := time.Since(start)
		t.expire(now)
		if now >= stopAt {
			break
		}
		if now >= end && t.pending == 0 {
			break
		}
		if now < end && t.r.Sent < max && t.canSend() {
			seq := t.r.Sent + 1
			binary.LittleEndian.PutUint64(payload[16:24], seq)
			n, err := conn.Write(payload)
			if err != nil {
				t.r.SendErrors++
				loopErr = err
				break
			}
			if n != len(payload) {
				loopErr = errors.New("partial UDP send")
				break
			}
			t.sent(now)
			continue
		}
		if t.r.Sent >= max {
			t.r.PacketLimitReached = true
		}
		wait := time.Millisecond
		if now >= end {
			wait = 100 * time.Microsecond
		}
		timer.Reset(wait)
		select {
		case a := <-acks:
			t.receive(a)
		case recvErr = <-recvDone:
			break loop
		case <-timer.C:
		}
	}
	close(done)
	conn.Close()
	if recvErr == nil {
		recvErr = <-recvDone
	}
drain:
	for {
		select {
		case a := <-acks:
			t.receive(a)
		default:
			t.r.Expired += uint64(t.pending)
			t.pending = 0
			break drain
		}
	}
	if recvErr != nil {
		var ne net.Error
		if !errors.Is(recvErr, net.ErrClosed) && (!errors.As(recvErr, &ne) || !ne.Timeout()) {
			loopErr = errors.Join(loopErr, recvErr)
		}
	}
	if t.r.Sent != t.r.OnTime+t.r.Expired || t.r.Echoed != t.r.OnTime+t.r.LateEchoed {
		loopErr = errors.Join(loopErr, errors.New("inconsistent sequence accounting"))
	}
	return t.r, loopErr
}

func addFlow(total *flowResult, r flowResult) {
	total.Sent += r.Sent
	total.Echoed += r.Echoed
	total.OnTime += r.OnTime
	total.Expired += r.Expired
	total.LateEchoed += r.LateEchoed
	total.Duplicates += r.Duplicates
	total.Corrupt += r.Corrupt
	total.Foreign += r.Foreign
	total.Unsent += r.Unsent
	total.SendErrors += r.SendErrors
	total.RTTCount += r.RTTCount
	total.RTTNanoseconds += r.RTTNanoseconds
	total.PacketLimitReached = total.PacketLimitReached || r.PacketLimitReached
	for i := range r.RTTBuckets {
		total.RTTBuckets[i] += r.RTTBuckets[i]
	}
}

func runClient(o options) (result, error) {
	r := metadata(o)
	start := time.Now()
	cpuBefore, err := currentCPUSeconds()
	if err != nil {
		return r, err
	}
	var sampleErr error
	var sampleDone chan struct{}
	var sampleStop chan struct{}
	var history threadHistory
	if o.pid != 0 {
		first, err := sampleProcessMode(o.pid, start, o.threadCPU)
		if err != nil {
			return r, err
		}
		history.observe(&first)
		r.Samples = append(r.Samples, first)
		sampleStop = make(chan struct{})
		sampleDone = make(chan struct{})
		go func() {
			defer close(sampleDone)
			ticker := time.NewTicker(250 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-sampleStop:
					return
				case <-ticker.C:
					sample, err := sampleProcessMode(o.pid, start, o.threadCPU)
					if err != nil {
						sampleErr = err
						return
					}
					if sample.StartToken != first.StartToken {
						sampleErr = errors.New("service process identity changed")
						return
					}
					history.observe(&sample)
					r.Samples = append(r.Samples, sample)
				}
			}
		}()
	}
	r.FlowResults = make([]flowResult, o.flows)
	errs := make([]error, o.flows)
	var wg sync.WaitGroup
	for flow := 0; flow < o.flows; flow++ {
		wg.Add(1)
		go func(flow int) { defer wg.Done(); r.FlowResults[flow], errs[flow] = runFlow(o, flow, start) }(flow)
	}
	wg.Wait()
	if sampleStop != nil {
		close(sampleStop)
		<-sampleDone
		sample, err := sampleProcessMode(o.pid, start, o.threadCPU)
		sampleErr = errors.Join(sampleErr, err)
		if err == nil {
			if sample.StartToken != r.Samples[0].StartToken {
				sampleErr = errors.Join(sampleErr, errors.New("service process identity changed"))
			} else {
				history.observe(&sample)
				r.Samples = append(r.Samples, sample)
			}
		}
	}
	r.Seconds = time.Since(start).Seconds()
	cpuAfter, cpuErr := currentCPUSeconds()
	r.GeneratorCPUCorePercent = 100 * (cpuAfter - cpuBefore) / r.Seconds
	for _, f := range r.FlowResults {
		addFlow(&r.Totals, f)
	}
	r.GoodputMbps = float64(r.Totals.Echoed) * float64(o.payload) * 8 / r.Seconds / 1e6
	r.DeadlineGoodputMbps = float64(r.Totals.OnTime) * float64(o.payload) * 8 / r.Seconds / 1e6
	if r.Totals.Sent != 0 {
		r.EchoLossPercent = 100 * float64(r.Totals.Sent-r.Totals.Echoed) / float64(r.Totals.Sent)
		r.DeadlineMissPercent = 100 * float64(r.Totals.Expired) / float64(r.Totals.Sent)
	}
	if len(r.Samples) > 1 {
		r.ServiceCPUCorePercent = 100 * (r.Samples[len(r.Samples)-1].CPUSeconds - r.Samples[0].CPUSeconds) / r.Seconds
	}
	err = errors.Join(append(errs, sampleErr, cpuErr)...)
	if r.Totals.Corrupt != 0 || r.Totals.Unsent != 0 {
		err = errors.Join(err, errors.New("invalid echo payload or unsent sequence"))
	}
	r.Completed = err == nil && !r.Totals.PacketLimitReached
	return r, err
}

func runEcho(o options) (result, error) {
	r := metadata(o)
	start := time.Now()
	cpuBefore, err := currentCPUSeconds()
	if err != nil {
		return r, err
	}
	var sockets []*net.UDPConn
	defer func() {
		for _, c := range sockets {
			c.Close()
		}
	}()
	for flow := 0; flow < o.flows; flow++ {
		c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(o.local), Port: o.port + flow})
		if err != nil {
			return r, err
		}
		sockets = append(sockets, c)
		if err = c.SetReadBuffer(4 << 20); err != nil {
			return r, err
		}
		if err = c.SetWriteBuffer(4 << 20); err != nil {
			return r, err
		}
		if err = c.SetDeadline(start.Add(time.Duration(o.seconds) * time.Second)); err != nil {
			return r, err
		}
	}
	if o.ready != "" {
		if err = writeExclusive(o.ready, []byte("ready\n")); err != nil {
			return r, err
		}
	}
	var received, echoed, invalid, sendErrors atomic.Uint64
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(stop)
	finished := make(chan struct{})
	defer close(finished)
	go func() {
		select {
		case <-stop:
			for _, c := range sockets {
				c.Close()
			}
		case <-finished:
		}
	}()
	var wg sync.WaitGroup
	for _, c := range sockets {
		wg.Add(1)
		go func(c *net.UDPConn) {
			defer wg.Done()
			buf := make([]byte, 65536)
			for {
				n, peer, err := c.ReadFromUDPAddrPort(buf)
				if err != nil {
					return
				}
				received.Add(1)
				if n < 40 || n > 1400 {
					invalid.Add(1)
					continue
				}
				written, err := c.WriteToUDPAddrPort(buf[:n], peer)
				if err != nil || written != n {
					sendErrors.Add(1)
					continue
				}
				echoed.Add(1)
			}
		}(c)
	}
	wg.Wait()
	r.Seconds = time.Since(start).Seconds()
	cpuAfter, cpuErr := currentCPUSeconds()
	r.GeneratorCPUCorePercent = 100 * (cpuAfter - cpuBefore) / r.Seconds
	r.Totals.Sent = received.Load()
	r.Totals.Echoed = echoed.Load()
	r.Totals.Corrupt = invalid.Load()
	r.Totals.SendErrors = sendErrors.Load()
	r.Completed = cpuErr == nil
	return r, cpuErr
}
