package photonwindows

import (
	"context"
	"errors"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

const (
	gatewayDNSWorkers   = 8
	gatewayDNSTimeout   = 3 * time.Second
	gatewayDNSRefresh   = 2 * time.Second
	gatewayDNSRetry     = 5 * time.Second
	gatewayDNSMaxAge    = 10 * time.Second
	gatewayDNSPlanDelay = 100 * time.Millisecond
)

var errGatewayDNSPending = errors.New("background DNS lookup pending")

type gatewayDNSHost struct {
	addresses []net.IPAddr
	err       error
	expires   time.Time
	retryAt   time.Time
	seen      bool
	pending   bool
}

type gatewayDNSJob struct {
	ctx   context.Context
	name  string
	entry *gatewayDNSHost
}

type gatewayDNSResult struct {
	job       gatewayDNSJob
	addresses []net.IPAddr
	err       error
}

// The planner owns the queue and cache. Workers only receive immutable jobs.
// Lookups during planning read the cache and enqueue work without waiting.
type gatewayDNS struct {
	now     time.Time
	ctx     context.Context
	cancel  context.CancelFunc
	hosts   map[string]*gatewayDNSHost
	queue   []gatewayDNSJob
	jobs    chan gatewayDNSJob
	results chan gatewayDNSResult
}

func newGatewayDNS() *gatewayDNS {
	return &gatewayDNS{
		hosts:   make(map[string]*gatewayDNSHost),
		jobs:    make(chan gatewayDNSJob),
		results: make(chan gatewayDNSResult, gatewayDNSWorkers),
	}
}

func (d *gatewayDNS) reset(ctx context.Context) {
	if d.cancel != nil {
		d.cancel()
	}
	d.ctx, d.cancel = context.WithCancel(ctx)
	d.queue = nil
	for _, entry := range d.hosts {
		entry.pending = false
		entry.retryAt = time.Time{}
		entry.err = nil
	}
}

func (d *gatewayDNS) beginPlan(now time.Time) {
	d.now = now
	for _, entry := range d.hosts {
		entry.seen = false
	}
}

func (d *gatewayDNS) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	name := strings.ToLower(host)
	entry := d.hosts[name]
	if entry == nil {
		entry = &gatewayDNSHost{}
		d.hosts[name] = entry
	}
	entry.seen = true
	if !entry.pending && !d.now.Before(entry.retryAt) {
		d.queue = append(d.queue, gatewayDNSJob{ctx: d.ctx, name: name, entry: entry})
		entry.pending = true
	}
	if d.now.Before(entry.expires) {
		// Address candidate selection sorts the returned slice in place.
		return slices.Clone(entry.addresses), nil
	}
	if entry.err != nil {
		return nil, entry.err
	}
	return nil, errGatewayDNSPending
}

func (d *gatewayDNS) endPlan() {
	for name, entry := range d.hosts {
		if !entry.seen {
			delete(d.hosts, name)
		}
	}
	d.queue = slices.DeleteFunc(d.queue, func(job gatewayDNSJob) bool {
		return !job.entry.seen
	})
}

func (d *gatewayDNS) next() (chan<- gatewayDNSJob, gatewayDNSJob) {
	if len(d.queue) == 0 {
		return nil, gatewayDNSJob{}
	}
	return d.jobs, d.queue[0]
}

func (d *gatewayDNS) dispatched() {
	d.queue[0] = gatewayDNSJob{}
	d.queue = d.queue[1:]
}

func (d *gatewayDNS) resolve(ctx context.Context, resolver ipsec.DNSResolver) {
	for {
		select {
		case <-ctx.Done():
			return
		case job := <-d.jobs:
			lookupCtx, cancel := context.WithTimeout(job.ctx, gatewayDNSTimeout)
			addresses, err := resolver.LookupIPAddr(lookupCtx, job.name)
			cancel()
			select {
			case d.results <- gatewayDNSResult{job: job, addresses: addresses, err: err}:
			case <-ctx.Done():
				return
			}
		}
	}
}

func (d *gatewayDNS) complete(result gatewayDNSResult, now time.Time) bool {
	entry := d.hosts[result.job.name]
	if result.job.ctx != d.ctx || entry != result.job.entry {
		return false
	}
	entry.pending = false
	entry.retryAt = now.Add(gatewayDNSRetry)
	previous, previousErr := entry.addresses, entry.err
	wasUsable := now.Before(entry.expires)
	if result.err == nil && len(result.addresses) == 0 {
		result.err = errors.New("DNS returned no addresses")
	}
	entry.err = result.err
	if result.err == nil {
		entry.addresses = slices.Clone(result.addresses)
		slices.SortFunc(entry.addresses, func(a, b net.IPAddr) int { return strings.Compare(a.String(), b.String()) })
		entry.expires = now.Add(gatewayDNSMaxAge)
		entry.retryAt = now.Add(gatewayDNSRefresh)
	} else {
		var dnsErr *net.DNSError
		if !now.Before(entry.expires) || (errors.As(result.err, &dnsErr) && dnsErr.IsNotFound) {
			entry.addresses, entry.expires = nil, time.Time{}
		}
	}
	return wasUsable != now.Before(entry.expires) || !slices.EqualFunc(previous, entry.addresses, func(a, b net.IPAddr) bool {
		return a.IP.Equal(b.IP) && a.Zone == b.Zone
	}) || gatewayDNSErrorText(previousErr) != gatewayDNSErrorText(entry.err)
}

func gatewayDNSErrorText(err error) string {
	if err != nil {
		return err.Error()
	}
	return ""
}
