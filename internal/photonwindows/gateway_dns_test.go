package photonwindows

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestGatewayDNSQueuesRetriesBehindWaitingHosts(t *testing.T) {
	dns := newGatewayDNS()
	dns.reset(t.Context())
	now := time.Now()
	plan := func(at time.Time) {
		dns.beginPlan(at)
		for _, host := range []string{"first.example", "FIRST.example", "second.example"} {
			_, _ = dns.LookupIPAddr(t.Context(), host)
		}
		dns.endPlan()
	}
	plan(now)
	_, first := dns.next()
	dns.dispatched()
	if len(dns.queue) != 1 || first.name != "first.example" {
		t.Fatalf("deduplication/order failed: first=%s, queue=%v", first.name, dns.queue)
	}
	dns.complete(gatewayDNSResult{job: first, err: context.DeadlineExceeded}, now)
	plan(now.Add(gatewayDNSRetry))
	if len(dns.queue) != 2 || dns.queue[0].name != "second.example" || dns.queue[1].name != "first.example" {
		t.Fatalf("retry displaced a waiting hostname: %v", dns.queue)
	}
}

func TestGatewayDNSExpiresResultsAndIgnoresOldNetwork(t *testing.T) {
	dns := newGatewayDNS()
	dns.reset(t.Context())
	now := time.Now()
	name := "gateway.example"
	plan := func(at time.Time) ([]net.IPAddr, error) {
		dns.beginPlan(at)
		addresses, err := dns.LookupIPAddr(t.Context(), name)
		dns.endPlan()
		return addresses, err
	}
	addresses, err := plan(now)
	if len(addresses) != 0 || !errors.Is(err, errGatewayDNSPending) {
		t.Fatalf("initial lookup = %v, %v", addresses, err)
	}
	_, old := dns.next()
	dns.dispatched()
	dns.reset(t.Context())
	plan(now)
	_, current := dns.next()
	dns.dispatched()
	success := []net.IPAddr{{IP: net.IPv4(192, 0, 2, 44)}}
	if dns.complete(gatewayDNSResult{job: old, addresses: success}, now) || old.ctx.Err() == nil {
		t.Fatal("accepted DNS result from previous network")
	}
	if !dns.complete(gatewayDNSResult{job: current, addresses: success}, now) {
		t.Fatal("first current result did not request a plan")
	}
	addresses, err = plan(now.Add(gatewayDNSRefresh))
	if len(addresses) != 1 || err != nil {
		t.Fatalf("refresh discarded usable answer: %v, %v", addresses, err)
	}
	_, refresh := dns.next()
	dns.dispatched()
	dns.complete(gatewayDNSResult{job: refresh, err: context.DeadlineExceeded}, now.Add(gatewayDNSRefresh))
	addresses, err = plan(now.Add(gatewayDNSMaxAge))
	if len(addresses) != 0 || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired address masked original error: %v, %v", addresses, err)
	}
	_, retry := dns.next()
	dns.dispatched()
	if !dns.complete(gatewayDNSResult{job: retry, addresses: success}, now.Add(gatewayDNSMaxAge)) {
		t.Fatal("renewing expired answer with the same address did not request a plan")
	}
}
