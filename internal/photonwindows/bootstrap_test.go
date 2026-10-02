package photonwindows

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"
)

type changingBootstrapResolver struct {
	address netip.Addr
	blocked bool
}

func (r *changingBootstrapResolver) LookupNetIP(ctx context.Context, _, _ string) ([]netip.Addr, error) {
	if r.blocked {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return []netip.Addr{r.address}, nil
}
func TestBootstrapDNSRefreshAndCancellation(t *testing.T) {
	config := &Config{Gateway: GatewayConfig{BootstrapHints: []BootstrapHint{{Peer: "node-a.catofes.", Address: "gateway.example:33434"}}}}
	resolver := &changingBootstrapResolver{address: netip.MustParseAddr("192.0.2.1")}
	first, err := resolveGossipBootstrapWith(t.Context(), config, netip.MustParseAddrPort("0.0.0.0:33434"), resolver)
	if err != nil {
		t.Fatal(err)
	}
	resolver.address = netip.MustParseAddr("192.0.2.2")
	second, err := resolveGossipBootstrapWith(t.Context(), config, netip.MustParseAddrPort("0.0.0.0:33434"), resolver)
	if err != nil {
		t.Fatal(err)
	}
	if first["node-a.catofes."].String() != "192.0.2.1:33434" || second["node-a.catofes."].String() != "192.0.2.2:33434" {
		t.Fatal("bootstrap DNS was not refreshed")
	}
	resolver.blocked = true
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	_, err = resolveGossipBootstrapWith(ctx, config, netip.MustParseAddrPort("0.0.0.0:33434"), resolver)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("DNS cancellation: %v", err)
	}
}
