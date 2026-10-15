package gossip

import (
	"errors"
	"math"
	"testing"
	"time"
)

func TestPeerQuotaPreservesFractionAcrossChecks(t *testing.T) {
	for _, step := range []time.Duration{time.Millisecond, 5 * time.Millisecond, 10 * time.Millisecond} {
		t.Run(step.String(), func(t *testing.T) {
			now := time.Unix(100, 0)
			q := NewPeerQuotas(QuotaConfig{ByteRate: 1, ByteBurst: 1})
			if err := q.Allow("p", 1, 128, now); err != nil {
				t.Fatal(err)
			}
			for elapsed := step; elapsed <= time.Second; elapsed += step {
				if err := q.Allow("p", 0, 0, now.Add(elapsed)); err != nil {
					t.Fatal(err)
				}
			}
			if err := q.Allow("p", 1, 128, now.Add(time.Second)); err != nil {
				t.Fatalf("fractional credit was lost: %v", err)
			}
		})
	}
}

func TestPeerQuotaRejectedChecksPreserveCredit(t *testing.T) {
	now := time.Unix(100, 0)
	q := NewPeerQuotas(QuotaConfig{})
	_ = q.Allow("p", 0, 128, now)
	accepted := 0
	for i := 1; i <= 1000; i++ {
		err := q.Allow("p", 0, 1, now.Add(time.Duration(i)*time.Millisecond))
		if err == nil {
			accepted++
		} else if !errors.Is(err, ErrQuotaExceeded) {
			t.Fatal(err)
		}
	}
	if accepted != 128 {
		t.Fatalf("accepted=%d, want rate of 128 objects over 1s", accepted)
	}
}

func TestPeerQuotaRollbackDoesNotMintCredit(t *testing.T) {
	now := time.Unix(100, 0)
	q := NewPeerQuotas(QuotaConfig{ObjectRate: 1, ObjectBurst: 1})
	_ = q.Allow("p", 0, 1, now)
	_ = q.Allow("p", 0, 0, now.Add(500*time.Millisecond))
	_ = q.Allow("p", 0, 0, now.Add(100*time.Millisecond))
	if err := q.Allow("p", 0, 1, now.Add(600*time.Millisecond)); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("clock rollback minted quota: %v", err)
	}
	if err := q.Allow("p", 0, 1, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
}

func TestPeerQuotaFullBucketDiscardsExcessFraction(t *testing.T) {
	now := time.Unix(100, 0)
	q := NewPeerQuotas(QuotaConfig{ObjectRate: 1, ObjectBurst: 1})
	_ = q.Allow("p", 0, 0, now)
	_ = q.Allow("p", 0, 1, now.Add(500*time.Millisecond))
	if err := q.Allow("p", 0, 1, now.Add(time.Second)); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("full bucket banked excess fraction: %v", err)
	}
	if err := q.Allow("p", 0, 1, now.Add(1500*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
}

func TestPeerQuotaLargeIdleRefillDoesNotOverflow(t *testing.T) {
	now := time.Unix(100, 0)
	q := NewPeerQuotas(QuotaConfig{ByteRate: math.MaxInt64, ByteBurst: math.MaxInt64, ObjectRate: math.MaxInt64, ObjectBurst: math.MaxInt64, PeerTTL: 24 * time.Hour})
	if err := q.Allow("p", math.MaxInt64, math.MaxInt64, now); err != nil {
		t.Fatal(err)
	}
	if err := q.Allow("p", math.MaxInt64, math.MaxInt64, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
}

func TestTransportDisabledDiagnosticsFastPathDoesNotAllocate(t *testing.T) {
	transport := &Transport{}
	if allocs := testing.AllocsPerRun(1000, func() { transport.logEvent(Event{}, nil, time.Time{}) }); allocs != 0 {
		t.Fatalf("disabled successful-packet diagnostics allocate %v times", allocs)
	}
}
