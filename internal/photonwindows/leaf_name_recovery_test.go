package photonwindows

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"
)

func nameRecoveryRuntime(t *testing.T, factory packetDeviceFactory) (*pipelineFixture, *leafRuntime) {
	t.Helper()
	f := runtimeFixture(t)
	r := newLeafRuntime(factory)
	t.Cleanup(func() {
		if err := r.close(); err != nil {
			t.Error(err)
		}
	})
	return f, r
}
func reconcileNameRecovery(t *testing.T, f *pipelineFixture, r *leafRuntime, now time.Time) error {
	t.Helper()
	// Model the daemon's periodic planner refresh with the fixture's stable
	// resolved address; the separate 10-second DNS hint lease must stay current.
	f.plan = revalidateResolvedGateway(f.config, f.view, f.plan, now)
	return r.reconcile(t.Context(), f.config, f.view, f.plan, f.p.tunnel, f.p.routerID, now)
}
func completeNameRecovery(t *testing.T, f *pipelineFixture, r *leafRuntime, now time.Time, result leafOpenResult) error {
	t.Helper()
	f.plan = revalidateResolvedGateway(f.config, f.view, f.plan, now)
	return r.complete(t.Context(), f.config, f.view, f.plan, f.p.tunnel, f.p.routerID, now, result)
}
func pendingNameFactory(context.Context, string, []netip.Prefix, []netip.Prefix, uint32, uint32) (ownedPacketDevice, error) {
	return newRuntimeDevice(), errPacketDeviceNamePending
}

func TestLeafNameRecoveryDeadlineSurvivesRetriesAndRevision(t *testing.T) {
	f, r := nameRecoveryRuntime(t, pendingNameFactory)
	for seconds := 0; seconds < 30; seconds += 5 {
		now := f.now.Add(time.Duration(seconds) * time.Second)
		f.view.Revision++ // An unrelated, accepted Gossip revision cannot renew the budget.
		if err := reconcileNameRecovery(t, f, r, now); err != nil {
			t.Fatal(err)
		}
		result := runtimeOpenResult(t, r)
		if err := completeNameRecovery(t, f, r, now, result); !errors.Is(err, errPacketDeviceNamePending) {
			t.Fatalf("retry: %v", err)
		}
		if r.nameRecoveryDeadline != f.now.Add(30*time.Second) {
			t.Fatalf("deadline extended at %ds", seconds)
		}
		select {
		case <-result.device.(*runtimePacketDevice).closed:
		default:
			t.Fatal("failed attempt leaked device")
		}
		if r.retryAt != now.Add(5*time.Second) {
			t.Fatal("retry interval changed")
		}
	}
	if err := reconcileNameRecovery(t, f, r, f.now.Add(30*time.Second-time.Nanosecond)); err != nil {
		t.Fatalf("expired early: %v", err)
	}
	if r.pending {
		t.Fatal("ignored retry backoff before deadline")
	}
	if err := reconcileNameRecovery(t, f, r, f.now.Add(30*time.Second)); !errors.Is(err, errPacketDeviceRecoveryExpired) {
		t.Fatalf("deadline not fatal: %v", err)
	}
	if r.pending || r.device != nil || r.pipeline != nil {
		t.Fatal("expiry retained active resources")
	}
}

func TestLeafNameRecoverySuccessBoundary(t *testing.T) {
	for _, elapsed := range []time.Duration{5 * time.Second, 30*time.Second - time.Nanosecond, 30 * time.Second, 31 * time.Second} {
		t.Run(elapsed.String(), func(t *testing.T) {
			next := newRuntimeDevice()
			calls := 0
			f, r := nameRecoveryRuntime(t, func(context.Context, string, []netip.Prefix, []netip.Prefix, uint32, uint32) (ownedPacketDevice, error) {
				calls++
				if calls == 1 {
					return nil, errPacketDeviceNamePending
				}
				return next, nil
			})
			if err := reconcileNameRecovery(t, f, r, f.now); err != nil {
				t.Fatal(err)
			}
			if err := completeNameRecovery(t, f, r, f.now, runtimeOpenResult(t, r)); !errors.Is(err, errPacketDeviceNamePending) {
				t.Fatal(err)
			}
			if err := reconcileNameRecovery(t, f, r, f.now.Add(5*time.Second)); err != nil {
				t.Fatal(err)
			}
			result := runtimeOpenResult(t, r)
			err := completeNameRecovery(t, f, r, f.now.Add(elapsed), result)
			if elapsed < 30*time.Second {
				if err != nil || r.pipeline == nil || !r.nameRecoveryDeadline.IsZero() {
					t.Fatalf("timely success rejected: %v", err)
				}
			} else {
				if !errors.Is(err, errPacketDeviceRecoveryExpired) || r.pipeline != nil {
					t.Fatalf("late success attached: %v", err)
				}
				select {
				case <-next.closed:
				default:
					t.Fatal("late successful device leaked")
				}
			}
		})
	}
}

func TestLeafNameRecoveryStaleCannotStartClearOrExtendBudget(t *testing.T) {
	for _, withBudget := range []bool{false, true} {
		for _, stale := range []string{"request", "revision", "attachment"} {
			for _, success := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/budget=%t/success=%t", stale, withBudget, success), func(t *testing.T) {
					f, r := nameRecoveryRuntime(t, pendingNameFactory)
					if err := reconcileNameRecovery(t, f, r, f.now); err != nil {
						t.Fatal(err)
					}
					result := runtimeOpenResult(t, r)
					if withBudget {
						if err := completeNameRecovery(t, f, r, f.now, result); !errors.Is(err, errPacketDeviceNamePending) {
							t.Fatal(err)
						}
						if err := reconcileNameRecovery(t, f, r, f.now.Add(5*time.Second)); err != nil {
							t.Fatal(err)
						}
						result = runtimeOpenResult(t, r)
					}
					before := r.nameRecoveryDeadline
					if success {
						result.err = nil
					}
					switch stale {
					case "request":
						result.request--
					case "revision":
						result.revision--
					case "attachment":
						result.want.local = netip.MustParseAddr("fe80::dead")
					}
					err := completeNameRecovery(t, f, r, f.now.Add(40*time.Second), result)
					if errors.Is(err, errPacketDeviceRecoveryExpired) || errors.Is(err, errPacketDeviceNamePending) {
						t.Fatalf("stale error escaped: %v", err)
					}
					if r.nameRecoveryDeadline != before {
						t.Fatal("stale completion changed naming budget")
					}
					select {
					case <-result.device.(*runtimePacketDevice).closed:
					default:
						t.Fatal("stale device leaked")
					}
				})
			}
		}
	}
}
func TestLeafNameRecoveryExpiryCancelsPendingOpen(t *testing.T) {
	started, joined := make(chan struct{}), make(chan struct{})
	calls := 0
	f, r := nameRecoveryRuntime(t, func(ctx context.Context, _ string, _ []netip.Prefix, _ []netip.Prefix, _ uint32, _ uint32) (ownedPacketDevice, error) {
		calls++
		if calls == 1 {
			return nil, errPacketDeviceNamePending
		}
		close(started)
		<-ctx.Done()
		close(joined)
		return nil, ctx.Err()
	})
	if err := reconcileNameRecovery(t, f, r, f.now); err != nil {
		t.Fatal(err)
	}
	if err := completeNameRecovery(t, f, r, f.now, runtimeOpenResult(t, r)); !errors.Is(err, errPacketDeviceNamePending) {
		t.Fatal(err)
	}
	if err := reconcileNameRecovery(t, f, r, f.now.Add(5*time.Second)); err != nil {
		t.Fatal(err)
	}
	<-started
	if err := reconcileNameRecovery(t, f, r, f.now.Add(30*time.Second)); !errors.Is(err, errPacketDeviceRecoveryExpired) {
		t.Fatalf("pending open bypassed deadline: %v", err)
	}
	if err := r.close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-joined:
	default:
		t.Fatal("pending open not canceled and joined")
	}
}

func TestLeafNameRecoveryCancellationClearsBudget(t *testing.T) {
	for _, cancel := range []string{"stop", "authorization"} {
		t.Run(cancel, func(t *testing.T) {
			f, r := nameRecoveryRuntime(t, pendingNameFactory)
			if err := reconcileNameRecovery(t, f, r, f.now); err != nil {
				t.Fatal(err)
			}
			if err := completeNameRecovery(t, f, r, f.now, runtimeOpenResult(t, r)); !errors.Is(err, errPacketDeviceNamePending) {
				t.Fatal(err)
			}
			if cancel == "stop" {
				if err := r.stop(); err != nil {
					t.Fatal(err)
				}
			} else {
				f.p.tunnel.phase = 0
				err := reconcileNameRecovery(t, f, r, f.now.Add(30*time.Second))
				if err == nil || errors.Is(err, errPacketDeviceRecoveryExpired) {
					t.Fatalf("revoked authorization retained fatal budget: %v", err)
				}
				f.p.tunnel.phase = 3
			}
			if !r.nameRecoveryDeadline.IsZero() {
				t.Fatal("cancellation retained budget")
			}
			now := f.now.Add(31 * time.Second)
			if err := reconcileNameRecovery(t, f, r, now); err != nil {
				t.Fatal(err)
			}
			if err := completeNameRecovery(t, f, r, now, runtimeOpenResult(t, r)); !errors.Is(err, errPacketDeviceNamePending) {
				t.Fatal(err)
			}
			if r.nameRecoveryDeadline != now.Add(30*time.Second) {
				t.Fatal("new intent inherited old budget")
			}
		})
	}
}

func TestLeafNameRecoveryOrdinaryFailureHasNoBudget(t *testing.T) {
	temporary := errors.New("temporary system error")
	f, r := nameRecoveryRuntime(t, func(context.Context, string, []netip.Prefix, []netip.Prefix, uint32, uint32) (ownedPacketDevice, error) {
		return nil, temporary
	})
	for _, seconds := range []int{0, 20, 40} {
		now := f.now.Add(time.Duration(seconds) * time.Second)
		if err := reconcileNameRecovery(t, f, r, now); err != nil {
			t.Fatal(err)
		}
		if err := completeNameRecovery(t, f, r, now, runtimeOpenResult(t, r)); !errors.Is(err, temporary) {
			t.Fatalf("ordinary error reclassified: %v", err)
		}
		if !r.nameRecoveryDeadline.IsZero() {
			t.Fatal("ordinary failure started naming budget")
		}
	}
}
