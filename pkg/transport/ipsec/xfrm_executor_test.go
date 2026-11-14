package ipsec

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestXFRMHungDeleteRetainsSlotAcrossCopiesAndOperations(t *testing.T) {
	driver := NewSystemXFRMDriver(NetNSSpec{Kind: NetNSHost})
	release := make(chan struct{})
	defer close(release)
	var mutations atomic.Int32
	driver.inspectNetlink = func(context.Context, NetNSSpec) ([]observedInterface, error) {
		return []observedInterface{{state: XFRMLinkState{InterfaceName: "phx-test"}}}, nil
	}
	driver.mutateNetlink = func(context.Context, NetNSSpec, string, xfrmMutation) (bool, error) {
		mutations.Add(1)
		<-release // Models a syscall that ignores context cancellation.
		return true, nil
	}
	driverCopy := driver
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	err := driver.DeleteInterface(ctx, "phx-test")
	if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, ErrXFRMOperationPending) || !strings.Contains(err.Error(), "delete interface phx-test") {
		t.Fatalf("delete error = %v", err)
	}
	spec := TransportLinkSpec{InterfaceName: "replacement", XFRMIfID: 1}
	operations := []func() error{
		func() error { return driverCopy.DeleteInterface(t.Context(), "phx-test") },
		func() error { return driverCopy.EnsureNamespace(t.Context(), NetNSSpec{}) },
		func() error { return driverCopy.EnsureInterface(t.Context(), spec) },
		func() error { return driverCopy.AssignAddress(t.Context(), spec, "192.0.2.1/32") },
		func() error { return driverCopy.AssignExtraAddress(t.Context(), spec, "192.0.2.2/32") },
		func() error { _, err := driverCopy.InspectLink(t.Context(), spec); return err },
		func() error { _, _, err := driverCopy.InspectLinks(t.Context(), nil, nil); return err },
		func() error { return driverCopy.EnsureObservedInterfaces(t.Context(), nil) },
		func() error { _, _, err := driverCopy.FilterSAsWithMissingLinks(t.Context(), nil, nil); return err },
	}
	started := time.Now()
	for range 10 {
		for _, operation := range operations {
			if err := operation(); !errors.Is(err, ErrXFRMOperationPending) {
				t.Fatalf("retry error = %v", err)
			}
		}
	}
	if time.Since(started) > time.Second || mutations.Load() != 1 {
		t.Fatalf("retries waited or launched more mutations: %s, %d", time.Since(started), mutations.Load())
	}
	if err := driverCopy.Close(); !errors.Is(err, ErrXFRMOperationPending) {
		t.Fatalf("close error = %v", err)
	}
	if err := driver.CheckAvailable(); !errors.Is(err, errXFRMClosed) {
		t.Fatalf("closed copy available: %v", err)
	}
}

func TestXFRMOperationHasDefaultWaitLimitAndDiscardsLateResult(t *testing.T) {
	driver := NewSystemXFRMDriver(NetNSSpec{})
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	start := time.Now()
	value, err := executeXFRM(t.Context(), driver, "blocked query", func(context.Context, SystemXFRMDriver) (int, error) {
		<-release
		return 42, nil
	})
	if value != 0 || !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, ErrXFRMOperationPending) {
		t.Fatalf("query = %d, %v", value, err)
	}
	if elapsed := time.Since(start); elapsed < xfrmOperationTimeout || elapsed > xfrmOperationTimeout+time.Second {
		t.Fatalf("wait limit = %s", elapsed)
	}
	release <- struct{}{}
	waitXFRMIdle(t, driver)
	value, err = executeXFRM(t.Context(), driver, "fresh query", func(context.Context, SystemXFRMDriver) (int, error) {
		return 7, nil
	})
	if value != 7 || err != nil {
		t.Fatalf("fresh query consumed stale result: %d, %v", value, err)
	}
}

func TestXFRMQueryOwnsInputAfterCancellation(t *testing.T) {
	driver := NewSystemXFRMDriver(NetNSSpec{Kind: NetNSHost})
	release := make(chan struct{})
	defer close(release)
	entered := make(chan struct{})
	driver.inspectNetlink = func(context.Context, NetNSSpec) ([]observedInterface, error) {
		close(entered)
		<-release
		return nil, nil
	}
	desired := []TransportLinkSpec{{InterfaceName: "old", ContactPoints: []ContactPoint{{Address: "192.0.2.1"}}}}
	sas := []SAState{{Name: "old"}}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		_, _, err := driver.FilterSAsWithMissingLinks(ctx, desired, sas)
		done <- err
	}()
	<-entered
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("query cancellation = %v", err)
	}
	// The blocked worker will inspect/compact its copies after release. Race
	// detection catches aliases to any of these owner-held slices.
	desired[0].InterfaceName = "new"
	desired[0].ContactPoints[0].Address = "192.0.2.2"
	sas[0].Name = "new"
	release <- struct{}{}
	waitXFRMIdle(t, driver)
	if sas[0].Name != "new" || desired[0].InterfaceName != "new" {
		t.Fatal("late worker changed caller input")
	}
}

func TestXFRMCompletedResultAfterCancellationIsDiscarded(t *testing.T) {
	for range 50 {
		driver := NewSystemXFRMDriver(NetNSSpec{})
		ctx, cancel := context.WithCancel(t.Context())
		value, err := executeXFRM(ctx, driver, "cancelled query", func(context.Context, SystemXFRMDriver) (int, error) {
			cancel()
			return 42, nil
		})
		cancel()
		if value != 0 || !errors.Is(err, context.Canceled) {
			t.Fatalf("accepted expired result: %d, %v", value, err)
		}
	}
}

func TestXFRMObservedMaintenanceDoesNotReenterExecutor(t *testing.T) {
	driver := NewSystemXFRMDriver(NetNSSpec{})
	var mutations atomic.Int32
	driver.inspectNetlink = func(context.Context, NetNSSpec) ([]observedInterface, error) { return nil, nil }
	driver.inNetNS = func(_ NetNSSpec, operation func() error) error { return errors.New("use fake command") }
	driver.Command = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "-n" {
			return []byte(strings.Repeat("1\n", len(args)-1)), nil
		}
		return nil, nil
	}
	driver.mutateNetlink = func(context.Context, NetNSSpec, string, xfrmMutation) (bool, error) {
		mutations.Add(1)
		return true, nil
	}
	err := driver.EnsureObservedInterfaces(t.Context(), []XFRMObservedInterface{{
		Spec: TransportLinkSpec{InterfaceName: "phx-new", XFRMIfID: 1, LocalTunnelAddr: netip.MustParseAddr("192.0.2.1")},
	}})
	if err != nil || mutations.Load() == 0 {
		t.Fatalf("nested ensure = %v, mutations = %d", err, mutations.Load())
	}
}

func waitXFRMIdle(t *testing.T, driver SystemXFRMDriver) {
	t.Helper()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for driver.CheckAvailable() != nil {
		select {
		case <-deadline.C:
			t.Fatal("worker did not release execution slot")
		case <-time.After(time.Millisecond):
		}
	}
}
