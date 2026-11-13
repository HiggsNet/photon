package photonlinux

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"testing"
)

type fakeUpstreamIO struct {
	state upstreamSnapshot
	fail  int
	calls []upstreamOperation
}

func (f *fakeUpstreamIO) Read(context.Context) (upstreamSnapshot, error) { return f.state, nil }

func (f *fakeUpstreamIO) Apply(_ context.Context, op upstreamOperation) error {
	f.calls = append(f.calls, op)
	if f.fail > 0 && len(f.calls) == f.fail {
		return errors.New("injected upstream failure")
	}
	if op.Address != nil {
		if op.Delete {
			f.state.Addresses = slices.DeleteFunc(f.state.Addresses, func(a upstreamAddress) bool { return a == *op.Address })
		} else {
			f.state.Addresses = append(f.state.Addresses, *op.Address)
		}
	} else if op.Delete {
		f.state.Routes = slices.DeleteFunc(f.state.Routes, func(r upstreamRoute) bool { return r == *op.Route })
	} else {
		f.state.Routes = append(f.state.Routes, *op.Route)
	}
	return nil
}

func TestUpstreamWithdrawsOnlyOwnedObjectsAndSettlesAfterPartialFailure(t *testing.T) {
	old, err := desiredUpstreamState(UpstreamRouteSpec{SourcePrefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")}, Prefixes: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}})
	if err != nil {
		t.Fatal(err)
	}
	desired, err := desiredUpstreamState(UpstreamRouteSpec{SourcePrefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.2/32")}, Prefixes: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}})
	if err != nil {
		t.Fatal(err)
	}
	for fail := 0; fail <= 4; fail++ {
		t.Run(strconv.Itoa(fail), func(t *testing.T) {
			manualRoute := upstreamRoute{Prefix: netip.MustParsePrefix("10.0.0.0/8"), Protocol: 4}
			manualAddress := upstreamAddress{Prefix: netip.MustParsePrefix("10.0.0.1/24")}
			io := &fakeUpstreamIO{state: upstreamSnapshot{Routes: append(slices.Clone(old.Routes), manualRoute), Addresses: append(slices.Clone(old.Addresses), manualAddress)}, fail: fail}
			err := reconcileUpstreamRoutes(t.Context(), io, desired)
			if (err != nil) != (fail > 0) {
				t.Fatalf("failure %d: %v", fail, err)
			}
			if fail > 0 && len(io.calls) != fail {
				t.Fatal("continued after a failed operation")
			}
			// A new controller uses the partial kernel state, with no journal.
			io.fail, io.calls = 0, nil
			if err := reconcileUpstreamRoutes(t.Context(), io, desired); err != nil {
				t.Fatal(err)
			}
			if !slices.Contains(io.state.Routes, manualRoute) || !slices.Contains(io.state.Addresses, manualAddress) || len(io.state.Routes) != 2 || len(io.state.Addresses) != 2 {
				t.Fatalf("wrong final ownership: %+v", io.state)
			}
			io.calls = nil
			if err := reconcileUpstreamRoutes(t.Context(), io, desired); err != nil || len(io.calls) != 0 {
				t.Fatalf("steady state repeated operations: %v, %v", io.calls, err)
			}
			if err := reconcileUpstreamRoutes(t.Context(), io, upstreamSnapshot{}); err != nil || !reflect.DeepEqual(io.state, upstreamSnapshot{Routes: []upstreamRoute{manualRoute}, Addresses: []upstreamAddress{manualAddress}}) {
				t.Fatalf("withdraw changed unmanaged objects: %+v, %v", io.state, err)
			}
		})
	}
}

func TestUpstreamDoesNotClaimLegacyOrConflictingObjects(t *testing.T) {
	desired, err := desiredUpstreamState(UpstreamRouteSpec{SourcePrefixes: []netip.Prefix{netip.MustParsePrefix("2001:db8::1/128")}, Prefixes: []netip.Prefix{netip.MustParsePrefix("2001:db8:1::/64")}})
	if err != nil {
		t.Fatal(err)
	}
	legacy := upstreamSnapshot{Routes: slices.Clone(desired.Routes), Addresses: slices.Clone(desired.Addresses)}
	legacy.Routes[0].Protocol, legacy.Addresses[0].Protocol = 4, 0
	io := &fakeUpstreamIO{state: legacy}
	if err := reconcileUpstreamRoutes(t.Context(), io, desired); err != nil || len(io.calls) != 0 {
		t.Fatalf("claimed existing unmanaged objects: %v, %v", io.calls, err)
	}
	if err := reconcileUpstreamRoutes(t.Context(), io, upstreamSnapshot{}); err != nil || len(io.calls) != 0 {
		t.Fatalf("deleted existing unmanaged objects: %v, %v", io.calls, err)
	}
	io.state.Routes[0].Gateway = netip.MustParseAddr("fe80::1234")
	if err := reconcileUpstreamRoutes(t.Context(), io, desired); err == nil || len(io.calls) != 0 {
		t.Fatal("conflicting unmanaged route was overwritten")
	}
}

func TestUpstreamValidatesEntireDesiredStateBeforeChanges(t *testing.T) {
	for _, spec := range []UpstreamRouteSpec{
		{Interface: "lo", Prefixes: []netip.Prefix{netip.MustParsePrefix("203.0.112.0/24"), netip.MustParsePrefix("203.0.112.1/24")}},
		{Interface: "lo", SourcePrefixes: []netip.Prefix{{}}},
		{Interface: "lo", MeshIPv4LL: "bad"},
		{Interface: "lo", MeshIPv4LL: "fe80::1/64"},
		{Interface: "lo", MeshIPv6LL: "192.0.2.1/24"},
	} {
		if err := newUpstreamRouteManager().EnsureRoutes(t.Context(), spec); err == nil {
			t.Fatalf("accepted invalid upstream input: %+v", spec)
		}
	}
}
