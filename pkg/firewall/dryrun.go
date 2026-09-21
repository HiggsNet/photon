package firewall

import (
	"context"
	"fmt"
)

// DryRunDriver is a non-root, testable FirewallDriver that records apply
// decisions without touching the system. It is the default driver for dry-run
// mode, unit tests, and non-privileged environments.
type DryRunDriver struct {
	// Backend overrides the reported backend name; defaults to "dry-run".
	Backend string
	// Applied records the most recent apply plans for inspection in tests.
	Applied []FirewallPlan
	// OwnedObjects simulates system state for adopt/delete decisions.
	OwnedObjects []FirewallObjectRef
}

// NewDryRunDriver returns a DryRunDriver with the given simulated owned objects.
func NewDryRunDriver() *DryRunDriver {
	return &DryRunDriver{Backend: "dry-run"}
}

func (d *DryRunDriver) Preflight(ctx context.Context, spec FirewallInstanceSpec) (FirewallPreflight, error) {
	backend := d.Backend
	if backend == "" {
		backend = "dry-run"
	}
	return FirewallPreflight{
		Backend:     backend,
		NFTNetlink:  "dry-run",
		CAPNetAdmin: "dry-run",
		NetNSStatus: "dry-run",
	}, nil
}

func (d *DryRunDriver) Apply(ctx context.Context, desired *FirewallDesiredState) (FirewallApplyResult, error) {
	if desired == nil {
		return FirewallApplyResult{}, fmt.Errorf("desired state is nil")
	}
	if desired.Instance.Mode == ModeExternal || desired.Instance.Mode == ModeDisabled {
		return FirewallApplyResult{}, nil
	}
	plan := PlanDiff(desired.Instance.ID, desired, FirewallObservedState{Objects: d.OwnedObjects})
	d.Applied = append(d.Applied, plan)
	result := FirewallApplyResult{
		Generation: 1,
	}
	for _, action := range plan.Actions {
		switch action.Action {
		case "create", "update":
			result.Applied++
		case "delete":
			result.Applied++
		case "adopt":
			// adopt is a noop for apply
		}
	}
	return result, nil
}

// RecordedPlans returns the recorded apply plans for test assertions.
func (d *DryRunDriver) RecordedPlans() []FirewallPlan {
	return d.Applied
}
