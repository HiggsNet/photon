package ipsec

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"
)

const xfrmOperationTimeout = 2 * time.Second

// ErrXFRMOperationPending means a platform call has not returned. A timeout
// cannot cancel a kernel syscall or establish whether a mutation took effect.
var ErrXFRMOperationPending = errors.New("xfrm operation still running; result unknown")

var errXFRMClosed = errors.New("xfrm driver is closed")

type xfrmOperation struct {
	name    string
	started time.Time
	cancel  context.CancelFunc
}

type xfrmExecutor struct {
	mu     sync.Mutex
	active *xfrmOperation
	closed bool
}

func (op *xfrmOperation) err(cause error) error {
	return fmt.Errorf("%s (started %s): %w", op.name, op.started.UTC().Format(time.RFC3339Nano), errors.Join(ErrXFRMOperationPending, cause))
}

// CheckAvailable lets composite operations refuse work before terminating SAs
// or unloading keys while an earlier XFRM operation still owns the resources.
func (d SystemXFRMDriver) CheckAvailable() error {
	if d.executor == nil {
		return nil
	}
	d.executor.mu.Lock()
	defer d.executor.mu.Unlock()
	if d.executor.closed {
		return errXFRMClosed
	}
	if d.executor.active != nil {
		return d.executor.active.err(nil)
	}
	return nil
}

// Close cancels cooperative work but never joins a potentially uninterruptible
// kernel call. Its slot stays owned until the worker actually returns.
func (d SystemXFRMDriver) Close() error {
	if d.executor == nil {
		return nil
	}
	d.executor.mu.Lock()
	defer d.executor.mu.Unlock()
	d.executor.closed = true
	if op := d.executor.active; op != nil {
		op.cancel()
		return op.err(nil)
	}
	return nil
}

// executeXFRM bounds the caller's wait, not the lifetime of the syscall. There
// is one slot per constructed driver, shared by all its value copies. Timed-out
// workers keep that slot; retries never create more workers or reuse resources.
// Results are private to this invocation and are discarded after cancellation.
func executeXFRM[T any](ctx context.Context, d SystemXFRMDriver, name string, run func(context.Context, SystemXFRMDriver) (T, error)) (T, error) {
	var zero T
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	executor := d.executor
	if executor == nil {
		return run(ctx, d)
	}
	workCtx, cancel := context.WithTimeout(ctx, xfrmOperationTimeout)
	defer cancel()
	op := &xfrmOperation{name: name, started: time.Now(), cancel: cancel}
	executor.mu.Lock()
	if executor.closed {
		executor.mu.Unlock()
		return zero, errXFRMClosed
	}
	if active := executor.active; active != nil {
		executor.mu.Unlock()
		return zero, active.err(nil)
	}
	executor.active = op
	executor.mu.Unlock()
	type result struct {
		value T
		err   error
	}
	done := make(chan result, 1)
	// Nested driver methods execute on the same worker, without reacquiring
	// the slot or starting a separate timeout for every step.
	d.executor = nil
	go func() {
		value, err := run(workCtx, d)
		executor.mu.Lock()
		executor.active = nil
		executor.mu.Unlock()
		done <- result{value, err}
	}()
	select {
	case result := <-done:
		// Cancellation and completion can become ready together. Never
		// publish a result produced after the caller's operation expired.
		if err := workCtx.Err(); err != nil {
			return zero, op.err(err)
		}
		return result.value, result.err
	case <-workCtx.Done():
		return zero, op.err(workCtx.Err())
	}
}

func executeXFRMError(ctx context.Context, d SystemXFRMDriver, name string, run func(context.Context, SystemXFRMDriver) error) error {
	_, err := executeXFRM(ctx, d, name, func(ctx context.Context, raw SystemXFRMDriver) (struct{}, error) {
		return struct{}{}, run(ctx, raw)
	})
	return err
}

func cloneXFRMSpec(spec TransportLinkSpec) TransportLinkSpec {
	spec.ContactPoints = slices.Clone(spec.ContactPoints)
	spec.LocalPrivateKey = slices.Clone(spec.LocalPrivateKey)
	spec.PeerPublicKey = slices.Clone(spec.PeerPublicKey)
	return spec
}

func (d SystemXFRMDriver) EnsureNamespace(ctx context.Context, spec NetNSSpec) error {
	return executeXFRMError(ctx, d, "ensure namespace "+netnsLabel(spec), func(ctx context.Context, raw SystemXFRMDriver) error {
		return raw.ensureNamespace(ctx, spec)
	})
}

func (d SystemXFRMDriver) EnsureInterface(ctx context.Context, spec TransportLinkSpec) error {
	spec = cloneXFRMSpec(spec)
	return executeXFRMError(ctx, d, "ensure interface "+spec.InterfaceName, func(ctx context.Context, raw SystemXFRMDriver) error {
		return raw.ensureInterface(ctx, spec)
	})
}

func (d SystemXFRMDriver) DeleteInterface(ctx context.Context, name string) error {
	return executeXFRMError(ctx, d, "delete interface "+name, func(ctx context.Context, raw SystemXFRMDriver) error {
		return raw.deleteInterface(ctx, name)
	})
}

func (d SystemXFRMDriver) AssignAddress(ctx context.Context, spec TransportLinkSpec, address string) error {
	spec = cloneXFRMSpec(spec)
	return executeXFRMError(ctx, d, "assign address "+spec.InterfaceName, func(ctx context.Context, raw SystemXFRMDriver) error {
		return raw.assignAddress(ctx, spec, address)
	})
}

func (d SystemXFRMDriver) AssignExtraAddress(ctx context.Context, spec TransportLinkSpec, address string) error {
	spec = cloneXFRMSpec(spec)
	return executeXFRMError(ctx, d, "assign extra address "+spec.InterfaceName, func(ctx context.Context, raw SystemXFRMDriver) error {
		return raw.assignExtraAddress(ctx, spec, address)
	})
}

func (d SystemXFRMDriver) InspectLink(ctx context.Context, spec TransportLinkSpec) (XFRMLinkState, error) {
	spec = cloneXFRMSpec(spec)
	return executeXFRM(ctx, d, "inspect interface "+spec.InterfaceName, func(ctx context.Context, raw SystemXFRMDriver) (XFRMLinkState, error) {
		return raw.inspectLink(ctx, spec)
	})
}

func (d SystemXFRMDriver) InspectLinks(ctx context.Context, specs []TransportLinkSpec, namespaces []NetNSSpec) ([]XFRMLinkState, []XFRMLinkState, error) {
	specs = slices.Clone(specs)
	for i := range specs {
		specs[i] = cloneXFRMSpec(specs[i])
	}
	namespaces = slices.Clone(namespaces)
	type observation struct{ states, inventory []XFRMLinkState }
	result, err := executeXFRM(ctx, d, "inspect interfaces", func(ctx context.Context, raw SystemXFRMDriver) (observation, error) {
		states, inventory, err := raw.inspectLinks(ctx, specs, namespaces)
		return observation{states, inventory}, err
	})
	return result.states, result.inventory, err
}

func (d SystemXFRMDriver) EnsureObservedInterfaces(ctx context.Context, observed []XFRMObservedInterface) error {
	observed = slices.Clone(observed)
	for i := range observed {
		observed[i].Spec = cloneXFRMSpec(observed[i].Spec)
		observed[i].State.Addresses = slices.Clone(observed[i].State.Addresses)
	}
	return executeXFRMError(ctx, d, "maintain interfaces", func(ctx context.Context, raw SystemXFRMDriver) error {
		return raw.ensureObservedInterfaces(ctx, observed)
	})
}

func (d SystemXFRMDriver) FilterSAsWithMissingLinks(ctx context.Context, desired []TransportLinkSpec, sas []SAState) ([]SAState, map[string]TransportLinkSpec, error) {
	desired = slices.Clone(desired)
	for i := range desired {
		desired[i] = cloneXFRMSpec(desired[i])
	}
	// The filter compacts its SA slice in place, so the worker must own it.
	sas = slices.Clone(sas)
	type observation struct {
		sas     []SAState
		missing map[string]TransportLinkSpec
	}
	result, err := executeXFRM(ctx, d, "filter interfaces", func(ctx context.Context, raw SystemXFRMDriver) (observation, error) {
		filtered, missing, err := raw.filterSAsWithMissingLinks(ctx, desired, sas)
		return observation{filtered, missing}, err
	})
	return result.sas, result.missing, err
}
