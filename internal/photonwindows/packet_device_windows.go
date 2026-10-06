package photonwindows

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"sync"
	"time"
)

// configuredPacketDevice owns only Windows resources. Business authorization
// and packet generation belong to the portable daemon owner. Cancellation must
// not tear down the raw adapter before IP Helper has withdrawn its resources.
type configuredPacketDevice struct {
	device   *wintunDevice
	driver   *ipHelperDriver
	cleanup  ipHelperIntent
	cancel   context.CancelFunc
	mu       sync.Mutex
	closed   bool
	once     sync.Once
	closeErr error
}

func openConfiguredPacketDevice(ctx context.Context, name string, addresses, splitRoutes []netip.Prefix, mtu, metric uint32) (ownedPacketDevice, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(addresses) == 0 || len(splitRoutes) == 0 {
		return nil, errors.New("packet device requires verified host addresses and split routes")
	}
	if err := validateIPHelperPrefixes(addresses, splitRoutes); err != nil {
		return nil, err
	}
	if mtu < 1280 || mtu > 65535 || metric == 0 || metric > 9999 {
		return nil, errors.New("invalid packet device MTU or metric")
	}
	for _, address := range addresses {
		covered := false
		for _, route := range splitRoutes {
			covered = covered || route.Contains(address.Addr())
		}
		if !covered {
			return nil, errors.New("packet device address outside configured split routes")
		}
	}
	for _, route := range splitRoutes {
		family := false
		for _, address := range addresses {
			family = family || address.Addr().BitLen() == route.Addr().BitLen()
		}
		if !family {
			return nil, errors.New("packet device route has no local address family")
		}
	}
	raw, err := openWintun(context.WithoutCancel(ctx), name, nil)
	if err != nil {
		return nil, err
	}
	driver, err := newIPHelperDriver(raw, splitRoutes)
	if err != nil {
		raw.Close()
		return nil, err
	}
	lifetime, cancel := context.WithCancel(ctx)
	d := &configuredPacketDevice{device: raw, driver: driver, cleanup: ipHelperIntent{MTU: mtu, Metric: metric}, cancel: cancel}
	// No callback is armed until initialization finishes: the constructor owns
	// failure cleanup, so cancellation cannot race partially initialized fields.
	readyCtx, readyCancel := context.WithTimeout(ctx, 10*time.Second)
	defer readyCancel()
	want := ipHelperIntent{Addresses: addresses, Routes: splitRoutes, MTU: mtu, Metric: metric}
	_, err = driver.Reconcile(readyCtx, want)
	if err == nil {
		err = waitIPHelperReady(readyCtx, driver, want)
	}
	if err != nil {
		return nil, errors.Join(err, d.Close())
	}
	context.AfterFunc(lifetime, func() { _ = d.Close() })
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(err, d.Close())
	}
	return d, nil
}

// IP Helper creation is asynchronous with respect to duplicate-address
// detection. Never advertise device readiness while either family is tentative.
func waitIPHelperReady(ctx context.Context, driver *ipHelperDriver, want ipHelperIntent) error {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		have, err := driver.Observe(ctx)
		if err != nil {
			return err
		}
		plan, err := planIPHelper(want, have)
		if err != nil {
			return err
		}
		if !plan.empty() {
			return errors.New("packet device configuration drifted before readiness")
		}
		ready := len(have.addresses) == len(want.Addresses)
		for _, row := range have.addresses {
			if row.DadState == 2 {
				return errors.New("packet device duplicate address detected")
			}
			ready = ready && row.DadState == 4 // IpDadStatePreferred
		}
		if ready {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (d *configuredPacketDevice) Read(ctx context.Context) ([]byte, error) {
	d.mu.Lock()
	closed := d.closed
	d.mu.Unlock()
	if closed {
		return nil, io.ErrClosedPipe
	}
	packet, err := d.device.Read(ctx)
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil, io.ErrClosedPipe
	}
	return packet, err
}

func (d *configuredPacketDevice) Write(packet []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return io.ErrClosedPipe
	}
	return d.device.Write(packet)
}

func (d *configuredPacketDevice) Close() error {
	d.once.Do(func() {
		d.mu.Lock()
		d.closed = true // deny delivery before removing any OS resources
		d.mu.Unlock()
		d.cancel()
		_, d.closeErr = d.driver.Reconcile(context.Background(), d.cleanup)
		// Adapter destruction is the fallback even when observation or explicit
		// removal fails. It also joins the bounded Wintun reader.
		d.device.Close()
	})
	return d.closeErr
}
