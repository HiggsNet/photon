package photonlinux

import (
	"context"
	"testing"

	"github.com/HiggsNet/photon/pkg/health"
	transportipsec "github.com/HiggsNet/photon/pkg/transport/ipsec"
)

type closeTrackingHealthProber struct {
	closed int
}

func (*closeTrackingHealthProber) Type() string { return health.ProbeTypeICMP }

func (*closeTrackingHealthProber) Probe(context.Context, health.ProbeTarget, health.ProbeConfig) health.ProbeResult {
	return health.ProbeResult{}
}

func (p *closeTrackingHealthProber) Close() { p.closed++ }

type lifecycleDriver struct {
	transportipsec.DryRunDriver
	events chan transportipsec.VICIEvent
}

func (d *lifecycleDriver) SubscribeLifecycleEvents(context.Context) (<-chan transportipsec.VICIEvent, func(), error) {
	return d.events, func() {}, nil
}

func mustNewLinuxDriver(t *testing.T, options LinuxDriverOptions) *LinuxDriver {
	t.Helper()
	driver, err := NewLinuxDriver(options)
	if err != nil {
		t.Fatalf("NewLinuxDriver: %v", err)
	}
	return driver
}

func TestLinuxDriverOwnsIPsecCleanupDependencies(t *testing.T) {
	driver := &transportipsec.DryRunDriver{}
	linuxDriver := mustNewLinuxDriver(t, LinuxDriverOptions{IPsecDriver: driver, XFRMDriver: driver})
	remaining, cleaned, err := linuxDriver.CleanupIPsecLinks(context.Background(), nil, []string{"already-missing"})
	if err != nil {
		t.Fatalf("CleanupIPsecLinks: %v", err)
	}
	if cleaned != 0 || len(remaining) != 0 {
		t.Fatalf("cleanup result = (%d, %v), want empty idempotent result", cleaned, remaining)
	}
}

func TestLinuxDriverClosesOwnedDependenciesOnce(t *testing.T) {
	closed := 0
	prober := &closeTrackingHealthProber{}
	driver := &transportipsec.DryRunDriver{}
	linuxDriver := mustNewLinuxDriver(t, LinuxDriverOptions{IPsecDriver: driver, XFRMDriver: driver, HealthProber: prober, Close: func() error {
		closed++
		return nil
	}})
	if err := linuxDriver.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := linuxDriver.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if closed != 1 {
		t.Fatalf("close calls = %d, want 1", closed)
	}
	if prober.closed != 1 {
		t.Fatalf("health prober close calls = %d, want 1", prober.closed)
	}
}

func TestLinuxDriverOwnsHealthProber(t *testing.T) {
	driver := &transportipsec.DryRunDriver{}
	injected := &closeTrackingHealthProber{}
	linuxDriver := mustNewLinuxDriver(t, LinuxDriverOptions{IPsecDriver: driver, XFRMDriver: driver, HealthProber: injected})
	if linuxDriver.HealthProber() != injected {
		t.Fatal("driver did not expose its injected health prober")
	}
	defaultDriver := mustNewLinuxDriver(t, LinuxDriverOptions{IPsecDriver: driver, XFRMDriver: driver})
	if defaultDriver.HealthProber() == nil {
		t.Fatal("driver did not construct the default Linux health prober")
	}
	_ = linuxDriver.Close()
	_ = defaultDriver.Close()
}

func TestLinuxDriverOwnsIPsecObservationAndLifecycleSubscription(t *testing.T) {
	driver := &lifecycleDriver{events: make(chan transportipsec.VICIEvent, 1)}
	linuxDriver := mustNewLinuxDriver(t, LinuxDriverOptions{IPsecDriver: driver, XFRMDriver: driver})
	if sas, err := linuxDriver.ListIPsecSAs(context.Background()); err != nil || len(sas) != 0 {
		t.Fatalf("ListIPsecSAs = (%v, %v), want empty observation", sas, err)
	}
	events, stop, supported, err := linuxDriver.SubscribeIPsecLifecycle(context.Background())
	if err != nil || !supported || events == nil || stop == nil {
		t.Fatalf("SubscribeIPsecLifecycle = (events=%v stop=%v supported=%v err=%v)", events != nil, stop != nil, supported, err)
	}
	stop()
}

func TestNewLinuxDriverRequiresExplicitDrivers(t *testing.T) {
	driver := &transportipsec.DryRunDriver{}
	if _, err := NewLinuxDriver(LinuxDriverOptions{XFRMDriver: driver}); err == nil {
		t.Fatal("missing IPsec driver was accepted")
	}
	if _, err := NewLinuxDriver(LinuxDriverOptions{IPsecDriver: driver}); err == nil {
		t.Fatal("missing XFRM driver was accepted")
	}
}
