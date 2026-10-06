package photonwindows

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

type runtimePacketDevice struct {
	input  chan []byte
	output chan []byte
	closed chan struct{}
	once   sync.Once
}

func newRuntimeDevice() *runtimePacketDevice {
	return &runtimePacketDevice{input: make(chan []byte, 64), output: make(chan []byte, 64), closed: make(chan struct{})}
}
func (d *runtimePacketDevice) Read(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-d.closed:
		return nil, errors.New("closed")
	case packet := <-d.input:
		return packet, nil
	}
}
func (d *runtimePacketDevice) Write(packet []byte) error {
	select {
	case <-d.closed:
		return errors.New("closed")
	default:
	}
	select {
	case d.output <- packet:
		return nil
	default:
		return errors.New("full")
	}
}
func (d *runtimePacketDevice) Close() error { d.once.Do(func() { close(d.closed) }); return nil }

func runtimeFixture(t *testing.T) *pipelineFixture {
	t.Helper()
	f := newPipelineFixture(t)
	overlay := ipsec.OverlayIntentRecord{Version: 1, OverlayID: f.config.Overlay.ID, Provider: ipsec.ProviderStrongSwan, PathKeys: []string{ipsec.DefaultPathKey}, TunnelAddress: ipsec.TunnelAddressSpec{Mode: ipsec.TunnelAddressDerivedLinkLocal, Family: ipsec.FamilyIPv6}}
	for _, path := range []zone.ZonePath{f.config.ManagedZone, f.plan.Selected.Zone} {
		f.put(path, ipsec.OverlayIntentRecordKey(f.config.Overlay.ID), ipsec.RecordTypeOverlayIntent, overlay)
	}
	binding, err := localTransportAuthorization(f.config, f.view, f.now)
	if err != nil {
		t.Fatal(err)
	}
	f.p.tunnel.localAuthorization = binding
	f.config.Wintun = WintunConfig{AdapterName: "test", MTU: 1400}
	return f
}
func runtimeOpenResult(t *testing.T, r *leafRuntime) leafOpenResult {
	t.Helper()
	select {
	case result := <-r.opened:
		return result
	case <-time.After(time.Second):
		t.Fatal("device creation did not complete")
		return leafOpenResult{}
	}
}

func TestLeafRuntimeAttachesDeviceAndRevokesBeforeCleanup(t *testing.T) {
	f := runtimeFixture(t)
	device := newRuntimeDevice()
	factory := func(ctx context.Context, name string, addresses, routes []netip.Prefix, mtu, metric uint32) (ownedPacketDevice, error) {
		if name != "test" || len(addresses) != 1 || addresses[0].String() != "10.9.0.1/32" || len(routes) != 1 || mtu != 1400 {
			return nil, errors.New("wrong platform intent")
		}
		return device, nil
	}
	runtime := newLeafRuntime(factory)
	t.Cleanup(func() { runtime.close() })
	if err := runtime.reconcile(t.Context(), f.config, f.view, f.plan, f.p.tunnel, f.p.routerID, f.now); err != nil {
		t.Fatal(err)
	}
	if runtime.pipeline != nil {
		t.Fatal("attached before platform completion")
	}
	result := runtimeOpenResult(t, runtime)
	if err := runtime.complete(t.Context(), f.config, f.view, f.plan, f.p.tunnel, f.p.routerID, f.now, result); err != nil {
		t.Fatal(err)
	}
	if runtime.pipeline == nil {
		t.Fatal("current device not attached")
	}
	f.p = runtime.pipeline
	if runtime.ready(f.config, f.view, f.plan, f.now) {
		t.Fatal("platform-only reported tunnel ready")
	}
	f.learn(t)
	if !runtime.ready(f.config, f.view, f.plan, f.now) {
		t.Fatal("authorized Babel+platform+SA not ready")
	}
	device.input <- f.packet(true)
	select {
	case packet := <-runtime.packets:
		if packet.generation != f.p.generation || !f.p.SubmitPacket(f.config, f.view, f.plan, f.now, packet.packet) {
			t.Fatal("reader event not submitted")
		}
	case <-time.After(time.Second):
		t.Fatal("device reader not pumped")
	}
	if !f.accept(t, f.businessCompletion(t)) {
		t.Fatal("device outbound completion rejected")
	}
	f.receiveBusiness(t)
	if !f.inbound(t, f.packet(false)) {
		t.Fatal("inbound rejected")
	}
	select {
	case <-device.output:
	case <-time.After(time.Second):
		t.Fatal("inbound did not reach configured device")
	}
	f.p.tunnel.generation++
	if err := runtime.reconcile(t.Context(), f.config, f.view, f.plan, f.p.tunnel, f.p.routerID, f.now); err == nil {
		t.Fatal("revoked generation accepted")
	}
	if runtime.pipeline != nil || runtime.device != nil {
		t.Fatal("revoked adapter remains attached")
	}
	select {
	case <-device.closed:
	default:
		t.Fatal("revoked device not closed")
	}
}

func TestLeafRuntimeDiscardsStaleRevisionAndLateOpen(t *testing.T) {
	for _, scenario := range []string{"revision", "stopped"} {
		t.Run(scenario, func(t *testing.T) {
			f := runtimeFixture(t)
			device := newRuntimeDevice()
			release := make(chan struct{})
			started := make(chan struct{})
			runtime := newLeafRuntime(func(context.Context, string, []netip.Prefix, []netip.Prefix, uint32, uint32) (ownedPacketDevice, error) {
				close(started)
				<-release
				return device, nil
			})
			t.Cleanup(func() { runtime.close() })
			if err := runtime.reconcile(t.Context(), f.config, f.view, f.plan, f.p.tunnel, f.p.routerID, f.now); err != nil {
				t.Fatal(err)
			}
			<-started
			if scenario == "stopped" {
				if err := runtime.stop(); err != nil {
					t.Fatal(err)
				}
				close(release)
				runtime.openWG.Wait()
			} else {
				close(release)
				result := runtimeOpenResult(t, runtime)
				f.view.Revision++
				if err := runtime.complete(t.Context(), f.config, f.view, f.plan, f.p.tunnel, f.p.routerID, f.now, result); err != nil {
					t.Fatal(err)
				}
			}
			if runtime.pipeline != nil {
				t.Fatal("stale asynchronous device attached")
			}
			select {
			case <-device.closed:
			case <-time.After(time.Second):
				t.Fatal("stale device leaked")
			}
		})
	}
}
