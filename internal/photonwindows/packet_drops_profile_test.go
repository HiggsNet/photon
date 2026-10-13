//go:build photon_profile

package photonwindows

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/photonclient/ike"
)

func assertFixtureDropDelta(t *testing.T, before, want FixturePacketDrops) {
	t.Helper()
	after := ReadFixturePacketDrops()
	got := FixturePacketDrops{
		RawIngress:  after.RawIngress - before.RawIngress,
		LeafIngress: after.LeafIngress - before.LeafIngress,
		ESPIngress:  after.ESPIngress - before.ESPIngress,
	}
	if got != want {
		t.Fatalf("packet queue drop delta = %+v, want %+v", got, want)
	}
}

func TestFixturePacketDropsConcurrentSnapshots(t *testing.T) {
	before := ReadFixturePacketDrops()
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for range 100 {
				recordRawIngressDrop()
				recordLeafIngressDrop()
				recordESPIngressDrop()
				_ = ReadFixturePacketDrops()
			}
		})
	}
	workers.Wait()
	assertFixtureDropDelta(t, before, FixturePacketDrops{800, 800, 800})
	// Reading cannot reset process totals or interfere with a later interval.
	if next := ReadFixturePacketDrops(); next != ReadFixturePacketDrops() {
		t.Fatal("snapshot changed counters")
	}
}

func TestFixturePacketDropsESPAdmission(t *testing.T) {
	before := ReadFixturePacketDrops()
	s := &packetSockets{ikePackets: make(chan tunnelDatagram, 16), espPackets: make(chan tunnelDatagram, 64)}
	ikePeer := netip.MustParseAddrPort("192.0.2.1:500")
	nattPeer := netip.MustParseAddrPort("192.0.2.1:4500")
	generation := s.SelectTunnel(ikePeer, nattPeer)
	esp := []byte{0x12, 0x34, 0x56, 0x78, 0, 0, 0, 1}
	for range cap(s.espPackets) {
		if !s.demuxLocked(esp, nattPeer) {
			t.Fatal("selected ESP bypassed demux")
		}
	}
	assertFixtureDropDelta(t, before, FixturePacketDrops{})
	for range 3 {
		if !s.demuxLocked(esp, nattPeer) {
			t.Fatal("full ESP queue bypassed demux")
		}
	}
	request, err := ike.NewInitiator()
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := ike.EncapsulateIKE(request.Request())
	if err != nil {
		t.Fatal(err)
	}
	for range cap(s.ikePackets) + 2 {
		if !s.demuxLocked(wrapped, nattPeer) || !s.demuxLocked(request.Request(), ikePeer) {
			t.Fatal("selected IKE bypassed demux")
		}
	}
	for _, packet := range [][]byte{{255}, {0}, {0, 0, 0, 0}, {0, 0, 0, 0, 1}} {
		if !s.demuxLocked(packet, nattPeer) {
			t.Fatal("selected keepalive or malformed NAT packet bypassed demux")
		}
	}
	foreign := netip.MustParseAddrPort("192.0.2.2:4500")
	if s.demuxLocked(esp, foreign) || s.demuxLocked([]byte("gossip"), foreign) {
		t.Fatal("unselected peer was consumed as tunnel traffic")
	}
	assertFixtureDropDelta(t, before, FixturePacketDrops{ESPIngress: 3})
	if len(s.espPackets) != 64 || len(s.ikePackets) != 16 {
		t.Fatal("diagnostics changed queue capacity or admission")
	}
	for range cap(s.espPackets) {
		got := <-s.espPackets
		if got.generation != generation || got.peer != nattPeer || !bytes.Equal(got.packet, esp) {
			t.Fatal("diagnostics changed admitted ESP bytes, generation or peer")
		}
	}
	// Once the existing consumer frees capacity, admission resumes without a
	// reset or another drop; a new selection keeps its original generation gate.
	generation = s.SelectTunnel(netip.AddrPort{}, nattPeer)
	if !s.demuxLocked(esp, nattPeer) || (<-s.espPackets).generation != generation {
		t.Fatal("selection or capacity recovery changed")
	}
	assertFixtureDropDelta(t, before, FixturePacketDrops{ESPIngress: 3})
}

// Each announced Read proves that the previous successful packet has finished
// its real leaf queue admission. The unbuffered input makes overload and error
// delivery deterministic without sleeping or changing the production reader.
type fixtureDropDevice struct {
	*runtimePacketDevice
	reading chan struct{}
	input   chan leafDevicePacket
}

func (d *fixtureDropDevice) Read(ctx context.Context) ([]byte, error) {
	select {
	case d.reading <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	select {
	case event := <-d.input:
		return event.packet, event.err
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-d.closed:
		return nil, errors.New("closed")
	}
}

func fixtureDropReaderReady(t *testing.T, d *fixtureDropDevice) {
	t.Helper()
	select {
	case <-d.reading:
	case <-time.After(time.Second):
		t.Fatal("leaf reader did not reach the next device Read")
	}
}

func fixtureDropReadResult(t *testing.T, d *fixtureDropDevice, event leafDevicePacket) {
	t.Helper()
	select {
	case d.input <- event:
	case <-time.After(time.Second):
		t.Fatal("leaf reader did not accept the device read result")
	}
}

func TestFixturePacketDropsLeafAdmissionAndReadTermination(t *testing.T) {
	for _, ending := range []string{"overflow", "read error", "cancel"} {
		t.Run(ending, func(t *testing.T) {
			f := runtimeFixture(t)
			d := &fixtureDropDevice{runtimePacketDevice: newRuntimeDevice(), reading: make(chan struct{}), input: make(chan leafDevicePacket)}
			r := newLeafRuntime(func(context.Context, string, []netip.Prefix, []netip.Prefix, uint32, uint32) (ownedPacketDevice, error) {
				return d, nil
			})
			t.Cleanup(func() { r.close() })
			if err := r.reconcile(t.Context(), f.config, f.view, f.plan, f.p.tunnel, f.p.routerID, f.now); err != nil {
				t.Fatal(err)
			}
			if err := r.complete(t.Context(), f.config, f.view, f.plan, f.p.tunnel, f.p.routerID, f.now, runtimeOpenResult(t, r)); err != nil {
				t.Fatal(err)
			}
			fixtureDropReaderReady(t, d)
			before := ReadFixturePacketDrops()
			for i := range cap(r.packets) {
				fixtureDropReadResult(t, d, leafDevicePacket{packet: []byte{byte(i)}})
				fixtureDropReaderReady(t, d)
			}
			assertFixtureDropDelta(t, before, FixturePacketDrops{})
			readErr := errors.New("fixture device read failure")
			switch ending {
			case "overflow":
				fixtureDropReadResult(t, d, leafDevicePacket{packet: []byte{255}})
				fixtureDropReaderReady(t, d)
				assertFixtureDropDelta(t, before, FixturePacketDrops{LeafIngress: 1})
			case "read error":
				fixtureDropReadResult(t, d, leafDevicePacket{err: readErr})
			case "cancel":
				r.cancelRead()
			}
			for i := range cap(r.packets) {
				got := <-r.packets
				if got.generation != f.p.generation || got.err != nil || !bytes.Equal(got.packet, []byte{byte(i)}) {
					t.Fatal("diagnostics changed admitted device packet order or generation")
				}
			}
			if ending == "overflow" {
				r.cancelRead()
			} else if ending == "read error" {
				select {
				case got := <-r.packets:
					if !errors.Is(got.err, readErr) || got.packet != nil {
						t.Fatal("full leaf queue lost its device error")
					}
				case <-time.After(time.Second):
					t.Fatal("device error was not delivered after freeing capacity")
				}
			}
			done := make(chan struct{})
			go func() { r.readWG.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("device reader did not terminate")
			}
			want := FixturePacketDrops{}
			if ending == "overflow" {
				want.LeafIngress = 1
			}
			assertFixtureDropDelta(t, before, want)
		})
	}
}
