package photonwindows

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
)

// A single adapter serves every peer. Leases only keep it alive; closing
// a failed peer's lease cannot remove routes used by healthy peers.
type meshDevice struct {
	mu                sync.Mutex
	ctx               context.Context
	factory           packetDeviceFactory
	device            ownedPacketDevice
	addresses, routes []netip.Prefix
	generation        uint64
	activeGeneration  atomic.Uint64
	source            atomic.Pointer[meshDeviceSource]
	refs              int
	cancel            context.CancelFunc
	wake              func()
}

type meshDeviceSource struct {
	device     ownedPacketDevice
	generation uint64
}

type meshDeviceLease struct {
	owner  *meshDevice
	device ownedPacketDevice
	once   sync.Once
}

func newMeshDevice(ctx context.Context, factory packetDeviceFactory) *meshDevice {
	return &meshDevice{ctx: ctx, factory: factory}
}

func (m *meshDevice) acquire(ctx context.Context, name string, addresses, routes []netip.Prefix, mtu, metric uint32) (ownedPacketDevice, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if m.device != nil && (!slices.Equal(addresses, m.addresses) || !slices.Equal(routes, m.routes)) {
		return nil, errors.New("mesh: adapter address transition pending")
	}
	if m.device == nil {
		// Cancellation may abort the first acquisition while it is opening,
		// but a successful adapter belongs to the mesh, not that first peer.
		deviceCtx, cancel := context.WithCancel(m.ctx)
		stopCancel := context.AfterFunc(ctx, cancel)
		device, err := m.factory(deviceCtx, name, addresses, routes, mtu, metric)
		stopCancel()
		if err != nil || ctx.Err() != nil {
			cancel()
			if device != nil {
				err = errors.Join(err, device.Close())
			}
			return nil, errors.Join(err, ctx.Err())
		}
		if device == nil {
			cancel()
			return nil, errors.New("mesh: device factory returned no device")
		}
		m.device, m.addresses, m.routes = device, slices.Clone(addresses), slices.Clone(routes)
		m.generation++
		m.cancel = cancel
		m.activeGeneration.Store(m.generation)
		m.source.Store(&meshDeviceSource{device: device, generation: m.generation})
		if m.wake != nil {
			m.wake()
		}
	}
	m.refs++
	return &meshDeviceLease{owner: m, device: m.device}, nil
}

func (m *meshDevice) current(generation uint64) bool {
	// Device creation/DAD holds mu outside the event loop. An obsolete queued
	// host packet must never wait for that platform work in the packet owner.
	return generation != 0 && m.activeGeneration.Load() == generation
}

func (l *meshDeviceLease) Read(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
func (l *meshDeviceLease) Write(packet []byte) error { return l.device.Write(packet) }
func (l *meshDeviceLease) Close() (err error) {
	l.once.Do(func() {
		m := l.owner
		m.mu.Lock()
		defer m.mu.Unlock()
		m.refs--
		if m.refs == 0 {
			m.activeGeneration.Store(0)
			m.source.Store(nil)
			if m.wake != nil {
				m.wake()
			}
			m.cancel()
			err = m.device.Close()
			m.device = nil
		}
	})
	return err
}
