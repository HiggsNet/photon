package photonwindows

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
)

// Instrument real devices without replacing platform work or packet verdicts.
// A LUID is an OS slot that may be reused immediately after adapter destruction;
// these wrapper instances instead prove distinct successful resource lifetimes.
type b4DeviceCounters struct {
	opens, closes, reads, writes atomic.Uint64
	mu                           sync.Mutex
	latest                       *b4CountedDevice
}

type b4CountedDevice struct {
	ownedPacketDevice
	counters *b4DeviceCounters
	once     sync.Once
	closed   atomic.Bool
	closeErr error
}

func (s *b4DeviceCounters) open(ctx context.Context, name string, addresses, routes []netip.Prefix, mtu, metric uint32) (ownedPacketDevice, error) {
	device, err := openConfiguredPacketDevice(ctx, name, addresses, routes, mtu, metric)
	if err != nil {
		return nil, err
	}
	tracked := &b4CountedDevice{ownedPacketDevice: device, counters: s}
	s.mu.Lock()
	s.latest = tracked
	s.opens.Add(1)
	s.mu.Unlock()
	return tracked, nil
}

func (s *b4DeviceCounters) current() *b4CountedDevice {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.latest
}

func (s *b4DeviceCounters) String() string {
	return fmt.Sprintf("successful_opens=%d completed_closes=%d read_packets=%d written_packets=%d", s.opens.Load(), s.closes.Load(), s.reads.Load(), s.writes.Load())
}

func (d *b4CountedDevice) Read(ctx context.Context) ([]byte, error) {
	packet, err := d.ownedPacketDevice.Read(ctx)
	if err == nil {
		d.counters.reads.Add(1)
	}
	return packet, err
}

func (d *b4CountedDevice) Write(packet []byte) error {
	err := d.ownedPacketDevice.Write(packet)
	if err == nil {
		d.counters.writes.Add(1)
	}
	return err
}

func (d *b4CountedDevice) Close() error {
	d.once.Do(func() {
		d.closeErr = d.ownedPacketDevice.Close()
		d.closed.Store(true)
		d.counters.closes.Add(1)
	})
	return d.closeErr
}
