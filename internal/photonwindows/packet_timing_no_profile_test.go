//go:build !photon_profile

package photonwindows

import (
	"net/netip"
	"testing"
	"unsafe"
)

func TestFixturePacketTimingOrdinaryNoop(t *testing.T) {
	type originalLeafPacket struct {
		generation uint64
		packet     []byte
		err        error
	}
	type originalDatagram struct {
		generation uint64
		peer       netip.AddrPort
		packet     []byte
	}
	type originalCompletion struct {
		job    dataplaneJob
		packet []byte
		err    error
	}
	if unsafe.Sizeof(fixturePacketTiming{}) != 0 {
		t.Fatal("ordinary timing is not empty")
	}
	for _, shape := range []struct {
		name         string
		actual, want uintptr
	}{
		{"leafDevicePacket", unsafe.Sizeof(leafDevicePacket{}), unsafe.Sizeof(originalLeafPacket{})},
		{"tunnelDatagram", unsafe.Sizeof(tunnelDatagram{}), unsafe.Sizeof(originalDatagram{})},
		{"dataplaneCompletion", unsafe.Sizeof(dataplaneCompletion{}), unsafe.Sizeof(originalCompletion{})},
	} {
		if shape.actual != shape.want {
			t.Fatalf("ordinary %s grew from %d to %d bytes", shape.name, shape.want, shape.actual)
		}
	}
	allocs := testing.AllocsPerRun(100, func() {
		trace := beginFixturePacketTimingQueue(fixturePacketTimingOutbound)
		trace.Dequeue()
		trace.Classify(fixturePacketTimingBusiness)
		trace.MarkAESBegin()
		trace.MarkAESEnd()
		trace.MarkDeliveryBegin()
		trace.MarkUDPWriterAcquired()
		trace.MarkUDPValidationDone()
		trace.MarkUDPDeadlineDone()
		trace.MarkUDPWriteDone()
		trace.MarkDeliveryEnd()
		trace.Finish(fixturePacketTimingDelivered)
		if trace.Sampled() {
			t.Fatal("ordinary timing sampled a packet")
		}
	})
	if allocs != 0 {
		t.Fatalf("ordinary noop allocated: %v", allocs)
	}
}
