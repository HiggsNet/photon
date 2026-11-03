package photonwindows

import (
	"errors"
	"testing"
)

type ringPressureDevice struct {
	device packetDevice
	err    error
}

func (d *ringPressureDevice) Write(packet []byte) error {
	if d.err != nil {
		return d.err
	}
	return d.device.Write(packet)
}

func TestBabelKeepsAttachmentAfterDeviceRingPressure(t *testing.T) {
	f := newPipelineFixture(t)
	f.learn(t)
	device := &ringPressureDevice{device: f.device, err: errPacketDeviceFull}
	f.p.device = device

	packet := f.packet(false)
	if f.inbound(t, packet) || len(f.device.written) != 0 {
		t.Fatal("packet was reported delivered while ring was full")
	}
	device.err = nil
	if !f.inbound(t, packet) || len(f.device.written) != 1 {
		t.Fatal("existing attachment did not resume delivery")
	}
	device.err = errors.New("device failed")
	completion := f.inboundCompletion(t, packet)
	if _, err := f.p.Accept(f.config, f.view, f.plan, f.now, completion); !errors.Is(err, device.err) {
		t.Fatalf("device failure was suppressed: %v", err)
	}
}
