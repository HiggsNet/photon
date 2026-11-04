package photonwindows

import (
	"net/netip"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/photonclient/esp"
)

type blockingMeshRXDevice struct {
	entered chan struct{}
	release chan struct{}
}

func (d *blockingMeshRXDevice) Write([]byte) error {
	close(d.entered)
	<-d.release
	return nil
}

func TestMeshRXDeviceWriteDoesNotBlockRouteSelection(t *testing.T) {
	m, _, p, event := meshHostRouteFixture(t)
	child := dataplaneChild(p.tunnel.data.active.spi)
	sender, err := esp.NewSender(child.InitiatorSPI, child.Keys.ResponderToInitiator)
	if err != nil {
		t.Fatal(err)
	}
	inner := dataplanePacket(false)
	copy(inner[12:16], []byte{10, 1, 2, 3})
	copy(inner[16:20], []byte{10, 9, 0, 1})
	wire, err := sender.Seal(inner)
	if err != nil {
		t.Fatal(err)
	}
	d := &blockingMeshRXDevice{entered: make(chan struct{}), release: make(chan struct{})}
	p.leaf.pipeline.device = d
	done := make(chan struct{})
	go func() {
		defer close(done)
		m.receiveESP(tunnelDatagram{generation: p.tunnel.generation, peer: netip.MustParseAddrPort("192.0.2.1:4500"), packet: wire})
	}()
	defer func() { close(d.release); <-done }()
	select {
	case <-d.entered:
	case <-time.After(time.Second):
		t.Fatal("inbound packet was never delivered")
	}
	if !m.stateMu.TryLock() {
		t.Fatal("state mutex held over device write")
	}
	_, canSend := m.prepareHost(event)
	m.stateMu.Unlock()
	if !canSend {
		t.Fatal("upload did not pass route selection while download delivery waited")
	}
}
