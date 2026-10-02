package host

import (
	"errors"
	"net"
	"testing"
)

func TestUpdateGossipBootstrapIsDetachedAndPreservesPeerIDs(t *testing.T) {
	driver := NewGossipDriver(nil, 0, nil, GossipDriverConfig{Discovery: GossipDiscoveryConfig{BootstrapPeers: []string{"gateway."}}})
	defer driver.Stop()
	peers := map[string]*net.UDPAddr{"gateway.": {IP: net.ParseIP("192.0.2.2"), Port: 33434}}
	if err := driver.UpdateGossipBootstrap(peers); err != nil {
		t.Fatal(err)
	}
	peers["gateway."].IP[15] = 99
	delete(peers, "gateway.")
	input := driver.GossipDiscoveryInput(nil)
	if len(input.BootstrapPeers) != 1 || input.BootstrapPeers[0] != "gateway." || input.Bootstrap["gateway."].String() != "192.0.2.2:33434" {
		t.Fatalf("discovery: %+v", input)
	}
	input.Bootstrap["gateway."].Port = 1
	if driver.GossipDiscoveryInput(nil).Bootstrap["gateway."].Port != 33434 {
		t.Fatal("caller modified driver bootstrap state")
	}
	if err := driver.UpdateGossipBootstrap(nil); err != nil {
		t.Fatal(err)
	}
	if input := driver.GossipDiscoveryInput(nil); len(input.Bootstrap) != 0 || len(input.BootstrapPeers) != 1 {
		t.Fatal("clearing DNS results changed configured peer IDs")
	}
	driver.Stop()
	if err := driver.UpdateGossipBootstrap(peers); !errors.Is(err, ErrGossipDriverStopped) {
		t.Fatalf("update after stop: %v", err)
	}
}
