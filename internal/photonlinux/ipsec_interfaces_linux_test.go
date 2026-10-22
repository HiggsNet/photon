//go:build linux

package photonlinux

import (
	"os"
	"testing"
)

func TestIPsecInterfaceHostObservation(t *testing.T) {
	if os.Getenv("PHOTON_IPSEC_INTERFACE_SMOKE") != "1" {
		t.Skip("set PHOTON_IPSEC_INTERFACE_SMOKE=1 for read-only native netlink observation")
	}
	inventory, err := ReadIPsecInterfaces()
	if err != nil {
		t.Fatal(err)
	}
	if len(inventory) == 0 {
		t.Fatal("empty host interface inventory")
	}
	foundLoopback := false
	for _, device := range inventory {
		if device.Name == "lo" {
			foundLoopback = true
			if !device.Up || len(device.Addresses) == 0 {
				t.Fatalf("loopback flags/addresses missing: %+v", device)
			}
		}
		for _, entry := range device.Addresses {
			if !entry.Address.IsValid() {
				t.Fatalf("invalid address on %s", device.Name)
			}
		}
	}
	if !foundLoopback {
		t.Fatal("loopback missing from netlink inventory")
	}
}
