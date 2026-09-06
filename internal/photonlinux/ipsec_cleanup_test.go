package photonlinux

import (
	"context"
	"testing"
	"time"

	transportipsec "github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestCleanupLinkInstancesTearsDownOwnedResourcesAndIgnoresMissing(t *testing.T) {
	spec := transportipsec.TransportLinkSpec{
		LocalZone: "node-a.catofes.", PeerZone: "node-b.catofes.", OverlayID: "main",
		TransportID: "ipsec-cleanup", InterfaceName: "phx-clean0", XFRMIfID: 5100,
	}
	instance := transportipsec.NewLinkInstance(spec, transportipsec.LinkStateUp, time.Unix(1000, 0))
	driver := &transportipsec.DryRunDriver{}
	linuxDriver := mustNewLinuxDriver(t, LinuxDriverOptions{IPsecDriver: driver, XFRMDriver: driver})
	remaining, cleaned, err := linuxDriver.CleanupIPsecLinks(context.Background(), map[string]transportipsec.LinkInstance{
		instance.ID: instance,
	}, []string{"already-missing", instance.ID})
	if err != nil {
		t.Fatal(err)
	}
	if cleaned != 1 || len(remaining) != 0 {
		t.Fatalf("cleaned/remaining = %d/%v", cleaned, remaining)
	}
	if len(driver.Terminated) != 1 || driver.Terminated[0] != spec.TransportID {
		t.Fatalf("terminated = %v", driver.Terminated)
	}
	if len(driver.DeletedIFs) != 1 || driver.DeletedIFs[0] != spec.InterfaceName {
		t.Fatalf("deleted interfaces = %v", driver.DeletedIFs)
	}
}

func TestCleanupOrphanConnectionsKeepsReferencedAndForeignNames(t *testing.T) {
	driver := &transportipsec.DryRunDriver{LoadedConnections: []transportipsec.ConnectionState{
		{Name: "ipsec-keep"},
		{Name: "ipsec-orphan"},
		{Name: "foreign"},
	}}
	linuxDriver := mustNewLinuxDriver(t, LinuxDriverOptions{IPsecDriver: driver, XFRMDriver: driver})
	cleaned, err := linuxDriver.CleanupIPsecOrphans(context.Background(), map[string]bool{"ipsec-keep": true})
	if err != nil {
		t.Fatal(err)
	}
	if cleaned != 1 {
		t.Fatalf("cleaned = %d, want 1", cleaned)
	}
	if len(driver.Terminated) != 1 || driver.Terminated[0] != "ipsec-orphan" {
		t.Fatalf("terminated = %v", driver.Terminated)
	}
	if len(driver.Unloaded) != 1 || driver.Unloaded[0] != "ipsec-orphan" {
		t.Fatalf("unloaded = %v", driver.Unloaded)
	}
}
