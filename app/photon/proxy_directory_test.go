package main

import (
	"net/netip"
	"testing"

	"github.com/HiggsNet/photon/internal/photonlinux"
	photonstate "github.com/HiggsNet/photon/internal/state"
	"github.com/HiggsNet/photon/pkg/service"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestProxyAnnouncementReusesOnlyAnExplicitIPsecHost(t *testing.T) {
	config := defaultAppConfig()
	config.IPsec.AnnounceAddrs = []photonlinux.IPsecAnnounceAddress{{Address: "2001:db8::9"}}
	input := service.ProxyMutation{Record: &service.ProxyCapability{}, AnnouncePort: 8444}
	got, err := prepareProxyCapability(config, input)
	if err != nil || got.Record.Address != "[2001:db8::9]:8444" || got.Record.Transport != service.ProxyTransport || got.AnnouncePort != 0 {
		t.Fatalf("announce address = %+v, %v", got.Record, err)
	}
	if input.Record.Address != "" {
		t.Fatal("resolution mutated the caller's input")
	}
	config.IPsec.AnnounceDNS = []photonlinux.IPsecAnnounceDNS{{Host: "proxy.example"}}
	if _, err := prepareProxyCapability(config, input); err == nil {
		t.Fatal("ambiguous IPsec announce hosts were resolved implicitly")
	}
	config.IPsec.AnnounceAddrs = nil
	got, err = prepareProxyCapability(config, input)
	if err != nil || got.Record.Address != "proxy.example:8444" {
		t.Fatalf("announce domain = %+v, %v", got.Record, err)
	}
}

func TestProxyDirectLinksExposeInstalledGenerationsForTheirActualFamily(t *testing.T) {
	d := &Daemon{}
	instance := ipsec.LinkInstance{
		ID: "instance", LinkID: "link", PeerZone: "peer.", PathKey: "family:ipv4", ActualState: ipsec.LinkStateUp,
		IKEName: "old", XFRMIfID: 1, InterfaceName: "phxold", RemoteGeneration: 2,
		LocalTunnelAddr: netip.MustParseAddr("fe80::1"), PeerTunnelAddr: netip.MustParseAddr("fe80::2"),
		StagedIKEName: "new", StagedXFRMIfID: 2, StagedInterfaceName: "phxnew", StagedGeneration: 3,
		StagedLocalTunnelAddr: netip.MustParseAddr("fe80::3"), StagedPeerTunnelAddr: netip.MustParseAddr("fe80::4"),
	}
	observed := &ipsecObservationSummary{
		Desired: []photonstate.DesiredLinkObservation{{InstanceID: instance.ID, LocalTunnelAddr: "fe80::3%phxnew netns=photon"}},
		ActualSAs: []photonstate.LinkSAObservation{
			{Name: "old", XFRMIfID: 1, RemoteEndpoint: "192.0.2.2:4500", Established: true, ChildState: "INSTALLED"},
			{Name: "new", XFRMIfID: 2, RemoteEndpoint: "192.0.2.2:4500", ChildState: "INSTALLING"},
		},
	}
	check := func(count int) []service.ProxyDirectLink {
		t.Helper()
		d.linuxObservation.replaceIPsec(map[string]ipsec.LinkInstance{instance.ID: instance}, observed)
		links := d.proxyDirectLinks()
		if len(links) != count {
			t.Fatalf("got %+v, want %d links", links, count)
		}
		return links
	}
	if links := check(1); links[0].Staged || links[0].Generation != 2 || links[0].Local != instance.LocalTunnelAddr || links[0].NetNS != "photon" {
		t.Fatalf("unexpected active link: %+v", links[0])
	}
	staged := &observed.ActualSAs[1]
	staged.Established, staged.ChildState = true, "INSTALLED"
	staged.RemoteEndpoint = "[2001:db8::2]:4500"
	check(1)
	staged.RemoteEndpoint = "192.0.2.2:4500"
	if links := check(2); !links[1].Staged || links[1].Generation != 3 || links[1].Local != instance.StagedLocalTunnelAddr || links[1].ID != links[0].ID {
		t.Fatalf("unexpected staged link: %+v", links[1])
	}
}
