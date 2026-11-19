package main

import (
	"testing"

	"github.com/HiggsNet/photon/internal/photonlinux"
	"github.com/HiggsNet/photon/pkg/service"
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
