package main

import (
	"strings"
	"testing"
)

func TestFilterEndpointDiscoveryInputsLoopbackOnly(t *testing.T) {
	config := &appConfig{
		ListenAddr:        ":33434",
		AdvertiseAddrs:    []string{"127.0.0.1:33434", "203.0.113.10:33434"},
		Reflectors:        []string{"auto"},
		EndpointDiscovery: "loopback_only",
	}
	advertise, reflectors := filterEndpointDiscoveryInputs(config, 33434)
	if len(reflectors) != 0 {
		t.Fatalf("reflectors = %v, want empty", reflectors)
	}
	foundPublic := false
	for _, addr := range advertise {
		if strings.Contains(addr, "203.0.113.10") {
			foundPublic = true
		}
	}
	if foundPublic {
		t.Fatalf("public advertise addr should be filtered in loopback_only: %v", advertise)
	}
	if len(advertise) == 0 {
		t.Fatalf("expected at least one loopback advertise addr")
	}
}

func TestFilterEndpointDiscoveryInputsAdvertiseOnly(t *testing.T) {
	config := &appConfig{
		ListenAddr:        "127.0.0.1:33434",
		AdvertiseAddrs:    []string{"203.0.113.10:33434"},
		Reflectors:        []string{"auto"},
		EndpointDiscovery: "advertise_only",
	}
	advertise, reflectors := filterEndpointDiscoveryInputs(config, 33434)
	if len(reflectors) != 0 {
		t.Fatalf("reflectors = %v, want empty", reflectors)
	}
	if len(advertise) != 1 || advertise[0] != "203.0.113.10:33434" {
		t.Fatalf("advertise = %v, want [203.0.113.10:33434]", advertise)
	}
}

func TestFilterEndpointDiscoveryInputsAutoLoopbackBootstrap(t *testing.T) {
	config := &appConfig{
		ListenAddr: ":33434",
		Bootstrap: []syncConfigPeer{
			{ID: "peer-a", Addr: "127.0.0.1:33435"},
		},
		AdvertiseAddrs: []string{"203.0.113.10:33434"},
		Reflectors:     []string{"auto"},
	}
	advertise, reflectors := filterEndpointDiscoveryInputs(config, 33434)
	if len(reflectors) != 0 {
		t.Fatalf("auto loopback-only should suppress reflectors")
	}
	for _, addr := range advertise {
		if strings.Contains(addr, "203.0.113.10") {
			t.Fatalf("auto loopback-only should filter public advertise addrs: %v", advertise)
		}
	}
}

func TestFilterEndpointDiscoveryInputsAutoPublicBootstrap(t *testing.T) {
	config := &appConfig{
		ListenAddr: ":33434",
		Bootstrap: []syncConfigPeer{
			{ID: "peer-a", Addr: "203.0.113.10:33435"},
		},
		AdvertiseAddrs: []string{"203.0.113.10:33434"},
		Reflectors:     []string{"auto"},
	}
	advertise, reflectors := filterEndpointDiscoveryInputs(config, 33434)
	if len(reflectors) == 0 {
		t.Fatalf("auto with public bootstrap should keep reflectors")
	}
	if len(advertise) != 1 || advertise[0] != "203.0.113.10:33434" {
		t.Fatalf("advertise = %v, want [203.0.113.10:33434]", advertise)
	}
}
