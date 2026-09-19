package ipsec

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestLocalAnnounceDNSForceUpdatesStaleInitiatorSA(t *testing.T) {
	spec := TransportLinkSpec{
		LocalZone: "node-a.", PeerZone: "node-b.", OverlayID: "main",
		Provider: ProviderStrongSwan, TransportID: "link-a",
		XFRMIfID: 42, InitiatorRole: InitiatorRolePrimary,
	}
	instance := NewLinkInstance(spec, LinkStateUp, time.Unix(1000, 0))
	hosts := []string{"vpn.example.com"}
	resolver := staticDNSResolver{"vpn.example.com": {{IP: net.ParseIP("198.51.100.20")}}}
	sa := SAState{
		Name: "link-a", XFRMIfID: 42, Established: true,
		Initiator: true, InitiatorKnown: true, LocalEndpoint: "198.51.100.10:4500",
		InboundPackets: 8, InboundIdleSecs: 301, InboundKnown: true,
	}

	updates, err := LocalAnnounceDNSForceUpdates(context.Background(), hosts, 5*time.Minute, []TransportLinkSpec{spec}, map[string]LinkInstance{instance.ID: instance}, []SAState{sa}, resolver)
	if err != nil {
		t.Fatalf("LocalAnnounceDNSForceUpdates: %v", err)
	}
	if updates[instance.ID] != "local announce DNS changed after inbound idle" {
		t.Fatalf("updates = %#v, want stale local DNS update", updates)
	}

	partial := &sequenceDNSResolver{results: []dnsLookupResult{
		{addresses: resolver[hosts[0]]}, {err: context.DeadlineExceeded},
	}}
	updates, err = LocalAnnounceDNSForceUpdates(context.Background(), []string{hosts[0], "other.example.com"}, 5*time.Minute, []TransportLinkSpec{spec}, map[string]LinkInstance{instance.ID: instance}, []SAState{sa}, partial)
	if !errors.Is(err, context.DeadlineExceeded) || len(updates) != 0 {
		t.Fatalf("partial DNS answer triggered reconnect: updates=%v err=%v", updates, err)
	}

	sa.InboundIdleSecs = 10
	updates, err = LocalAnnounceDNSForceUpdates(context.Background(), hosts, 5*time.Minute, []TransportLinkSpec{spec}, map[string]LinkInstance{instance.ID: instance}, []SAState{sa}, resolver)
	if err != nil || len(updates) != 0 {
		t.Fatalf("active SA updates = %#v, err = %v", updates, err)
	}

	sa.InboundIdleSecs = 301
	sa.LocalEndpoint = "198.51.100.20:4500"
	updates, err = LocalAnnounceDNSForceUpdates(context.Background(), hosts, 5*time.Minute, []TransportLinkSpec{spec}, map[string]LinkInstance{instance.ID: instance}, []SAState{sa}, resolver)
	if err != nil || len(updates) != 0 {
		t.Fatalf("current DNS address updates = %#v, err = %v", updates, err)
	}
}

func TestLocalAnnounceDNSForceUpdatesSkipsNATScopeMismatch(t *testing.T) {
	spec := TransportLinkSpec{LocalZone: "node-a.", PeerZone: "node-b.", OverlayID: "main", Provider: ProviderStrongSwan, TransportID: "link-a", InitiatorRole: InitiatorRolePrimary}
	instance := NewLinkInstance(spec, LinkStateUp, time.Unix(1000, 0))
	sa := SAState{Name: "link-a", Established: true, Initiator: true, InitiatorKnown: true, LocalEndpoint: "192.168.1.10:4500", ChildAgeSeconds: 600, InboundKnown: true}
	hosts := []string{"vpn.example.com"}
	resolver := staticDNSResolver{"vpn.example.com": {{IP: net.ParseIP("198.51.100.20")}}}

	updates, err := LocalAnnounceDNSForceUpdates(context.Background(), hosts, 5*time.Minute, []TransportLinkSpec{spec}, map[string]LinkInstance{instance.ID: instance}, []SAState{sa}, resolver)
	if err != nil || len(updates) != 0 {
		t.Fatalf("NAT scope mismatch updates = %#v, err = %v", updates, err)
	}
}
