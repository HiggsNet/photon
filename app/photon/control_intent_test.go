package main

import (
	"testing"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	photonservice "github.com/HiggsNet/photon/pkg/service"
)

func TestCommonControlIntentAdaptersAreTypedAndDetached(t *testing.T) {
	pool, err := commonIPAMIntent(ipamMutationRequest{
		Operation: ipamOperationPoolCreate, Zone: "catofes.", Prefix: "10.0.0.1/16", Target: "pek.catofes.",
	})
	if err != nil {
		t.Fatalf("commonIPAMIntent(pool): %v", err)
	}
	if typed, ok := pool.(corestate.PutIPAMPoolIntent); !ok || typed.Zone != "catofes." || typed.DelegatedTo != "pek.catofes." {
		t.Fatalf("pool intent = %#v", pool)
	}
	assignment, err := commonIPAMIntent(ipamMutationRequest{
		Operation: ipamOperationAssignmentRevoke, Zone: "catofes.", Prefix: "10.0.1.0/24", Target: "node.pek.catofes.",
	})
	if err != nil {
		t.Fatalf("commonIPAMIntent(assignment): %v", err)
	}
	if typed, ok := assignment.(corestate.RevokeIPAMAssignmentIntent); !ok || typed.AssignedTo != "node.pek.catofes." {
		t.Fatalf("assignment intent = %#v", assignment)
	}
	if _, ok := commonRouteIntent(routeMutationRequest{Zone: "node.pek.catofes.", Prefix: "10.0.1.0/24", Active: true}).(corestate.AnnounceRouteIntent); !ok {
		t.Fatal("active route request did not map to AnnounceRouteIntent")
	}
	if _, ok := commonRouteIntent(routeMutationRequest{Zone: "node.pek.catofes.", Prefix: "10.0.1.0/24"}).(corestate.WithdrawRouteIntent); !ok {
		t.Fatal("inactive route request did not map to WithdrawRouteIntent")
	}

	request := serviceMutationRequest{Operation: serviceOperationPublish, Endpoints: []photonservice.SOCKS5Endpoint{{
		Region: "cn", Address: "10.0.1.1", Port: 1080,
	}}}
	service, err := commonServiceIntent(request)
	if err != nil {
		t.Fatalf("commonServiceIntent: %v", err)
	}
	typed, ok := service.(corestate.PublishSOCKS5Intent)
	if !ok || len(typed.Endpoints) != 1 {
		t.Fatalf("service intent = %#v", service)
	}
	request.Endpoints[0].Address = "mutated"
	if typed.Endpoints[0].Address != "10.0.1.1" {
		t.Fatal("service intent retained control request endpoints")
	}
}
