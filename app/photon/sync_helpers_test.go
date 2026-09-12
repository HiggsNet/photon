package main

import (
	"crypto/ed25519"
	"errors"
	"github.com/HiggsNet/photon/internal/photonlinux"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
	"os"
	"testing"
	"time"
)

func buildTestDaemonOwners(t testing.TB) (*corestate.VerifiedState, *corestate.GossipCheckpoint, *photonlinux.LinuxState, *appConfig) {
	t.Helper()

	rootPub, rootPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(root): %v", err)
	}
	catofesPub, catofesPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(catofes): %v", err)
	}
	nodeBPub, nodeBPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(node-b): %v", err)
	}

	rootAuthority := &zone.ZoneAuthority{
		Zone:      zone.RootZone,
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: rootPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermDelegate},
			}},
		}},
	}
	catofesAuthority := &zone.ZoneAuthority{
		Zone:      "catofes.",
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: catofesPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermDelegate},
			}},
		}},
	}
	nodeBAuthority := &zone.ZoneAuthority{
		Zone:      "node-b.catofes.",
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: nodeBPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermWrite},
			}},
		}},
	}

	catofesDelegation := &zone.Delegation{
		ZoneName:  "catofes.",
		Scope:     zone.DelegationScopeDirectChild,
		Authority: *catofesAuthority,
	}
	if err := photoncrypto.SignDelegation(catofesDelegation, zone.RootZone, rootPriv); err != nil {
		t.Fatalf("SignDelegation(catofes): %v", err)
	}

	nodeBDelegation := &zone.Delegation{
		ZoneName:  "node-b.catofes.",
		Scope:     zone.DelegationScopeDirectChild,
		Authority: *nodeBAuthority,
	}
	if err := photoncrypto.SignDelegation(nodeBDelegation, "catofes.", catofesPriv); err != nil {
		t.Fatalf("SignDelegation(node-b): %v", err)
	}

	ns := zone.NewNetworkState()
	ns.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, rootAuthority)
	ns.Zones["catofes."] = zone.NewZoneState("catofes.", catofesAuthority)
	ns.Zones["node-b.catofes."] = zone.NewZoneState("node-b.catofes.", nodeBAuthority)
	ns.Zones[zone.RootZone].Delegations["catofes."] = catofesDelegation
	ns.Zones["catofes."].Delegations["node-b.catofes."] = nodeBDelegation

	configureValidation(ns)

	now := time.Unix(123, 0)
	if err := photoncrypto.VerifyChain(ns, "catofes.", now); err != nil {
		t.Fatalf("VerifyChain(catofes): %v", err)
	}
	if err := photoncrypto.VerifyChain(ns, "node-b.catofes.", now); err != nil {
		t.Fatalf("VerifyChain(node-b): %v", err)
	}

	verified := &corestate.VerifiedState{
		ManagedZone:        "node-a.catofes.",
		Network:            ns,
		IdentityPrivateKey: nodeBPriv,
	}
	config := defaultAppConfig()
	config.PeerID = "node-a.catofes."
	config.ListenAddr = "127.0.0.1:0"
	return verified, &corestate.GossipCheckpoint{}, &photonlinux.LinuxState{}, config
}

func skipRestrictedSocket(t *testing.T, err error) {
	t.Helper()
	if errors.Is(err, os.ErrPermission) {
		t.Skipf("UDP sockets are not permitted in this environment: %v", err)
	}
}
