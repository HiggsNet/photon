package photonwindows

import (
	"bytes"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

func TestPacketAuthorizationExactDelegationExpiry(t *testing.T) {
	f := newPipelineFixture(t)
	// A sub-second delegation deadline must invalidate a new event even when
	// its revision and Unix second are unchanged. Re-sign the root fixture so
	// this tests a valid expiry, not rejection of a corrupted signature.
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	root := f.view.State.Network.Zones[zone.RootZone]
	root.Authority = photoncrypto.ConfiguredRootAuthority(public)
	f.config.TrustedRootPublicKey = public
	for _, record := range root.Records {
		if err := photoncrypto.SignRecord(record, private); err != nil {
			t.Fatal(err)
		}
	}
	expires := f.now.Add(500 * time.Millisecond)
	delegation := root.Delegations[f.config.ManagedZone]
	delegation.ExpiresAt = &expires
	if err := photoncrypto.SignDelegation(delegation, zone.RootZone, private); err != nil {
		t.Fatal(err)
	}
	before, ok := f.p.prepare(f.config, f.view, f.plan, expires.Add(-time.Nanosecond))
	if !ok || !f.p.preparedCurrent(before) || len(before.hosts) == 0 {
		t.Fatal("valid signed facts unavailable before exact deadline")
	}
	if facts, ok := f.p.prepare(f.config, f.view, f.plan, expires); ok || facts != nil {
		t.Fatal("same revision retained authorization at sub-second expiry")
	}
}

func TestPacketAuthorizationRollbackAndPacketChecks(t *testing.T) {
	t.Run("clock rollback", func(t *testing.T) {
		f := newPipelineFixture(t)
		if _, ok := f.p.prepare(f.config, f.view, f.plan, f.now); !ok {
			t.Fatal("initial facts rejected")
		}
		if _, ok := f.p.prepare(f.config, f.view, f.plan, f.now.Add(-time.Nanosecond)); ok {
			t.Fatal("planner timestamp refreshed or rollback ignored")
		}
	})
	t.Run("packet and attachment", func(t *testing.T) {
		f := newPipelineFixture(t)
		f.learn(t)
		facts, ok := f.p.prepare(f.config, f.view, f.plan, f.now)
		if !ok || !f.p.authorize(facts, f.packet(true), true) || !f.p.authorize(facts, f.packet(false), false) {
			t.Fatal("authorized bidirectional traffic rejected")
		}
		for _, offset := range []int{12, 16} {
			packet := bytes.Clone(f.packet(true))
			packet[offset] = 11
			if f.p.authorize(facts, packet, true) {
				t.Fatal("per-packet source or destination gate bypassed")
			}
		}
		other := *f.p
		if other.preparedCurrent(facts) {
			t.Fatal("facts transferred to another attachment")
		}
		f.p.tunnel.generation++
		if f.p.authorize(facts, f.packet(true), true) {
			t.Fatal("prepared facts bypassed current generation")
		}
	})
}

func TestPacketAuthorizationChildActivationBeforeDelivery(t *testing.T) {
	f := newPipelineFixture(t)
	f.learn(t)
	if !f.submitFromDevice(t, f.packet(true)) {
		t.Fatal("initial outbound submit rejected")
	}
	outbound := f.businessCompletion(t)
	inbound := f.inboundCompletion(t, f.packet(false))
	facts, ok := f.p.prepare(f.config, f.view, f.plan, f.now)
	if !ok {
		t.Fatal("initial authorization rejected")
	}
	// The daemon's observeData can activate a peer's new CHILD after prepare,
	// before acceptPrepared. Prepared facts must not pin the former active SA.
	next := dataplaneChild(513)
	next.LocalSelectors, next.RemoteSelectors = f.child.LocalSelectors, f.child.RemoteSelectors
	if err := f.p.tunnel.data.install(f.p.generation, f.plan, outbound.job.sa.endpoint, next); err != nil {
		t.Fatal(err)
	}
	if err := f.p.tunnel.data.activate(next.InitiatorSPI); err != nil {
		t.Fatal(err)
	}
	if accepted, err := f.p.acceptPrepared(facts, outbound); accepted || err != nil {
		t.Fatal("old outbound survived active CHILD change", err)
	}
	if accepted, err := f.p.acceptPrepared(facts, inbound); !accepted || err != nil || len(f.device.written) != 1 {
		t.Fatal("old inbound lost valid CHILD overlap", err)
	}
}
