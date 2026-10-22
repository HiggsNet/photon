package photonwindows

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/photonclient/ike"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
	"github.com/HiggsNet/photon/pkg/routing"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
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

// Re-sign the root of this fixture without exposing the existing child signer.
// This permits authenticated parent-policy changes after warming the memo.
func packetFixtureRootSigner(t *testing.T, f *pipelineFixture) ed25519.PrivateKey {
	t.Helper()
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
	for _, delegation := range root.Delegations {
		if err := photoncrypto.SignDelegation(delegation, zone.RootZone, private); err != nil {
			t.Fatal(err)
		}
	}
	return private
}

func TestPacketSignatureMemoKeepsCurrentPolicy(t *testing.T) {
	t.Run("signed route withdrawal same revision", func(t *testing.T) {
		f := newPipelineFixture(t)
		f.learn(t)
		if !f.submitFromDevice(t, f.packet(true)) {
			t.Fatal("warm submit rejected")
		}
		completion := f.businessCompletion(t)
		key, _ := routing.NormalizeRouteAnnouncementKey("10.1.2.0/24")
		f.put("node-a.catofes.", key, routing.RecordTypeRouteAnnouncement, routing.RouteAnnouncementRecord{Version: 1, Prefix: "10.1.2.0/24", Active: false})
		if f.accept(t, completion) {
			t.Fatal("memo retained a withdrawn signed route")
		}
	})
	t.Run("signed permission removal", func(t *testing.T) {
		f := newPipelineFixture(t)
		private := packetFixtureRootSigner(t, f)
		f.learn(t)
		local := f.view.State.Network.Zones[f.config.ManagedZone]
		local.Authority.Keys[0].Capabilities = []zone.Capability{{Permissions: []zone.Permission{zone.PermDelegate, zone.PermAllocateIP}}}
		delegation := f.view.State.Network.Zones[zone.RootZone].Delegations[f.config.ManagedZone]
		delegation.Authority = *local.Authority
		if err := photoncrypto.SignDelegation(delegation, zone.RootZone, private); err != nil {
			t.Fatal(err)
		}
		if err := photoncrypto.VerifyChain(f.view.State.Network, f.config.ManagedZone, f.now); err != nil {
			t.Fatal("fixture must remain a valid signed chain", err)
		}
		if _, ok := f.p.prepare(f.config, f.view, f.plan, f.now); ok {
			t.Fatal("cached record math bypassed current Write permission")
		}
	})
	t.Run("transport key expiry same revision", func(t *testing.T) {
		f := newPipelineFixture(t)
		record := f.view.State.Network.Zones[f.config.ManagedZone].Records[ipsec.RecordKeyTransportKey]
		key, err := ipsec.ParseTransportKeyRecord(record)
		if err != nil {
			t.Fatal(err)
		}
		key.NotAfter = f.now.Add(time.Second).Unix()
		f.put(f.config.ManagedZone, record.Key, record.Type, key)
		f.p.tunnel.localAuthorization, err = localTransportAuthorization(f.config, f.view, f.now)
		if err != nil {
			t.Fatal(err)
		}
		f.learn(t)
		if _, ok := f.p.prepare(f.config, f.view, f.plan, f.now.Add(time.Second)); ok {
			t.Fatal("cached signature extended a transport key lifetime")
		}
	})
	t.Run("future signed identity collision", func(t *testing.T) {
		f := newPipelineFixture(t)
		private := packetFixtureRootSigner(t, f)
		value, err := json.Marshal(routing.BabelIdentityRecord{Version: 1, RouterIDs: []string{hex.EncodeToString(f.remoteID[:])}, ExpiresAt: f.now.Add(time.Hour).Unix()})
		if err != nil {
			t.Fatal(err)
		}
		record := &zone.Record{Zone: zone.RootZone, Key: routing.RecordKeyBabelIdentity, Type: routing.RecordTypeBabelIdentity, Value: value, Version: 1, Timestamp: f.now.Add(time.Second).Unix()}
		if err := photoncrypto.SignRecord(record, private); err != nil {
			t.Fatal(err)
		}
		f.view.State.Network.Zones[zone.RootZone].Records[record.Key] = record
		f.learn(t) // VerifyRecord warms the future record's valid signature too.
		facts, ok := f.p.prepare(f.config, f.view, f.plan, f.now.Add(time.Second))
		if !ok {
			t.Fatal("collision affects remote ID, not local attachment")
		}
		if f.p.authorize(facts, f.packet(true), true) {
			t.Fatal("cached math hid newly active Router ID conflict")
		}
	})
	t.Run("current child selectors", func(t *testing.T) {
		f := newPipelineFixture(t)
		f.learn(t)
		completion := f.inboundCompletion(t, f.packet(false))
		facts, ok := f.p.prepare(f.config, f.view, f.plan, f.now)
		if !ok {
			t.Fatal("warm authorization failed")
		}
		address := netip.MustParseAddr("10.8.0.1")
		completion.job.sa.local = []ike.TrafficSelector{{StartAddr: address, EndAddr: address, EndPort: 65535}}
		if accepted, err := f.p.acceptPrepared(facts, completion); accepted || err != nil {
			t.Fatal("memo bypassed current CHILD selectors", err)
		}
	})
}
