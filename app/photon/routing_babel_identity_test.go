package main

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/photonlinux"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
	"github.com/HiggsNet/photon/pkg/routing"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func babelPublisherFixture(t *testing.T) (*Daemon, *fakeBirdClient, *time.Time) {
	t.Helper()
	verified, checkpoint, runtime, base := buildTestRoutingOwners(t)
	now := time.Unix(4000, 0)
	config := defaultAppConfig()
	config.DataDir = t.TempDir()
	config.PublishEndpoints = false
	config.Netns = photonlinux.NetNSConfig{Names: map[string]ipsec.NetNSSpec{"mesh": {Kind: ipsec.NetNSName, Name: "mesh", Create: true}}}
	var err error
	config.Routing, err = photonlinux.ParseRoutingConfig([]photonlinux.RoutingInstanceYAML{{ID: "mesh", NetNS: "mesh", Enabled: boolPtr(true), Mode: ipsec.RoutingModeExternal}}, config.Netns, config.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	d := newTestDaemonFromOwners(&testApp{Config: config, Clock: func() time.Time { return now }}, verified, checkpoint, runtime, base, time.Second)
	d.gossipDriver.Stop()
	client := &fakeBirdClient{raw: map[string]string{}}
	installTestBirdDrivers(d, &fakeBirdProcessManager{running: true}, func(string, time.Duration) birdClient { return client })
	return d, client, &now
}
func publisherEntry(id string) string {
	return fmt.Sprintf("photon_babel_mesh:\nPrefix Router ID Metric Seqno Routes Sources\n10.0.0.0/24 %s 0 1 0 0\n", id)
}
func publishedBabel(t *testing.T, d *Daemon, now time.Time) (*zone.Record, *routing.BabelIdentityRecord) {
	t.Helper()
	v := d.State.Common.ReadView().State
	record := v.Network.Zones[v.ManagedZone].Records[routing.RecordKeyBabelIdentity]
	parsed, err := routing.ParseBabelIdentityRecord(record, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := photoncrypto.VerifyRecord(record, v.Network.Zones[v.ManagedZone].Authority, now); err != nil {
		t.Fatal("identity signature", err)
	}
	return record, parsed
}

func TestBabelIdentityPublisherSignsRenewsRestartsAndWithdraws(t *testing.T) {
	d, client, now := babelPublisherFixture(t)
	const command = "show babel entries photon_babel_mesh"
	client.raw[command] = publisherEntry("12:34:56:78:0a:00:00:01")
	if err := d.publishRoutingBabelIdentity(context.Background()); err != nil {
		t.Fatal(err)
	}
	first, p := publishedBabel(t, d, *now)
	if len(p.RouterIDs) != 1 || p.RouterIDs[0] != "123456780a000001" {
		t.Fatal(p)
	}
	if err := d.publishRoutingBabelIdentity(context.Background()); err != nil {
		t.Fatal(err)
	}
	same, _ := publishedBabel(t, d, *now)
	if same.Version != first.Version {
		t.Fatal("steady state republished")
	}
	*now = now.Add(babelIdentityLease / 2)
	if err := d.publishRoutingBabelIdentity(context.Background()); err != nil {
		t.Fatal(err)
	}
	renewed, _ := publishedBabel(t, d, *now)
	if renewed.Version != first.Version+1 {
		t.Fatal("lease was not renewed")
	}
	client.raw[command] = publisherEntry("fe:dc:ba:98:0a:00:00:01")
	if err := d.publishRoutingBabelIdentity(context.Background()); err != nil {
		t.Fatal(err)
	}
	restarted, p := publishedBabel(t, d, *now)
	if restarted.Version != renewed.Version+1 || len(p.RouterIDs) != 1 || p.RouterIDs[0] != "fedcba980a000001" {
		t.Fatal("old randomized ID survived", p)
	}
	client.rawErr = errors.New("BIRD stopped")
	if err := d.publishRoutingBabelIdentity(context.Background()); err != nil {
		t.Fatal(err)
	}
	withdrawn, p := publishedBabel(t, d, *now)
	if len(p.RouterIDs) != 0 {
		t.Fatal("missing evidence did not withdraw", p)
	}
	if err := d.publishRoutingBabelIdentity(context.Background()); err != nil {
		t.Fatal(err)
	}
	same, _ = publishedBabel(t, d, *now)
	if same.Version != withdrawn.Version {
		t.Fatal("empty binding republished")
	}
	*now = now.Add(babelIdentityLease)
	if _, err := routing.ParseBabelIdentityRecord(restarted, *now); err == nil {
		t.Fatal("old lease remains current")
	}
}

func TestBabelIdentityPlannerFailClosedAndRevisionChecked(t *testing.T) {
	d, client, now := babelPublisherFixture(t)
	command := "show babel entries photon_babel_mesh"
	view := d.State.Common.ReadView()
	client.raw[command] = publisherEntry("12:34:56:78:0a:00:00:01")
	intent, err := d.routingBabelIdentityProtocolIntent(context.Background(), view.State, *now)
	if err != nil || intent == nil {
		t.Fatal(intent, err)
	}
	if _, err := advanceTestVerifiedRevision(d.State.Common, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := commitLocalProtocols(context.Background(), d.State, uint64(view.Revision), []corestate.LocalIntent{*intent}, nil, *now); !errors.Is(err, errStateRevisionStale) {
		t.Fatal("stale observation committed", err)
	}
	for _, output := range []string{
		"", "other_protocol:\n10.0.0.0/24 12:34:56:78:0a:00:00:01 0 1 0 0\n",
		"photon_babel_mesh:\n10.0.0.0/24 12:34:56:78:0a:00:00:01 100 1 1 1\n",
		"photon_babel_mesh:\n10.1.0.0/24 12:34:56:78:0a:00:00:01 0 1 0 0\n",
	} {
		client.raw[command] = output
		if intent, err := d.routingBabelIdentityProtocolIntent(context.Background(), d.State.Common.ReadView().State, *now); err != nil || intent != nil {
			t.Fatal("published without local proof", intent, err)
		}
	}
}

func TestBabelIdentityStartupAndDisabledInstanceWithdraw(t *testing.T) {
	d, client, now := babelPublisherFixture(t)
	client.raw["show babel entries photon_babel_mesh"] = publisherEntry("12:34:56:78:0a:00:00:01")
	// Exercise the real startup/timer batch owner, not only the routing trigger.
	if _, err := d.publishLocalProtocols(); err != nil {
		t.Fatal(err)
	}
	publishedBabel(t, d, *now)
	d.Config.Routing.Instances[0].Enabled = false
	if _, err := d.publishLocalProtocols(); err != nil {
		t.Fatal(err)
	}
	_, value := publishedBabel(t, d, *now)
	if len(value.RouterIDs) != 0 {
		t.Fatal("disabled instance retains binding", value)
	}
}
