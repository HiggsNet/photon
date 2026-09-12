package main

import (
	"crypto/ed25519"
	"net"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/photonlinux"
	"github.com/HiggsNet/photon/pkg/core/gossip"
	corehost "github.com/HiggsNet/photon/pkg/core/host"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

func newTestObserverServer() *observerServer {
	store := corestate.NewStoreWithCheckpoint(&corestate.VerifiedState{}, &corestate.GossipCheckpoint{}, nil)
	d := &Daemon{
		State: newState(nil, store, &photonlinux.LinuxState{}),
		App: &AppContext{Config: &appConfig{
			PeerID: "test-node", ListenAddr: "127.0.0.1:33434",
		}},
	}
	d.gossipDriver = corehost.NewGossipDriver(corehost.NewClock(nil), corehost.DefaultEventBuffer, store, gossipDriverConfig(d.App.Config, store.ReadView().State, nil))
	cfg := defaultObserverConfig()
	cfg.Enabled = true
	return newObserverServer(d, cfg)
}

func updateTestObserverOwners(srv *observerServer, fn func(*corestate.VerifiedState, *corestate.GossipCheckpoint, *photonlinux.LinuxState)) {
	if srv == nil || srv.daemon == nil || srv.daemon.State == nil || fn == nil {
		return
	}
	common := srv.daemon.State.Common.ReadView()
	runtime := srv.daemon.State.ReadLinux()
	fn(common.State, common.Gossip, runtime)
	store := corestate.NewStoreWithCheckpoint(common.State, common.Gossip, nil)
	srv.daemon.State = newState(nil, store, runtime)
	srv.daemon.gossipDriver = corehost.NewGossipDriver(corehost.NewClock(nil), corehost.DefaultEventBuffer, store, gossipDriverConfig(srv.daemon.App.Config, store.ReadView().State, nil))
}

func addObserverEndpointZone(t *testing.T, ns *zone.NetworkState, path zone.ZonePath, ip string, port uint16, now time.Time) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(%s): %v", path, err)
	}
	authority := &zone.ZoneAuthority{Zone: path, Epoch: 1, Threshold: 1, Keys: []zone.AuthorizedKey{{Key: pub}}}
	zs := zone.NewZoneState(path, authority)
	value := endpointRecordBytes([]gossip.LocalEndpoint{{
		IP:       net.ParseIP(ip),
		Port:     port,
		Scope:    "loopback",
		Priority: 100,
		Source:   gossip.SourceAdvertise,
	}}, now)
	record := &zone.Record{
		Zone:      path,
		Key:       gossip.EndpointRecordKeyUDP,
		Type:      "sync.endpoint",
		Value:     value,
		Version:   1,
		Timestamp: now.Unix(),
	}
	if err := photoncrypto.SignRecord(record, priv); err != nil {
		t.Fatalf("SignRecord(%s): %v", path, err)
	}
	zs.Records[gossip.EndpointRecordKeyUDP] = record
	ns.Zones[path] = zs
}
