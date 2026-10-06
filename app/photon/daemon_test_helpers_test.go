package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net"
	"testing"
	"time"

	photonlinux "github.com/HiggsNet/photon/internal/photonlinux"
	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
	"github.com/HiggsNet/photon/pkg/firewall"
	"github.com/HiggsNet/photon/pkg/health"
	"github.com/HiggsNet/photon/pkg/routing/bird"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

type birdClient = photonlinux.BirdClient

type testLinuxDrivers struct {
	ipsec             ipsec.IPsecDriver
	xfrm              ipsec.XFRMDriver
	firewall          firewall.FirewallDriver
	veth              bird.VethManager
	upstreamRoutes    photonlinux.UpstreamRouteManager
	birdProcess       bird.ProcessManager
	birdProcesses     map[string]bird.ProcessManager
	birdClientFactory func(string, time.Duration) photonlinux.BirdClient
	healthProber      health.Prober
	kernelRouteRunner func(context.Context, string, ...string) ([]byte, error)
}

// newTestDaemonFromOwners is the normal fixture for tests of current
// daemon behavior. New tests must construct the common and Linux owners
// explicitly instead of passing the retired aggregate stateFile shape.
func newTestDaemonFromOwners(
	rt *testApp,
	verified *corestate.VerifiedState,
	checkpoint *corestate.GossipCheckpoint,
	runtime *photonlinux.LinuxState,
	config *appConfig,
	interval time.Duration,
) *Daemon {
	if rt != nil && rt.Config == nil {
		rt.Config = config
		if rt.Config == nil {
			rt.Config = defaultAppConfig()
		}
	} else if rt != nil && config != nil && rt.Config != config {
		rt.Config.PeerID = config.PeerID
		rt.Config.ListenAddr = config.ListenAddr
		rt.Config.Bootstrap = append([]syncConfigPeer(nil), config.Bootstrap...)
		rt.Config.MaxMessageBytes = config.MaxMessageBytes
		rt.Config.MaxSyncZones = config.MaxSyncZones
		rt.Config.MaxSyncRecords = config.MaxSyncRecords
	}
	if verified == nil {
		verified = &corestate.VerifiedState{}
	}
	if rt != nil && rt.Config != nil && len(rt.Config.TrustedRootPublicKey) > 0 {
		copyVerified := *verified
		copyVerified.TrustedRootPublicKey = append(ed25519.PublicKey(nil), rt.Config.TrustedRootPublicKey...)
		verified = &copyVerified
	}
	common := corestate.NewStoreWithCheckpoint(verified, checkpoint, nil, nil)
	service := newDaemon(rt.Config, newState(nil, common, runtime), interval, rt.Now)
	peerIDs := []string{"peer-a", "root-admin", "bootstrap.catofes."}
	if verified.Network != nil {
		for path := range verified.Network.Zones {
			if path.Valid() && path != verified.ManagedZone {
				peerIDs = append(peerIDs, path.String())
			}
		}
	}
	if config != nil {
		for _, peer := range config.Bootstrap {
			peerIDs = append(peerIDs, peer.ID)
		}
	}
	known := make(map[string]*net.UDPAddr, len(peerIDs))
	for _, peerID := range peerIDs {
		if peerID != "" {
			known[peerID] = &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 33435}
		}
	}
	localPeerID := "test-local.catofes."
	if config != nil && config.PeerID != "" {
		localPeerID = config.PeerID
	}
	transport, err := gossip.NewTransport(gossip.Config{
		PeerID: localPeerID, KnownPeers: known, MaxMessageBytes: gossip.DefaultDatagramBudget,
	}, &testGossipDatagram{addr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 33434}})
	if err != nil {
		panic(err)
	}
	if err := service.gossipDriver.BindGossipTransport(transport); err != nil {
		panic(err)
	}
	dryRun := &ipsec.DryRunDriver{}
	installTestIPsecDrivers(service, dryRun, dryRun)
	return service
}

func installTestIPsecDrivers(service *Daemon, ipsecDriver ipsec.IPsecDriver, xfrmDriver ipsec.XFRMDriver) {
	installTestLinuxDrivers(service, testLinuxDrivers{ipsec: ipsecDriver, xfrm: xfrmDriver})
}

func installTestFirewallDriver(service *Daemon, firewallDriver firewall.FirewallDriver) {
	dryRun := &ipsec.DryRunDriver{}
	installTestLinuxDrivers(service, testLinuxDrivers{ipsec: dryRun, xfrm: dryRun, firewall: firewallDriver})
}

func installTestBirdDrivers(service *Daemon, process bird.ProcessManager, clientFactory func(string, time.Duration) photonlinux.BirdClient) {
	dryRun := &ipsec.DryRunDriver{}
	installTestLinuxDrivers(service, testLinuxDrivers{ipsec: dryRun, xfrm: dryRun, birdProcess: process, birdClientFactory: clientFactory})
}

func installTestLinuxDrivers(service *Daemon, drivers testLinuxDrivers) {
	if service == nil {
		return
	}
	if drivers.ipsec == nil {
		drivers.ipsec = &ipsec.DryRunDriver{}
	}
	if drivers.xfrm == nil {
		drivers.xfrm = &ipsec.DryRunDriver{}
	}
	if err := service.installLinuxDriver(newTestLinuxDriverWithOptions(photonlinux.LinuxDriverOptions{
		IPsecDriver:       drivers.ipsec,
		XFRMDriver:        drivers.xfrm,
		FirewallDriver:    drivers.firewall,
		VethManager:       drivers.veth,
		UpstreamRoutes:    drivers.upstreamRoutes,
		BirdProcess:       drivers.birdProcess,
		BirdProcesses:     drivers.birdProcesses,
		BirdClientFactory: drivers.birdClientFactory,
		HealthProber:      drivers.healthProber,
		KernelRouteRunner: drivers.kernelRouteRunner,
	})); err != nil {
		panic(err)
	}
}

func newTestLinuxDriver(ipsecDriver ipsec.IPsecDriver, xfrmDriver ipsec.XFRMDriver) *photonlinux.LinuxDriver {
	return newTestLinuxDriverWithOptions(photonlinux.LinuxDriverOptions{
		IPsecDriver: ipsecDriver,
		XFRMDriver:  xfrmDriver,
	})
}

func newTestLinuxDriverWithOptions(options photonlinux.LinuxDriverOptions) *photonlinux.LinuxDriver {
	driver, err := photonlinux.NewLinuxDriver(options)
	if err != nil {
		panic(err)
	}
	return driver
}

func setTestIPsecObservation(d *Daemon, links map[string]ipsec.LinkInstance, reconcile *ipsecObservationSummary) {
	if d == nil {
		return
	}
	d.linuxObservation.replaceIPsec(links, reconcile)
}

func readTestIPsecObservation(d *Daemon) (map[string]ipsec.LinkInstance, *ipsecObservationSummary) {
	if d == nil {
		return nil, nil
	}
	return d.linuxObservation.ipsecSnapshot()
}

func buildSignedRecordAt(network *zone.NetworkState, signer ed25519.PrivateKey, path zone.ZonePath, key string, value []byte, recordType string, now time.Time) (*zone.Record, error) {
	if network == nil {
		return nil, fmt.Errorf("network is nil")
	}
	configureValidation(network)
	zs := network.Zones[path]
	if zs == nil {
		return nil, fmt.Errorf("%w: %s", zone.ErrZoneNotFound, path)
	}
	current := zs.Records[key]
	record := &zone.Record{Zone: path, Key: key, Type: recordType, Value: value, Version: 1, Timestamp: now.Unix()}
	if current != nil {
		record.Version = current.Version + 1
		record.PrevHash = photoncrypto.RecordHash(current)
	}
	if len(signer) != ed25519.PrivateKeySize || zs.Authority == nil || !authorityHasPrivateKey(zs.Authority, signer) {
		return nil, fmt.Errorf("no local signing key for zone %s", path)
	}
	if err := photoncrypto.SignRecord(record, signer); err != nil {
		return nil, err
	}
	return record, nil
}

func authorityHasPrivateKey(authority *zone.ZoneAuthority, priv ed25519.PrivateKey) bool {
	if authority == nil || len(priv) != ed25519.PrivateKeySize {
		return false
	}
	return authority.HasPublicKey(priv.Public().(ed25519.PublicKey))
}

func advanceTestVerifiedRevision(store *corestate.Store, now time.Time) (uint64, error) {
	view := store.ReadView()
	if view.State == nil {
		return 0, fmt.Errorf("state is nil")
	}
	path := view.State.ManagedZone
	for candidate, zs := range view.State.Network.Zones {
		if zs != nil && authorityHasPrivateKey(zs.Authority, view.State.IdentityPrivateKey) {
			path = candidate
			break
		}
	}
	result, err := store.ApplyLocalIntent(context.Background(), corestate.PutRecordIntent{
		Zone: path, Key: fmt.Sprintf("tests/revision/%d", now.UnixNano()), Type: "application/vnd.photon.test-revision.v1", Value: []byte("1"),
	}, now)
	return uint64(result.Changes.VerifiedRevision), err
}

func endpointRecordBytes(endpoints []gossip.LocalEndpoint, now time.Time) []byte {
	record := gossip.LocalEndpointsToRecordWithPolicy(endpoints, nil, now, gossip.DefaultEndpointTTL, gossip.DefaultEndpointGrace)
	value, err := json.Marshal(record)
	if err != nil {
		panic(err)
	}
	return value
}

func buildTestABVerifiedStates(t *testing.T) (*corestate.VerifiedState, *appConfig, *corestate.VerifiedState, *appConfig) {
	t.Helper()
	rootPub, rootPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(root): %v", err)
	}
	catofesPub, catofesPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(catofes): %v", err)
	}
	nodeAPub, nodeAPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(node-a): %v", err)
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
	nodeAAuthority := testWriteAuthority("node-a.catofes.", nodeAPub)
	nodeBAuthority := testWriteAuthority("node-b.catofes.", nodeBPub)
	catofesDelegation := testSignedDelegation(t, "catofes.", *catofesAuthority, zone.RootZone, rootPriv)
	nodeADelegation := testSignedDelegation(t, "node-a.catofes.", *nodeAAuthority, "catofes.", catofesPriv)
	nodeBDelegation := testSignedDelegation(t, "node-b.catofes.", *nodeBAuthority, "catofes.", catofesPriv)

	buildNetwork := func(managed zone.ZonePath) *zone.NetworkState {
		ns := zone.NewNetworkState()
		ns.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, rootAuthority)
		ns.Zones["catofes."] = zone.NewZoneState("catofes.", catofesAuthority)
		ns.Zones[zone.RootZone].Delegations["catofes."] = catofesDelegation
		ns.Zones["catofes."].Delegations["node-a.catofes."] = nodeADelegation
		ns.Zones["catofes."].Delegations["node-b.catofes."] = nodeBDelegation
		switch managed {
		case "node-a.catofes.":
			ns.Zones["node-a.catofes."] = zone.NewZoneState("node-a.catofes.", nodeAAuthority)
		case "node-b.catofes.":
			ns.Zones["node-b.catofes."] = zone.NewZoneState("node-b.catofes.", nodeBAuthority)
		default:
			t.Fatalf("unexpected managed zone %s", managed)
		}
		configureValidation(ns)
		for _, path := range []zone.ZonePath{"catofes.", managed} {
			if err := photoncrypto.VerifyChain(ns, path, time.Unix(123, 0)); err != nil {
				t.Fatalf("VerifyChain(%s): %v", path, err)
			}
		}
		return ns
	}

	verifiedA := &corestate.VerifiedState{
		ManagedZone:        "node-a.catofes.",
		Network:            buildNetwork("node-a.catofes."),
		IdentityPrivateKey: nodeAPriv,
	}
	verifiedB := &corestate.VerifiedState{
		ManagedZone:        "node-b.catofes.",
		Network:            buildNetwork("node-b.catofes."),
		IdentityPrivateKey: nodeBPriv,
	}
	configA := defaultAppConfig()
	configA.PeerID, configA.ListenAddr = "node-a.catofes.", "127.0.0.1:0"
	configB := defaultAppConfig()
	configB.PeerID, configB.ListenAddr = "node-b.catofes.", "127.0.0.1:0"
	return verifiedA, configA, verifiedB, configB
}

func testWriteAuthority(path zone.ZonePath, pub ed25519.PublicKey) *zone.ZoneAuthority {
	return &zone.ZoneAuthority{
		Zone:      path,
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: pub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermWrite},
			}},
		}},
	}
}

func testSignedDelegation(t *testing.T, path zone.ZonePath, authority zone.ZoneAuthority, parent zone.ZonePath, priv ed25519.PrivateKey) *zone.Delegation {
	t.Helper()
	delegation := &zone.Delegation{
		ZoneName:  path,
		Scope:     zone.DelegationScopeDirectChild,
		Authority: authority,
	}
	if err := photoncrypto.SignDelegation(delegation, parent, priv); err != nil {
		t.Fatalf("SignDelegation(%s): %v", path, err)
	}
	return delegation
}

func pumpDaemonEvents(ctx context.Context, service *Daemon) {
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			service.processEvents(ctx, nil)
		}
	}
}

func controlRequestViaPipe(t *testing.T, service *Daemon, request controlRequest) controlResponse {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	_ = server.SetDeadline(time.Now().Add(5 * time.Second))
	done := make(chan struct{})
	go func() {
		defer close(done)
		service.handleControlConn(context.Background(), server)
	}()
	if err := json.NewEncoder(client).Encode(request); err != nil {
		t.Fatalf("Encode(request): %v", err)
	}
	var response controlResponse
	if err := json.NewDecoder(client).Decode(&response); err != nil {
		t.Fatalf("Decode(response): %v", err)
	}
	<-done
	return response
}

func controlViewRequestViaPipe[T any](t *testing.T, service *Daemon, request controlRequest) controlViewResponse[T] {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	_ = server.SetDeadline(time.Now().Add(5 * time.Second))
	done := make(chan struct{})
	go func() {
		defer close(done)
		service.handleControlConn(context.Background(), server)
	}()
	if err := json.NewEncoder(client).Encode(request); err != nil {
		t.Fatalf("Encode(request): %v", err)
	}
	var response controlViewResponse[T]
	if err := json.NewDecoder(client).Decode(&response); err != nil {
		t.Fatalf("Decode(response): %v", err)
	}
	<-done
	return response
}
