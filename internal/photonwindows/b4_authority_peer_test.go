package photonwindows

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corehost "github.com/HiggsNet/photon/pkg/core/host"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
	"github.com/HiggsNet/photon/pkg/routing"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

// b4AuthorityPeer is an isolated authority using the fixture's actual signing
// key and production transaction, gossip, and object-pull APIs. It never holds
// the running daemon's State, opens its Bolt file concurrently, or bypasses a
// route verdict. Its separate temporary DB is removed with the test directory.
type b4AuthorityPeer struct {
	state    *State
	driver   *corehost.GossipDriver
	socket   *packetSockets
	commands chan b4AuthorityCommand
	cancel   context.CancelFunc
	done     chan struct{}
	failures chan error
	target   zone.ZonePath
	gateways []zone.ZonePath
}
type b4AuthorityCommand struct {
	intents []corestate.LocalIntent
	result  chan error
}

func startB4AuthorityPeer(t *testing.T, ctx context.Context, config *Config) *b4AuthorityPeer {
	return startB4AuthorityPeerAt(t, ctx, config, "127.0.0.1:0")
}

func startB4AuthorityPeerAt(t *testing.T, ctx context.Context, config *Config, listen string) *b4AuthorityPeer {
	t.Helper()
	if len(config.Gateway.AllowedZones) == 0 {
		t.Fatal("authority fixture requires at least one gateway")
	}
	// Read and release the fixture DB before the real daemon takes its exclusive
	// lock. Only the common verified data is copied, not transport private state.
	original, err := corestate.OpenBoltStore(config.State.Path, 0600, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	candidate, revision, _, found, loadErr := original.LoadCommon()
	closeErr := original.Close()
	if loadErr != nil || closeErr != nil || !found || candidate == nil || candidate.Verified == nil {
		t.Fatal("read authority fixture", loadErr, closeErr)
	}
	gateway := config.Gateway.AllowedZones[0]
	candidate.Verified.ManagedZone = gateway
	candidate.Gossip = &corestate.GossipCheckpoint{}
	// Keep every signing credential inside the caller's unique run directory,
	// so the outer cross-host runner also removes it after a hard Go timeout.
	path := filepath.Join(filepath.Dir(config.State.Path), "authority.db")
	owned, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal("create owned authority fixture", err)
	}
	t.Cleanup(func() {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Error("remove authority fixture", err)
		}
	})
	if err := owned.Close(); err != nil {
		t.Fatal(err)
	}
	disk, err := corestate.OpenBoltStore(path, 0600, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	err = disk.CommitCommon(ctx, candidate, corestate.ChangeSet{VerifiedRevision: revision, NetworkChanged: true})
	closeErr = disk.Close()
	if err != nil || closeErr != nil {
		t.Fatal("persist isolated authority", err, closeErr)
	}
	source, err := OpenState(path, gateway, config.TrustedRootPublicKey, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	peerCtx, cancel := context.WithCancel(ctx)
	socket, err := openPacketSockets(peerCtx, listen)
	if err != nil {
		cancel()
		source.Close()
		t.Fatal(err)
	}
	driver := corehost.NewGossipDriver(nil, 0, source.Store(), corehost.GossipDriverConfig{PeerID: string(gateway), Limits: corestate.DefaultSyncLimits()})
	peer := &b4AuthorityPeer{state: source, driver: driver, socket: socket, commands: make(chan b4AuthorityCommand), cancel: cancel, done: make(chan struct{}), failures: make(chan error, 1), target: config.ManagedZone}
	peer.gateways = slices.Clone(config.Gateway.AllowedZones)
	transport, err := gossip.NewTransport(gossip.Config{PeerID: string(gateway)}, socket)
	if err == nil {
		err = driver.StartGossipObjectPullServer(peerCtx, gossipListener{socket}, 0, 0)
	}
	executor := corehost.NewGossipObjectPullExecutor(corehost.GossipObjectPullExecutorConfig{Client: objectPullClient{}, Discovery: func() corehost.GossipDiscoveryInput { return driver.GossipDiscoveryInput(nil) }})
	if err == nil {
		err = driver.StartGossipObjectPullWorkers(peerCtx, executor, 0, 0)
	}
	if err == nil {
		err = driver.RefreshGossipDiscovery(peerCtx, nil, time.Now(), transport)
	}
	if err == nil {
		err = driver.StartGossipTransport(peerCtx, transport, func(err error) {
			if peerCtx.Err() == nil {
				peer.recordError(err)
			}
		})
	}
	if err != nil {
		cancel()
		socket.Close()
		driver.Stop()
		source.Close()
		t.Fatal(err)
	}
	go func() {
		defer close(peer.done)
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for {
			var event corehost.Event
			select {
			case <-peerCtx.Done():
				return
			case command := <-peer.commands:
				view := source.Store().ReadView()
				_, err := source.Store().ApplyLocalIntentsAtRevision(peerCtx, command.intents, time.Now(), view.Revision)
				if err == nil {
					_, err = driver.SyncGossipPeers(peerCtx, time.Now(), nil, true)
				}
				command.result <- err
				continue
			case event = <-driver.Events():
			case event = <-driver.Completions():
			case event = <-driver.Continuations():
			case <-ticker.C:
				if err := driver.RefreshGossipDiscovery(peerCtx, nil, time.Now(), transport); err != nil && peerCtx.Err() == nil {
					peer.recordError(err)
				}
				if _, err := driver.SyncGossipPeers(peerCtx, time.Now(), nil, false); err != nil && peerCtx.Err() == nil {
					peer.recordError(err)
				}
				continue
			}
			if _, err := driver.HandleGossipHostEvent(peerCtx, event, time.Now(), nil); err != nil && !errors.Is(err, corehost.ErrGossipSessionNotFound) && peerCtx.Err() == nil {
				peer.recordError(err)
			}
		}
	}()
	t.Cleanup(func() {
		cancel()
		socket.Close()
		<-peer.done
		driver.Stop()
		if err := source.Close(); err != nil {
			t.Error("authority cleanup", err)
		}
	})
	config.Gateway.BootstrapHints = []BootstrapHint{{Peer: gateway, Address: socket.LocalAddr().String()}}
	return peer
}
func (p *b4AuthorityPeer) recordError(err error) {
	select {
	case p.failures <- err:
	default:
	}
}

func (p *b4AuthorityPeer) setHostAssignments(t *testing.T, ctx context.Context, prefixes []string, active bool) {
	t.Helper()
	var intents []corestate.LocalIntent
	for _, prefix := range prefixes {
		if active {
			intents = append(intents, corestate.PutIPAMAssignmentIntent{Zone: zone.RootZone, Prefix: prefix, AssignedTo: p.target})
		} else {
			intents = append(intents, corestate.RevokeIPAMAssignmentIntent{Zone: zone.RootZone, Prefix: prefix, AssignedTo: p.target})
		}
	}
	p.applyIntents(t, ctx, intents)
}

func (p *b4AuthorityPeer) applyIntents(t *testing.T, ctx context.Context, intents []corestate.LocalIntent) {
	t.Helper()
	result := make(chan error, 1)
	select {
	case p.commands <- b4AuthorityCommand{intents, result}:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatal("signed authority transaction", err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func (p *b4AuthorityPeer) setGatewayEnabled(t *testing.T, ctx context.Context, gateway zone.ZonePath, enabled bool) {
	t.Helper()
	if !slices.Contains(p.gateways, gateway) {
		t.Fatal("gateway is outside authority fixture")
	}
	profile, err := ipsec.ParseProfileRecord(p.state.Store().ReadView().State.Network.Zones[gateway].Records[ipsec.RecordKeyProfile])
	if err != nil {
		t.Fatal(err)
	}
	profile.Enabled = enabled
	value, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	p.applyIntents(t, ctx, []corestate.LocalIntent{corestate.PutProtocolRecordIntent{Kind: corestate.ProtocolRecordIPsec, Zone: gateway, Key: ipsec.RecordKeyProfile, Type: ipsec.RecordTypeProfile, Value: value}})
}

func (p *b4AuthorityPeer) waitGatewayEnabled(t *testing.T, ctx context.Context, gateway zone.ZonePath, enabled bool) {
	t.Helper()
	profile, err := ipsec.ParseProfileRecord(p.state.Store().ReadView().State.Network.Zones[gateway].Records[ipsec.RecordKeyProfile])
	if err != nil || profile.Enabled != enabled {
		t.Fatal("expected signed gateway profile is absent", err)
	}
	p.waitSignedRecords(t, ctx, gateway, []string{ipsec.RecordKeyProfile})
}

func (p *b4AuthorityPeer) waitAssignments(t *testing.T, ctx context.Context, prefixes []string, active bool) {
	t.Helper()
	root := p.state.Store().ReadView().State.Network.Zones[zone.RootZone]
	keys := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		key, err := routing.NormalizeIPAMAssignmentKey(prefix)
		if err != nil {
			t.Fatal(err)
		}
		value, err := routing.ParseIPAMAssignmentRecord(root.Records[key])
		if err != nil || value.Active != active || value.AssignedTo != p.target {
			t.Fatal("expected signed host assignment is absent", err)
		}
		keys = append(keys, key)
	}
	p.waitSignedRecords(t, ctx, zone.RootZone, keys)
}

// waitSignedRecords reads the real daemon's object-pull endpoint, learned by the
// production discovery checkpoint. Matching signature, version and value hash
// proves its running verified store accepted our signed transition.
func (p *b4AuthorityPeer) waitSignedRecords(t *testing.T, parent context.Context, path zone.ZonePath, keys []string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	expectedZone := p.state.Store().ReadView().State.Network.Zones[path]
	var lastError error
	for {
		select {
		case err := <-p.failures:
			// The real daemon changes its shared socket during the rebind
			// phase. Production discovery retries an old endpoint naturally;
			// acceptance is the signed snapshot from the new live endpoint.
			lastError = err
		default:
		}
		endpoint := corehost.ResolveGossipObjectPullAddress(p.driver.GossipDiscoveryInput(nil), string(p.target), time.Now())
		if endpoint != "" {
			response, err := (objectPullClient{}).Exchange(ctx, endpoint, &gossip.ObjectPullRequest{Type: gossip.ObjectPullZone, Zone: path})
			if err == nil && response.OK && response.Snapshot != nil && response.Snapshot.Zone == path {
				matched := true
				for _, key := range keys {
					record := response.Snapshot.Records[key]
					expected := expectedZone.Records[key]
					if record == nil || expected == nil || record.Zone != path || record.Key != key || record.Type != expected.Type || record.Version != expected.Version || !bytes.Equal(record.ValueHash, expected.ValueHash) || photoncrypto.VerifyRecord(record, expectedZone.Authority, time.Now()) != nil {
						matched = false
						break
					}
				}
				if matched {
					return
				}
			}
		}
		select {
		case <-ctx.Done():
			t.Fatal(fmt.Sprintf("running daemon did not converge signed records in %s: %v", path, lastError))
		case <-ticker.C:
		}
	}
}

func TestB4AuthorityPeerChangesRunningDaemonState(t *testing.T) {
	network, _, private := signedNetwork(t)
	root := private.Public().(ed25519.PublicKey)
	network.Zones[zone.RootZone].Authority = photoncrypto.ConfiguredRootAuthority(root)
	if err := photoncrypto.SignDelegation(network.Zones[zone.RootZone].Delegations["catofes."], zone.RootZone, private); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Truncate(time.Second)
	put := func(path zone.ZonePath, key, kind string, value any) {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		record := &zone.Record{Zone: path, Key: key, Type: kind, Value: encoded, Version: 1, Timestamp: now.Unix()}
		if err := photoncrypto.SignRecord(record, private); err != nil {
			t.Fatal(err)
		}
		network.Zones[path].Records[key] = record
	}
	backup := zone.ZonePath("node-b.catofes.")
	backupAuthority := *network.Zones["node-a.catofes."].Authority
	backupAuthority.Zone = backup
	delegation := &zone.Delegation{ZoneName: backup, Authority: backupAuthority}
	if err := photoncrypto.SignDelegation(delegation, "catofes.", private); err != nil {
		t.Fatal(err)
	}
	network.Zones["catofes."].Delegations[backup] = delegation
	network.Zones[backup] = zone.NewZoneState(backup, &backupAuthority)
	config := &Config{ManagedZone: "node-a.catofes.", TrustedRootPublicKey: root, GossipListen: "127.0.0.1:0", State: StateConfig{Path: filepath.Join(t.TempDir(), "daemon.db")}, Gateway: GatewayConfig{AllowedZones: []zone.ZonePath{"catofes.", backup}}}
	_, transportKey, err := ipsec.GenerateTransportKeyRecord(ipsec.AlgorithmEd25519, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for _, gateway := range config.Gateway.AllowedZones {
		put(gateway, ipsec.RecordKeyProfile, ipsec.RecordTypeProfile, ipsec.ProfileRecord{Version: 1, Enabled: true, Provider: ipsec.ProviderStrongSwan, IKEIdentity: string(gateway), TransportKeyFingerprint: transportKey.Fingerprint, Role: ipsec.RoleIn, AddressFamilies: []string{ipsec.FamilyIPv4}, PathModes: []string{ipsec.PathModeFamilyRedundant}})
	}
	for _, prefix := range []string{"198.18.253.0/24", "fd00:7068:b4::/64"} {
		key, _ := routing.NormalizeIPAMPoolKey(prefix)
		put(zone.RootZone, key, routing.RecordTypeIPAMPool, routing.IPAMPoolRecord{Version: 1, Prefix: prefix, DelegatedTo: zone.RootZone, Active: true})
	}
	prefixes := []string{"198.18.253.2/32", "fd00:7068:b4::2/128"}
	for _, prefix := range prefixes {
		key, _ := routing.NormalizeIPAMAssignmentKey(prefix)
		put(zone.RootZone, key, routing.RecordTypeIPAMAssignment, routing.IPAMAssignmentRecord{Version: 1, Prefix: prefix, AssignedTo: config.ManagedZone, Active: true})
	}
	disk, err := corestate.OpenBoltStore(config.State.Path, 0600, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	err = disk.CommitCommon(t.Context(), &corestate.CommitCandidate{Verified: &corestate.VerifiedState{ManagedZone: config.ManagedZone, Network: network, TrustedRootPublicKey: root, IdentityPrivateKey: private}, Gossip: &corestate.GossipCheckpoint{}}, corestate.ChangeSet{VerifiedRevision: 1, NetworkChanged: true})
	closeErr := disk.Close()
	if err != nil || closeErr != nil {
		t.Fatal(err, closeErr)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Second)
	defer cancel()
	authority := startB4AuthorityPeer(t, ctx, config)
	daemon := NewDaemon(config, slog.New(slog.NewTextHandler(io.Discard, nil)))
	done := make(chan error, 1)
	go func() { done <- daemon.Run(ctx) }()
	defer func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(5 * time.Second):
			t.Error("daemon did not stop")
		}
	}()
	authority.waitAssignments(t, ctx, prefixes, true)
	authority.setHostAssignments(t, ctx, prefixes, false)
	authority.waitAssignments(t, ctx, prefixes, false)
	authority.setHostAssignments(t, ctx, prefixes, true)
	authority.waitAssignments(t, ctx, prefixes, true)
	for _, gateway := range config.Gateway.AllowedZones {
		before, err := ipsec.ParseProfileRecord(authority.state.Store().ReadView().State.Network.Zones[gateway].Records[ipsec.RecordKeyProfile])
		if err != nil {
			t.Fatal(err)
		}
		authority.setGatewayEnabled(t, ctx, gateway, false)
		authority.waitGatewayEnabled(t, ctx, gateway, false)
		before.Enabled = false
		want, _ := json.Marshal(before)
		if !bytes.Equal(want, authority.state.Store().ReadView().State.Network.Zones[gateway].Records[ipsec.RecordKeyProfile].Value) {
			t.Fatal("toggle changed another gateway profile field")
		}
		authority.setGatewayEnabled(t, ctx, gateway, true)
		authority.waitGatewayEnabled(t, ctx, gateway, true)
	}
}
