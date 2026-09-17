package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	photonstate "github.com/HiggsNet/photon/internal/state"

	"github.com/HiggsNet/photon/internal/inspect"
	"github.com/HiggsNet/photon/internal/photonlinux"
	pingdebug "github.com/HiggsNet/photon/internal/ping"
	"github.com/HiggsNet/photon/pkg/core/gossip"
	corehost "github.com/HiggsNet/photon/pkg/core/host"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/health"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
	bolt "go.etcd.io/bbolt"
)

type controlPingProber struct {
	target health.ProbeTarget
	config health.ProbeConfig
}

type blockingControlPingProber struct {
	started chan context.Context
	stopped chan error
}

func (p *blockingControlPingProber) Probe(ctx context.Context, target health.ProbeTarget, _ health.ProbeConfig) health.ProbeResult {
	p.started <- ctx
	<-ctx.Done()
	p.stopped <- ctx.Err()
	return health.ProbeResult{InstanceID: target.InstanceID, Err: ctx.Err()}
}
func (*blockingControlPingProber) Type() string { return health.ProbeTypeICMP }

func TestDaemonControlPingCancellation(t *testing.T) {
	for _, mode := range []string{"client_cancel", "disconnect", "daemon_cancel"} {
		t.Run(mode, func(t *testing.T) {
			verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
			service := newTestDaemonFromOwners(&AppContext{Config: defaultAppConfig()}, verified, checkpoint, runtime, config, time.Second)
			prober := &blockingControlPingProber{started: make(chan context.Context, 1), stopped: make(chan error, 1)}
			dryRun := &ipsec.DryRunDriver{}
			installTestLinuxDrivers(service, testLinuxDrivers{ipsec: dryRun, xfrm: dryRun, healthProber: prober})
			setTestIPsecObservation(service, map[string]ipsec.LinkInstance{"link-b": {ActualState: "up"}}, &ipsecObservationSummary{Desired: []photonstate.DesiredLinkObservation{{InstanceID: "link-b", PeerZone: "node-b.catofes.", LocalTunnelAddr: "10.0.0.1", PeerTunnelAddr: "10.0.0.2"}}})
			daemonCtx, cancelDaemon := context.WithCancel(t.Context())
			defer cancelDaemon()
			service.ControlSocketPath = filepath.Join(t.TempDir(), "photon.sock")
			stop, err := service.startControlServer(daemonCtx)
			if err != nil {
				t.Fatal(err)
			}
			defer stop()
			request := controlRequest{Method: "ping_view", Zone: "node-b.catofes.", Ping: &pingdebug.Options{Count: 1000, Timeout: time.Minute}}
			clientCtx, cancelClient := context.WithCancel(t.Context())
			defer cancelClient()
			clientDone := make(chan error, 1)
			var conn net.Conn
			if mode == "disconnect" {
				conn, err = net.Dial("unix", service.ControlSocketPath)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				if err := json.NewEncoder(conn).Encode(request); err != nil {
					t.Fatal(err)
				}
			} else {
				go func() {
					var response controlResponse
					clientDone <- exchangeControl(clientCtx, service.ControlSocketPath, request, &response)
				}()
			}
			select {
			case ctx := <-prober.started:
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > controlPingMaxDuration {
					t.Fatal("missing server execution limit")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("probe did not start")
			}
			switch mode {
			case "disconnect":
				_ = conn.Close()
			case "client_cancel":
				cancelClient()
			case "daemon_cancel":
				cancelDaemon()
			}
			select {
			case err := <-prober.stopped:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("probe error = %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("probe did not receive cancellation")
			}
			if mode != "disconnect" {
				select {
				case err := <-clientDone:
					if mode == "client_cancel" && !errors.Is(err, context.Canceled) {
						t.Fatalf("client error = %v", err)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("client did not finish")
				}
			}
			if mode != "daemon_cancel" {
				if daemonCtx.Err() != nil {
					t.Fatalf("daemon canceled: %v", daemonCtx.Err())
				}
				ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
				defer cancel()
				var response controlViewResponse[inspect.DaemonStatusView]
				if err := exchangeControl(ctx, service.ControlSocketPath, controlRequest{Method: "daemon_status_view"}, &response); err != nil || !response.OK || !response.View.DaemonOnline {
					t.Fatalf("daemon no longer serves requests: %+v, %v", response, err)
				}
			}
		})
	}
}

func (p *controlPingProber) Probe(_ context.Context, target health.ProbeTarget, config health.ProbeConfig) health.ProbeResult {
	p.target = target
	p.config = config
	return health.ProbeResult{InstanceID: target.InstanceID, Success: true, RTT: time.Millisecond}
}

func (*controlPingProber) Type() string { return health.ProbeTypeICMP }

func TestDaemonControlErrorResponses(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	service := newTestDaemonFromOwners(
		&AppContext{Config: defaultAppConfig()}, verified, checkpoint, runtime, config, time.Second,
	)

	response := controlRequestViaPipe(t, service, controlRequest{Method: "record_put", Zone: "node-b.catofes."})
	if response.OK || response.Error == "" {
		t.Fatalf("invalid record_put response = %#v, want error", response)
	}

	response = controlRequestViaPipe(t, service, controlRequest{Method: "record_get", Zone: "node-b.catofes."})
	if response.OK || response.Error == "" {
		t.Fatalf("invalid record_get response = %#v, want error", response)
	}

	response = controlRequestViaPipe(t, service, controlRequest{Method: "bogus"})
	if response.OK || response.Error == "" {
		t.Fatalf("unknown method response = %#v, want error", response)
	}

	response = controlRequestViaPipe(t, service, controlRequest{Method: "root_init"})
	if response.OK || response.Error == "" {
		t.Fatalf("root_init response = %#v, want error", response)
	}
}

func TestDaemonControlStatus(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	service := newTestDaemonFromOwners(
		&AppContext{Config: defaultAppConfig()}, verified, checkpoint, runtime, config, time.Second,
	)
	service.ControlSocketPath = filepath.Join(t.TempDir(), "photon.sock")
	ctx := t.Context()
	stop, err := service.startControlServer(ctx)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			t.Skipf("Unix sockets are not permitted in this environment: %v", err)
		}
		t.Fatalf("startControlServer: %v", err)
	}
	defer stop()

	var response controlViewResponse[inspect.DaemonStatusView]
	requestCtx, cancel := context.WithTimeout(ctx, controlRequestDeadline)
	defer cancel()
	if err := exchangeControl(requestCtx, service.ControlSocketPath, controlRequest{Method: "daemon_status_view"}, &response); err != nil {
		t.Fatalf("daemon_status_view: %v", err)
	}
	if !response.OK || response.View.PeerID != config.PeerID || !response.View.DaemonOnline {
		t.Fatalf("status response = %#v", response)
	}
}

func TestCanonicalZoneQueryUsesControlWhileBoltOwnedAndMatchesOffline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "photon.db")
	legacy, trustedRoot := legacyRuntimeMigrationFixture(t)
	seedLegacyLinuxState(t, path, legacy)
	config := defaultAppConfig()
	config.StatePath = path
	config.TrustedRootPublicKey = append([]byte(nil), trustedRoot...)
	rt := &AppContext{Config: config, StatePath: path, Clock: func() time.Time { return time.Unix(1000, 0) }}

	state, err := openState(rt)
	if err != nil {
		t.Fatalf("openState: %v", err)
	}
	storeOpen := true
	t.Cleanup(func() {
		if storeOpen {
			_ = state.Close()
		}
	})
	service := newDaemon(rt, state, time.Second)
	installTestIPsecDrivers(service, &ipsec.DryRunDriver{}, &ipsec.DryRunDriver{})
	service.ControlSocketPath = filepath.Join(t.TempDir(), "photon.sock")
	t.Setenv("PHOTON_CONTROL_SOCKET", service.ControlSocketPath)
	stop, err := service.startControlServer(t.Context())
	if err != nil {
		t.Fatalf("startControlServer: %v", err)
	}

	if competing, err := corestate.OpenBoltStore(path, 0o600, 25*time.Millisecond); !errors.Is(err, bolt.ErrTimeout) {
		if competing != nil {
			_ = competing.Close()
		}
		t.Fatalf("second Bolt open error = %v, want timeout while daemon owns handle", err)
	}
	online, ok, err := readCanonicalViewViaControl[[]inspect.ZoneDetail](rt, controlRequest{Method: "zones_view"})
	if err != nil || !ok {
		t.Fatalf("online zones_view = ok %v err %v", ok, err)
	}

	stop()
	if err := state.Close(); err != nil {
		t.Fatalf("close daemon State: %v", err)
	}
	storeOpen = false
	common, _, err := loadOfflineOwnerViews(rt)
	if err != nil {
		t.Fatalf("loadOfflineOwnerViews: %v", err)
	}
	offline := buildZoneDetails(common.State.Network, rt.Now())
	if !reflect.DeepEqual(online, offline) {
		t.Fatalf("online/offline zone DTO mismatch:\nonline=%#v\noffline=%#v", online, offline)
	}
}

func TestDaemonControlCommonReadViews(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	config.Bootstrap = []syncConfigPeer{{ID: "node-b.catofes.", Addr: "127.0.0.1:43435"}}
	service := newTestDaemonFromOwners(
		&AppContext{Config: defaultAppConfig()}, verified, checkpoint, runtime, config, time.Second,
	)
	prober := &controlPingProber{}
	dryRun := &ipsec.DryRunDriver{}
	installTestLinuxDrivers(service, testLinuxDrivers{ipsec: dryRun, xfrm: dryRun, healthProber: prober})
	setTestIPsecObservation(service, map[string]ipsec.LinkInstance{
		"link-b": {ActualState: "up"},
	}, &ipsecObservationSummary{Desired: []photonstate.DesiredLinkObservation{{
		InstanceID: "link-b", GroupID: "group-b", PeerZone: "node-b.catofes.",
		LocalTunnelAddr: "10.0.0.1", PeerTunnelAddr: "10.0.0.2",
	}}})

	records := controlViewRequestViaPipe[inspect.RecordsDebugView](t, service, controlRequest{Method: "records_view", Zone: "node-b.catofes."})
	if !records.OK {
		t.Fatalf("records_view response = %#v", records)
	}
	zones := controlViewRequestViaPipe[[]inspect.ZoneDetail](t, service, controlRequest{Method: "zones_view"})
	if !zones.OK || len(zones.View) == 0 {
		t.Fatalf("zones_view response = %#v", zones)
	}
	services := controlViewRequestViaPipe[inspect.ServiceInspection](t, service, controlRequest{Method: "services_view"})
	if !services.OK {
		t.Fatalf("services_view response = %#v", services)
	}
	routes := controlViewRequestViaPipe[inspect.RouteShowReport](t, service, controlRequest{Method: "route_view"})
	if !routes.OK {
		t.Fatalf("route_view response = %#v", routes)
	}
	assignments := controlViewRequestViaPipe[[]inspect.IPAMAssignmentRow](t, service, controlRequest{Method: "ipam_assignments_view"})
	if !assignments.OK {
		t.Fatalf("ipam_assignments_view response = %#v", assignments)
	}
	endpoints := controlViewRequestViaPipe[inspect.EndpointDebugView](t, service, controlRequest{Method: "endpoints_view"})
	if !endpoints.OK {
		t.Fatalf("endpoints_view response = %#v", endpoints)
	}
	pingOptions := pingdebug.Options{Count: 2, Timeout: 20 * time.Millisecond}
	pingView := controlViewRequestViaPipe[inspect.PingDebugView](t, service, controlRequest{Method: "ping_view", Zone: "node-b.catofes.", Ping: &pingOptions})
	if !pingView.OK || pingView.View.Zone != "node-b.catofes." || len(pingView.View.Targets) != 1 || !pingView.View.Targets[0].Success {
		t.Fatalf("ping_view response = %#v", pingView)
	}
	if prober.target.InstanceID != "link-b" || prober.config.Burst != 2 || prober.config.Timeout != 20*time.Millisecond {
		t.Fatalf("daemon prober call target=%#v config=%#v", prober.target, prober.config)
	}
	statusView := controlViewRequestViaPipe[inspect.StatusView](t, service, controlRequest{Method: "status_view"})
	if !statusView.OK || !statusView.View.DaemonOnline {
		t.Fatalf("status_view response = %#v", statusView)
	}
	daemonStatus := controlViewRequestViaPipe[inspect.DaemonStatusView](t, service, controlRequest{Method: "daemon_status_view"})
	if !daemonStatus.OK || !daemonStatus.View.DaemonOnline || daemonStatus.View.PeerID != config.PeerID {
		t.Fatalf("daemon_status_view response = %#v", daemonStatus)
	}
	rootPublicKey := controlViewRequestViaPipe[[]byte](t, service, controlRequest{Method: "root_public_key"})
	if !rootPublicKey.OK || len(rootPublicKey.View) == 0 {
		t.Fatalf("root_public_key response = %#v", rootPublicKey)
	}
	admission := controlViewRequestViaPipe[inspect.AdmissionDiagnosis](t, service, controlRequest{Method: "admission_status"})
	if !admission.OK {
		t.Fatalf("admission_status response = %#v", admission)
	}
	endpointACLs := controlViewRequestViaPipe[[]photonstate.EndpointACL](t, service, controlRequest{Method: "endpoint_acl_list"})
	if !endpointACLs.OK {
		t.Fatalf("endpoint_acl_list response = %#v", endpointACLs)
	}
	peerLifecycle := controlViewRequestViaPipe[inspect.PeerLifecycleDebugView](t, service, controlRequest{Method: "peer_lifecycle_view"})
	if !peerLifecycle.OK {
		t.Fatalf("peer_lifecycle_view response = %#v", peerLifecycle)
	}
	gossipPeers := controlViewRequestViaPipe[[]inspect.PeerDebugView](t, service, controlRequest{Method: "gossip_peers_view"})
	if !gossipPeers.OK {
		t.Fatalf("gossip_peers_view response = %#v", gossipPeers)
	}
	healthView := controlViewRequestViaPipe[inspect.HealthView](t, service, controlRequest{Method: "health_status"})
	if !healthView.OK {
		t.Fatalf("health_status response = %#v", healthView)
	}
	syncView := controlViewRequestViaPipe[inspect.SyncStatusView](t, service, controlRequest{Method: "sync_view", Verbose: true})
	if !syncView.OK || syncView.View.PeerID != config.PeerID {
		t.Fatalf("sync_view response = %#v", syncView)
	}
	peer := controlViewRequestViaPipe[inspect.PeerDebugView](t, service, controlRequest{Method: "peer_debug", Zone: "node-b.catofes."})
	if !peer.OK || peer.View.PeerID != "node-b.catofes." {
		t.Fatalf("peer_debug response = %#v", peer)
	}
	zoneView := controlViewRequestViaPipe[inspect.ZoneInspectionView](t, service, controlRequest{Method: "zone_debug", Zone: "node-b.catofes.", History: 1})
	if !zoneView.OK || zoneView.View.Detail.Path == "" {
		t.Fatalf("zone_debug response = %#v", zoneView)
	}
	verifiedResponse := controlRequestViaPipe(t, service, controlRequest{Method: "verify_chain", Zone: "node-b.catofes."})
	if !verifiedResponse.OK {
		t.Fatalf("verify_chain response = %#v", verifiedResponse)
	}
}

func TestPrepareControlSocketPathRejectsActiveListener(t *testing.T) {
	path := filepath.Join(t.TempDir(), "photon.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			t.Skipf("Unix sockets are not permitted in this environment: %v", err)
		}
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	err = prepareControlSocketPath(path)
	if err == nil || !strings.Contains(err.Error(), "already in use") {
		t.Fatalf("prepareControlSocketPath(active) error = %v", err)
	}
	if _, statErr := os.Lstat(path); statErr != nil {
		t.Fatalf("active socket was removed: %v", statErr)
	}
}

func TestPrepareControlSocketPathRemovesStaleSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "photon.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			t.Skipf("Unix sockets are not permitted in this environment: %v", err)
		}
		t.Fatalf("listen: %v", err)
	}
	listener.(*net.UnixListener).SetUnlinkOnClose(false)
	if err := listener.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}

	if err := prepareControlSocketPath(path); err != nil {
		t.Fatalf("prepareControlSocketPath(stale): %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale socket still exists: %v", err)
	}
}

func TestPrepareControlSocketPathPreservesRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "photon.sock")
	if err := os.WriteFile(path, []byte("do not remove"), 0o600); err != nil {
		t.Fatalf("write regular file: %v", err)
	}

	if err := prepareControlSocketPath(path); err == nil || !strings.Contains(err.Error(), "not a Unix socket") {
		t.Fatalf("prepareControlSocketPath(regular) error = %v", err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "do not remove" {
		t.Fatalf("regular file changed: data=%q err=%v", got, err)
	}
}

func TestDaemonControlRoutingReload(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestRoutingOwners(t)
	appConfig := defaultAppConfig()
	appConfig.DataDir = t.TempDir()
	rt := &AppContext{Config: appConfig, StatePath: filepath.Join(t.TempDir(), "photon.db")}
	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, config, time.Second)
	service.routingDirty = false
	ctx := t.Context()
	go pumpDaemonEvents(ctx, service)

	response := controlRequestViaPipe(t, service, controlRequest{Method: "routing_reload"})
	if !response.OK || response.Message != "routing reloaded" {
		t.Fatalf("routing_reload response = %#v", response)
	}
	if service.routingDirty {
		t.Fatalf("routingDirty should be cleared after synchronous routing_reload")
	}
}

func TestDaemonControlBirdDump(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestRoutingOwners(t)
	appConfig := defaultAppConfig()
	appConfig.DataDir = t.TempDir()
	appConfig.Netns = photonlinux.NetNSConfig{Names: map[string]ipsec.NetNSSpec{"photontesth2": {Kind: ipsec.NetNSName, Name: "photontesth2", Create: true}}}
	appConfig.Routing, _ = photonlinux.ParseRoutingConfig([]photonlinux.RoutingInstanceYAML{{
		ID:            "main",
		NetNS:         "photontesth2",
		Enabled:       boolPtr(true),
		Mode:          ipsec.RoutingModeManaged,
		ControlSocket: "/run/photon/bird-photontesth2.ctl",
	}}, appConfig.Netns, appConfig.DataDir)

	client := &fakeBirdClient{raw: map[string]string{
		"show route table all where source = RTS_BABEL all": "Table photon_photontesth24:\n10.0.0.0/24 unicast\n",
	}}
	service := newTestDaemonFromOwners(&AppContext{Config: appConfig}, verified, checkpoint, runtime, config, time.Second)
	installTestBirdDrivers(service, nil, func(socketPath string, timeout time.Duration) birdClient {
		if socketPath != "/run/photon/bird-photontesth2.ctl" {
			t.Fatalf("socketPath = %q, want /run/photon/bird-photontesth2.ctl", socketPath)
		}
		return client
	})

	response := controlViewRequestViaPipe[inspect.BirdDumpResponse](t, service, controlRequest{Method: "bird_dump", NetNS: "photontesth2", BirdView: "route"})
	if !response.OK {
		t.Fatalf("bird_dump response = %#v", response)
	}
	inst := response.View.Instances["photontesth2"]
	command := "show route table all where source = RTS_BABEL all"
	if inst.ControlSocket != "/run/photon/bird-photontesth2.ctl" || inst.Raw[command] == "" {
		t.Fatalf("bird_dump instance = %#v", inst)
	}
	if len(client.rawCommands) != 2 || client.rawCommands[0] != command || client.rawCommands[1] != "show babel routes" {
		t.Fatalf("raw commands = %#v, want BIRD RIB and Babel routes", client.rawCommands)
	}
}

func TestDaemonControlLinksStatusUsesReconcileSnapshot(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	observationLinks := map[string]ipsec.LinkInstance{
		"link-1": {
			ID:            "link-1",
			GroupID:       "main",
			PeerZone:      "node-b.catofes.",
			TransportKind: "ipsec",
			LinkID:        "stable-link",
			TransportID:   "runtime-r3",
			ActualState:   "up",
			InterfaceName: "phxabc123",
			XFRMIfID:      42,
			IKEName:       "runtime-r3",
			ChildSAName:   "runtime-r3-child",
			Endpoint:      "198.51.100.2:4500",
		},
	}
	observationReconcile := &ipsecObservationSummary{
		LastRunUnix:  1234,
		DesiredLinks: 1,
		Desired: []photonstate.DesiredLinkObservation{{
			InstanceID:      "link-1",
			GroupID:         "main",
			PeerZone:        "node-b.catofes.",
			LinkID:          "stable-link",
			TransportID:     "runtime-r3",
			DesiredSpecHash: "desired-hash",
			InterfaceName:   "phxabc123",
			XFRMIfID:        42,
			Endpoint:        "203.0.113.9:33403",
			LocalTunnelAddr: "fd00::1%phxabc123",
			PeerTunnelAddr:  "fd00::2%phxabc123",
		}},
		ActualSAs: []photonstate.LinkSAObservation{{
			Name:           "runtime-r3",
			ChildSA:        "runtime-r3-child",
			RemoteEndpoint: "203.0.113.9:33403",
			Established:    true,
		}},
	}
	service := newTestDaemonFromOwners(
		&AppContext{Config: defaultAppConfig()}, verified, checkpoint, runtime, config, time.Second,
	)
	setTestIPsecObservation(service, observationLinks, observationReconcile)

	response := controlViewRequestViaPipe[inspect.LinksDebugView](t, service, controlRequest{Method: "links_view"})
	if !response.OK {
		t.Fatalf("links_view response = %#v", response)
	}
	if response.View.DesiredPlanSource != "last_reconcile" || response.View.LastDesiredCount != 1 {
		t.Fatalf("links_view source/count = %q/%d, want last_reconcile/1", response.View.DesiredPlanSource, response.View.LastDesiredCount)
	}
	if len(response.View.ReconcileSAs) != 1 {
		t.Fatalf("links_view stored_sas = %d, want 1", len(response.View.ReconcileSAs))
	}
	links := response.View.Inspection.Links
	if len(links) != 1 || links[0].Desired == nil {
		t.Fatalf("links_view links = %+v, want desired snapshot", links)
	}
	if got := links[0].Desired.Endpoint; got != "203.0.113.9:33403" {
		t.Fatalf("links_view desired endpoint = %q, want reconcile snapshot endpoint", got)
	}
}

func TestDaemonControlReadMethodsIgnoreDetachedOwnerInputMutations(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	observationLinks := map[string]ipsec.LinkInstance{
		"link-committed": {
			ID:          "link-committed",
			GroupID:     "main",
			PeerZone:    "node-b.catofes.",
			ActualState: "up",
		},
	}
	observationReconcile := &ipsecObservationSummary{
		LastRunUnix:  1234,
		DesiredLinks: 1,
		Desired: []photonstate.DesiredLinkObservation{{
			InstanceID: "link-committed",
			GroupID:    "main",
			PeerZone:   "node-b.catofes.",
			Endpoint:   "203.0.113.9:4500",
		}},
	}
	checkpoint.Peers = map[string]corestate.PeerCheckpoint{
		"node-b": {
			LastSyncUnix:      1111,
			ObservedEndpoint:  "198.51.100.2:7777",
			ObservedUntilUnix: time.Now().Add(time.Minute).Unix(),
		},
	}
	service := newTestDaemonFromOwners(
		&AppContext{Config: defaultAppConfig()}, verified, checkpoint, runtime, config, time.Second,
	)
	setTestIPsecObservation(service, observationLinks, observationReconcile)
	committedRev := uint64(service.State.Common.VerifiedRevision())

	observationLinks["link-uncommitted"] = ipsec.LinkInstance{ID: "link-uncommitted"}
	observationReconcile.DesiredLinks = 99

	status := controlViewRequestViaPipe[inspect.DaemonStatusView](t, service, controlRequest{Method: "daemon_status_view"})
	if !status.OK {
		t.Fatalf("status response = %#v", status)
	}
	if status.View.StateRevision != committedRev || status.View.LinkInstances != 1 || status.View.DesiredLinks != 1 {
		t.Fatalf("status = %#v, want committed rev=%d link_instances=1 desired_links=1", status, committedRev)
	}

	links := controlViewRequestViaPipe[inspect.LinksDebugView](t, service, controlRequest{Method: "links_view"})
	if !links.OK {
		t.Fatalf("links_view response = %#v", links)
	}
	if links.View.LastDesiredCount != 1 {
		t.Fatalf("links_view = %#v, want desired=1", links)
	}

	peers := controlViewRequestViaPipe[inspect.PeerLifecycleDebugView](t, service, controlRequest{Method: "peer_lifecycle_view"})
	if !peers.OK {
		t.Fatalf("peer_lifecycle_view response = %#v", peers)
	}
}

func TestDaemonPacketEventUpdatesCheckpointOwner(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	service := newTestDaemonFromOwners(
		&AppContext{Config: defaultAppConfig()}, verified, checkpoint, runtime, config, time.Second,
	)
	packet := &gossip.Packet{
		Addr: &net.UDPAddr{IP: net.ParseIP("198.51.100.9"), Port: 33434},
		Message: &gossip.Message{
			Type:   gossip.MessagePong,
			PeerID: "node-b.catofes.",
			Pong:   &gossip.Pong{},
		},
	}

	if _, err := service.handleGossipDriverEvent(context.Background(), corehost.GossipPacketReceived{Packet: packet}); err != nil {
		t.Fatalf("packet event error: %v", err)
	}

	peer := service.State.Common.ReadView().Gossip.Peers["node-b.catofes."]
	if peer.ObservedEndpoint != "198.51.100.9:33434" {
		t.Fatalf("observed endpoint = %q, want packet source", peer.ObservedEndpoint)
	}
}

func TestDaemonControlRecordGet(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	record, err := buildSignedRecordAt(verified.Network, verified.IdentityPrivateKey, "node-b.catofes.", "site/name", []byte(`{"name":"node-b"}`), "policy.json", time.Unix(1000, 0))
	if err != nil {
		t.Fatalf("buildSignedRecordAt: %v", err)
	}
	if err := verified.Network.Put(record); err != nil {
		t.Fatalf("Put(record): %v", err)
	}
	record, err = buildSignedRecordAt(verified.Network, verified.IdentityPrivateKey, "node-b.catofes.", "site/name", []byte(`{"name":"node-b-2"}`), "policy.json", time.Unix(1001, 0))
	if err != nil {
		t.Fatalf("buildSignedRecordAt(second): %v", err)
	}
	if err := verified.Network.Put(record); err != nil {
		t.Fatalf("Put(second record): %v", err)
	}
	service := newTestDaemonFromOwners(
		&AppContext{Config: defaultAppConfig()}, verified, checkpoint, runtime, config, time.Second,
	)

	response := controlViewRequestViaPipe[*inspect.RecordDetailView](t, service, controlRequest{
		Method:  "record_get",
		Zone:    "node-b.catofes.",
		Key:     "site/name",
		History: 1,
	})
	if !response.OK {
		t.Fatalf("record_get response = %#v", response)
	}
	if response.View == nil || response.View.Key != "site/name" || response.View.Value != `{"name":"node-b-2"}` || response.View.RecordHash == "" {
		t.Fatalf("record_get record = %#v", response.View)
	}
	history := response.View.RecordHistory
	if len(history) != 1 {
		t.Fatalf("record_get history len = %d, want 1", len(history))
	}
	if item := history[0]; item.Value != `{"name":"node-b"}` {
		t.Fatalf("record_get history = %#v", history)
	}

	legacyError := controlRequestViaPipe(t, service, controlRequest{
		Method: "record_get",
		Zone:   "node-b.catofes.",
		Key:    "missing",
	})
	if legacyError.OK || legacyError.Error == "" {
		t.Fatalf("missing record_get response = %#v, want error", legacyError)
	}
}
