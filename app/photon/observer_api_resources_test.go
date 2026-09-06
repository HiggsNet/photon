package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	inspecttext "github.com/HiggsNet/photon/internal/inspect/text"
	"github.com/HiggsNet/photon/internal/observability/healthspool"
	"github.com/HiggsNet/photon/internal/observer"
	"github.com/HiggsNet/photon/pkg/core/gossip"
	"github.com/HiggsNet/photon/pkg/core/observability"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestZoneOwnerFixtureKeepsControlCLIAndHTTPMeaningAligned(t *testing.T) {
	srv := newTestObserverServer()
	ns := zone.NewNetworkState()
	ns.Zones["node-a.catofes."] = zone.NewZoneState("node-a.catofes.", nil)
	ns.Zones["node-a.catofes."].Records["site/name"] = &zone.Record{Key: "site/name"}
	ns.Zones["branch.node-a.catofes."] = zone.NewZoneState("branch.node-a.catofes.", nil)
	updateTestObserverOwners(srv, func(verified *corestate.VerifiedState, _ *corestate.GossipCheckpoint, _ *linuxRuntimeState) {
		verified.ManagedZone = "node-a.catofes."
		verified.Network = ns
	})

	control := controlViewRequestViaPipe[[]inspect.ZoneDetail](t, srv.daemon, controlRequest{Method: "zones_view"})
	if !control.OK || len(control.View) != 2 {
		t.Fatalf("zones_view response = %#v", control)
	}
	var cli bytes.Buffer
	if err := inspecttext.WriteZones(&cli, control.View, "", false); err != nil {
		t.Fatalf("WriteZones: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/zones", nil)
	rr := httptest.NewRecorder()
	srv.handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("zones status = %d, body=%s", rr.Code, rr.Body.String())
	}
	var response observer.APIResponse
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("decode zones response: %v", err)
	}
	httpZones := response.Data.(map[string]any)["zones"].([]any)
	if len(httpZones) != len(control.View) {
		t.Fatalf("HTTP/control zone count = %d/%d", len(httpZones), len(control.View))
	}
	for i, detail := range control.View {
		summary := httpZones[i].(map[string]any)
		if summary["path"] != detail.Path || summary["records"] != float64(detail.RecordCount) || summary["delegations"] != float64(detail.DelegationCount) || summary["revocations"] != float64(detail.RevocationCount) || summary["revoked"] != detail.Revoked {
			t.Fatalf("zone %d HTTP/control mismatch: summary=%#v detail=%#v", i, summary, detail)
		}
		if !strings.Contains(cli.String(), detail.Path) {
			t.Fatalf("CLI output missing canonical zone %q: %s", detail.Path, cli.String())
		}
	}
}

func TestObserverHandlerRoutesPeerDetail(t *testing.T) {
	srv := newTestObserverServer()
	updateTestObserverOwners(srv, func(_ *corestate.VerifiedState, checkpoint *corestate.GossipCheckpoint, _ *linuxRuntimeState) {
		checkpoint.Peers["peer-a.catofes."] = corestate.PeerCheckpoint{
			LastSyncUnix: 123,
			FailureCount: 2,
		}
	})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/peers/peer-a.catofes.", nil)
	rr := httptest.NewRecorder()
	srv.handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d; body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	var resp observer.APIResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if !resp.OK {
		t.Fatalf("response OK should be true: %#v", resp)
	}
	data, ok := resp.Data.(map[string]any)
	if !ok {
		t.Fatalf("data is not a map: %T", resp.Data)
	}
	if data["peer_id"] != "peer-a.catofes." {
		t.Errorf("peer_id = %v, want peer-a.catofes.", data["peer_id"])
	}
	if data["failure_count"] != float64(2) {
		t.Errorf("failure_count = %v, want 2", data["failure_count"])
	}
}

func TestObserverZonesAPIEmpty(t *testing.T) {
	srv := newTestObserverServer()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/zones", nil)
	rr := httptest.NewRecorder()
	srv.handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("status code = %d, want %d", rr.Code, http.StatusOK)
	}
	var resp observer.APIResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	data, ok := resp.Data.(map[string]any)
	if !ok {
		t.Fatal("data is not a map")
	}
	zones, ok := data["zones"].([]any)
	if !ok {
		t.Fatal("zones is not a list")
	}
	if len(zones) != 0 {
		t.Errorf("zones count = %d, want 0", len(zones))
	}
}

func TestObserverZoneDetailIncludesRecordsAuthorityAndHistory(t *testing.T) {
	srv := newTestObserverServer()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	authority := &zone.ZoneAuthority{
		Zone:      "node-a.catofes.",
		Epoch:     7,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: pub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermWrite},
				KeyPrefix:   "identity",
			}},
		}},
	}
	active := &zone.Record{
		Zone:      "node-a.catofes.",
		Key:       "identity",
		Type:      "policy.string",
		Value:     []byte(`{"name":"node-a"}`),
		Version:   2,
		Timestamp: 20,
	}
	if err := photoncrypto.SignRecord(active, priv); err != nil {
		t.Fatalf("SignRecord(active): %v", err)
	}
	old := &zone.Record{
		Zone:      "node-a.catofes.",
		Key:       "identity",
		Type:      "policy.string",
		Value:     []byte("old"),
		Version:   1,
		Timestamp: 10,
	}
	if err := photoncrypto.SignRecord(old, priv); err != nil {
		t.Fatalf("SignRecord(old): %v", err)
	}
	zs := zone.NewZoneState("node-a.catofes.", authority)
	zs.Records["identity"] = active
	zs.RecordHistory["identity"] = []*zone.Record{old}
	updateTestObserverOwners(srv, func(verified *corestate.VerifiedState, _ *corestate.GossipCheckpoint, _ *linuxRuntimeState) {
		verified.Network = &zone.NetworkState{Zones: map[zone.ZonePath]*zone.ZoneState{
			"node-a.catofes.": zs,
		}}
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/zones/node-a.catofes.", nil)
	rr := httptest.NewRecorder()
	srv.handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d; body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	var resp observer.APIResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	data := resp.Data.(map[string]any)
	if data["authority_hash"] == "" {
		t.Fatalf("authority_hash should be present: %#v", data)
	}
	authorityData := data["authority"].(map[string]any)
	if authorityData["epoch"] != float64(7) {
		t.Fatalf("authority epoch = %v, want 7", authorityData["epoch"])
	}
	records := data["records"].([]any)
	if len(records) != 1 {
		t.Fatalf("records len = %d, want 1", len(records))
	}
	record := records[0].(map[string]any)
	if record["value"].(string) != `{"name":"node-a"}` {
		t.Fatalf("record value = %v", record["value"])
	}
	if record["value_json"] == nil || record["record_hash"] == "" || record["signature"] == "" {
		t.Fatalf("record should include parsed JSON, hash and signature: %#v", record)
	}
	if data["history_count"] != float64(1) {
		t.Fatalf("history_count = %v, want 1", data["history_count"])
	}
}

func TestObserverPeersAPIEmpty(t *testing.T) {
	srv := newTestObserverServer()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/peers", nil)
	rr := httptest.NewRecorder()
	srv.handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("status code = %d, want %d", rr.Code, http.StatusOK)
	}
	var resp observer.APIResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	data := resp.Data.(map[string]any)
	peers := data["peers"].([]any)
	if len(peers) != 0 {
		t.Errorf("peers count = %d, want 0", len(peers))
	}
}

func TestObserverPeersAPIIncludesEndpointAndDiagnosticsDetails(t *testing.T) {
	srv := newTestObserverServer()
	now := time.Unix(1000, 0)
	srv.daemon.App.Clock = func() time.Time { return now }
	srv.daemon.App.Config.Bootstrap = []syncConfigPeer{{ID: "node-b.catofes.", Addr: "192.0.2.10:33434"}}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	authority := &zone.ZoneAuthority{Zone: "node-b.catofes.", Epoch: 1, Threshold: 1, Keys: []zone.AuthorizedKey{{Key: pub}}}
	zs := zone.NewZoneState("node-b.catofes.", authority)
	endpointValue := endpointRecordBytes([]gossip.LocalEndpoint{{
		IP:       net.ParseIP("203.0.113.20"),
		Port:     33434,
		Scope:    "global",
		Priority: 100,
		Source:   gossip.SourceAdvertise,
	}}, now)
	endpointRecord := &zone.Record{
		Zone:      "node-b.catofes.",
		Key:       gossip.EndpointRecordKeyUDP,
		Type:      "sync.endpoint",
		Value:     endpointValue,
		Version:   1,
		Timestamp: now.Unix(),
	}
	if err := photoncrypto.SignRecord(endpointRecord, priv); err != nil {
		t.Fatalf("SignRecord(endpoint): %v", err)
	}
	zs.Records[gossip.EndpointRecordKeyUDP] = endpointRecord
	updateTestObserverOwners(srv, func(verified *corestate.VerifiedState, checkpoint *corestate.GossipCheckpoint, _ *linuxRuntimeState) {
		verified.Network = zone.NewNetworkState()
		verified.Network.Zones["node-b.catofes."] = zs
		checkpoint.Peers["node-b.catofes."] = corestate.PeerCheckpoint{
			LastSyncUnix:       900,
			LastRelayUnix:      920,
			DiscoveredEndpoint: "203.0.113.20:33434",
			ObservedEndpoint:   "198.51.100.9:33434",
			ObservedGraceEndpoints: []corestate.ObservedGraceEndpoint{{
				Endpoint: "198.51.100.8:33434", UntilUnix: 1100,
			}},
			RejectedObjects: map[zone.ZonePath]corestate.RejectedObject{
				"node-b.catofes.": {Reason: "verify_failed"},
			},
		}
	})
	srv.daemon.gossipDriver.Observability.Update("node-b.catofes.", now, func(diagnostics *observability.PeerDiagnostics) {
		diagnostics.LastUpdateSource = "announce"
		diagnostics.LastRelaySuppression = "relay_fanout_limited"
		diagnostics.ObservedSource = "verified_packet"
		diagnostics.DatagramStats = &observability.PeerDatagramStats{ChunkFallbacks: 2}
	})
	srv.daemon.gossipDriver.Observability.Update("node-b.catofes.", now, func(diagnostics *observability.PeerDiagnostics) {
		diagnostics.ObjectPullStats = &observability.PeerObjectPullStats{Attempts: 3, Successes: 2, LastUnix: now.Unix(), LastObject: "zone", LastZone: "node-b.catofes.", LastSourcePeer: "node-b.catofes."}
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/peers/node-b.catofes.", nil)
	rr := httptest.NewRecorder()
	srv.handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d; body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	var resp observer.APIResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	data := resp.Data.(map[string]any)
	if data["configured_addr"] != "192.0.2.10:33434" {
		t.Fatalf("configured_addr = %v", data["configured_addr"])
	}
	if data["last_update_source"] != "announce" || data["last_relay_suppression"] != "relay_fanout_limited" {
		t.Fatalf("peer diagnostics missing: %#v", data)
	}
	datagram := data["datagram_stats"].(map[string]any)
	if datagram["chunk_fallbacks"] != float64(2) {
		t.Fatalf("datagram_stats = %#v, want chunk_fallbacks=2", datagram)
	}
	objectPull := data["object_pull_stats"].(map[string]any)
	if objectPull["attempts"] != float64(3) || objectPull["successes"] != float64(2) {
		t.Fatalf("object_pull_stats = %#v, want attempts=3 successes=2", objectPull)
	}
	endpoints := data["endpoints"].([]any)
	if len(endpoints) < 3 {
		t.Fatalf("endpoints len = %d, want at least 3: %#v", len(endpoints), endpoints)
	}
	var sawSigned, sawObserved bool
	for _, item := range endpoints {
		ep := item.(map[string]any)
		if ep["addr"] == "203.0.113.20:33434" && ep["source"] == "advertise" {
			sawSigned = true
		}
		if ep["addr"] == "198.51.100.9:33434" && ep["source"] == "verified_packet" {
			sawObserved = true
		}
	}
	if !sawSigned || !sawObserved {
		t.Fatalf("missing signed/observed endpoints: %#v", endpoints)
	}
}

func TestObserverPeersAPIExcludesLocalPeerID(t *testing.T) {
	srv := newTestObserverServer()
	now := time.Unix(1000, 0)
	srv.daemon.App.Clock = func() time.Time { return now }
	srv.daemon.App.Config.PeerID = "node-a.catofes."
	srv.daemon.App.Config.Bootstrap = []syncConfigPeer{
		{ID: "node-a.catofes.", Addr: "127.0.0.1:33434"},
		{ID: "node-b.catofes.", Addr: "127.0.0.1:33435"},
	}
	updateTestObserverOwners(srv, func(verified *corestate.VerifiedState, _ *corestate.GossipCheckpoint, _ *linuxRuntimeState) {
		verified.ManagedZone = "node-a.catofes."
		verified.Network = zone.NewNetworkState()
		addObserverEndpointZone(t, verified.Network, "node-a.catofes.", "127.0.0.1", 33434, now)
		addObserverEndpointZone(t, verified.Network, "node-b.catofes.", "127.0.0.1", 33435, now)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/peers", nil)
	rr := httptest.NewRecorder()
	srv.handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d; body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	var resp observer.APIResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	data := resp.Data.(map[string]any)
	peers := data["peers"].([]any)
	if len(peers) != 1 {
		t.Fatalf("peers len = %d, want 1: %#v", len(peers), peers)
	}
	peer := peers[0].(map[string]any)
	if peer["peer_id"] != "node-b.catofes." {
		t.Fatalf("peer_id = %v, want node-b.catofes.; peers=%#v", peer["peer_id"], peers)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/peers/node-a.catofes.", nil)
	rr = httptest.NewRecorder()
	srv.handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("self peer status code = %d, want %d; body=%s", rr.Code, http.StatusNotFound, rr.Body.String())
	}
}

func TestObserverPeersAPISortsByZonePath(t *testing.T) {
	srv := newTestObserverServer()
	now := time.Unix(1000, 0)
	srv.daemon.App.Clock = func() time.Time { return now }
	srv.daemon.App.Config.PeerID = "node-a.catofes."
	updateTestObserverOwners(srv, func(verified *corestate.VerifiedState, _ *corestate.GossipCheckpoint, _ *linuxRuntimeState) {
		verified.ManagedZone = "node-a.catofes."
		verified.Network = zone.NewNetworkState()
		addObserverEndpointZone(t, verified.Network, "zeta.other.", "127.0.0.1", 33439, now)
		addObserverEndpointZone(t, verified.Network, "node-b.catofes.", "127.0.0.1", 33435, now)
		addObserverEndpointZone(t, verified.Network, "alpha.catofes.", "127.0.0.1", 33436, now)
		addObserverEndpointZone(t, verified.Network, "branch.alpha.catofes.", "127.0.0.1", 33437, now)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/peers", nil)
	rr := httptest.NewRecorder()
	srv.handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d; body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	var resp observer.APIResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	data := resp.Data.(map[string]any)
	peers := data["peers"].([]any)
	var got []string
	for _, item := range peers {
		got = append(got, item.(map[string]any)["peer_id"].(string))
	}
	want := []string{"alpha.catofes.", "branch.alpha.catofes.", "node-b.catofes.", "zeta.other."}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("peer order = %v, want %v", got, want)
	}
}

func TestObserverLinksAPIEmpty(t *testing.T) {
	srv := newTestObserverServer()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/links", nil)
	rr := httptest.NewRecorder()
	srv.handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("status code = %d, want %d", rr.Code, http.StatusOK)
	}
	var resp observer.APIResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	data := resp.Data.(map[string]any)
	instances := data["instances"].([]any)
	if len(instances) != 0 {
		t.Errorf("instances count = %d, want 0", len(instances))
	}
}

func TestObserverLinksAPIDetailIncludesDesiredSAAndRouting(t *testing.T) {
	srv := newTestObserverServer()
	srv.daemon.App.Config = &appConfig{
		IPsec: ipsecConfig{
			LinkGroups: []ipsec.LinkGroupSpec{{
				ID:    "blue",
				NetNS: ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "phx-blue"},
			}},
		},
		Routing: routingConfig{
			Instances: []RoutingInstance{{
				Enabled: true,
				NetNS:   "phx-blue",
			}},
		},
	}
	updateTestObserverOwners(srv, func(_ *corestate.VerifiedState, _ *corestate.GossipCheckpoint, runtime *linuxRuntimeState) {
		runtime.LinkInstances = map[string]linkInstanceState{
			"link-1": {
				ID:              "link-1",
				GroupID:         "blue",
				PeerZone:        "node-b.catofes.",
				ActualState:     "up",
				InterfaceName:   "phx0",
				XFRMIfID:        42,
				Endpoint:        "198.51.100.10:4500",
				DesiredSpecHash: "abcdef0123456789",
				ChildSAName:     "child-link-1",
				InitiatorRole:   "primary",
			},
		}
		runtime.IPsecReconcile = &ipsecReconcileState{
			LastRunUnix:  123,
			DesiredLinks: 1,
			Desired: []desiredLinkState{{
				InstanceID:      "link-1",
				GroupID:         "blue",
				PeerZone:        "node-b.catofes.",
				DesiredSpecHash: "abcdef0123456789",
				InterfaceName:   "phx0",
				XFRMIfID:        42,
				Endpoint:        "198.51.100.10:4500",
				LocalTunnelAddr: "fd00::1%phx0",
				PeerTunnelAddr:  "fd00::2%phx0",
			}},
			ActualSAs: []linkSAState{{
				Name:           "link-1",
				ChildSA:        "child-link-1",
				Established:    true,
				ReqID:          77,
				LocalIdentity:  "node-a.catofes.",
				RemoteIdentity: "node-b.catofes.",
			}},
		}
		runtime.BirdInstances = map[string]*BirdInstanceState{
			"phx-blue": {State: "running"},
		}
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/links", nil)
	rr := httptest.NewRecorder()
	srv.handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d; body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	var resp observer.APIResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	data := resp.Data.(map[string]any)
	instances := data["instances"].([]any)
	if len(instances) != 1 {
		t.Fatalf("instances count = %d, want 1", len(instances))
	}
	link := instances[0].(map[string]any)
	if link["state"] != "up" {
		t.Fatalf("state = %v, want up", link["state"])
	}
	desired := link["desired"].(map[string]any)
	if desired["peer_tunnel_addr"] != "fd00::2%phx0" {
		t.Fatalf("peer_tunnel_addr = %v, want fd00::2%%phx0", desired["peer_tunnel_addr"])
	}
	sa := link["actual_sa"].(map[string]any)
	if sa["reqid"].(float64) != 77 || sa["remote_identity"] != "node-b.catofes." {
		t.Fatalf("actual_sa = %#v, want reqid and remote identity", sa)
	}
	routing := link["routing"].(map[string]any)
	if routing["bird_state"] != "running" {
		t.Fatalf("bird_state = %v, want running", routing["bird_state"])
	}
}

func TestObserverHealthAPIIncludesLinkContextWithoutSamples(t *testing.T) {
	srv := newTestObserverServer()
	updateTestObserverOwners(srv, func(_ *corestate.VerifiedState, _ *corestate.GossipCheckpoint, runtime *linuxRuntimeState) {
		runtime.LinkInstances = map[string]linkInstanceState{
			"link-1": {
				ID:            "link-1",
				GroupID:       "blue",
				PeerZone:      "node-b.catofes.",
				ActualState:   "up",
				InterfaceName: "phx0",
				Endpoint:      "198.51.100.10:4500",
			},
		}
		runtime.IPsecReconcile = &ipsecReconcileState{
			Desired: []desiredLinkState{{
				InstanceID:      "link-1",
				GroupID:         "blue",
				PeerZone:        "node-b.catofes.",
				InterfaceName:   "phx0",
				LocalTunnelAddr: "fd00::1%phx0",
				PeerTunnelAddr:  "fd00::2%phx0",
			}},
		}
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	rr := httptest.NewRecorder()
	srv.handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d; body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	var resp observer.APIResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	data := resp.Data.(map[string]any)
	links := data["links"].([]any)
	if len(links) != 1 {
		t.Fatalf("health links = %d, want 1", len(links))
	}
	item := links[0].(map[string]any)
	if item["peer_zone"] != "node-b.catofes." || item["peer_tunnel_addr"] != "fd00::2%phx0" {
		t.Fatalf("health context = %#v, want peer and tunnel context", item)
	}
	health := item["health"].(map[string]any)
	if health["state"] != "unknown" {
		t.Fatalf("health state = %v, want unknown", health["state"])
	}
}

func TestObserverHealthSeriesReadsLocalSpool(t *testing.T) {
	srv := newTestObserverServer()
	cfg := defaultHealthConfig()
	cfg.MetricsEnabled = true
	cfg.LocalSpoolPath = t.TempDir()
	cfg.LocalSpoolMaxAge = time.Hour
	srv.daemon.App.Config.Health = cfg
	srv.daemon.health = &healthDriver{spool: healthspool.New(cfg.spoolConfig())}
	now := time.Unix(3000, 0)
	srv.daemon.App.Clock = func() time.Time { return now }
	if err := srv.daemon.health.spool.Append(now, healthSpoolSamples([]healthLinkJSON{{
		InstanceID: "link-1",
		State:      "healthy",
		ProbeType:  "icmp",
		LastRTTMs:  42,
		LossRatio:  0,
		JitterMs:   3,
	}})); err != nil {
		t.Fatalf("appendHealthSpool: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health/link-1/series?metric=rtt&range=5m&step=1m", nil)
	rr := httptest.NewRecorder()
	srv.handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d; body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	var resp observer.APIResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	data := resp.Data.(map[string]any)
	ds := data["datasource"].(map[string]any)
	if ds["configured"] != true || ds["type"] != "local_spool" {
		t.Fatalf("datasource = %#v, want configured local_spool", ds)
	}
	series := data["series"].(map[string]any)
	points := series["points"].([]any)
	if len(points) != 1 {
		t.Fatalf("points = %#v, want 1 point", points)
	}
	point := points[0].(map[string]any)
	if point["value"].(float64) != 42 {
		t.Fatalf("point value = %v, want 42", point["value"])
	}
}

func TestObserverRoutesAPI(t *testing.T) {
	srv := newTestObserverServer()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/routes", nil)
	rr := httptest.NewRecorder()
	srv.handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("status code = %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestObserverBirdAPI(t *testing.T) {
	srv := newTestObserverServer()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/bird", nil)
	rr := httptest.NewRecorder()
	srv.handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("status code = %d, want %d", rr.Code, http.StatusOK)
	}
}
