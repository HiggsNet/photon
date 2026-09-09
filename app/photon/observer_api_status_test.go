package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/observer"
)

func TestObserverStatusAPI(t *testing.T) {
	srv := newTestObserverServer()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	rr := httptest.NewRecorder()
	srv.handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("status code = %d, want %d", rr.Code, http.StatusOK)
	}
	var resp observer.APIResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if !resp.OK {
		t.Error("response OK should be true")
	}
	data, ok := resp.Data.(map[string]any)
	if !ok {
		t.Fatal("data is not a map")
	}
	if data["peer_id"] != "test-node" {
		t.Errorf("peer_id = %v, want test-node", data["peer_id"])
	}
	if data["daemon_online"] != true {
		t.Error("daemon should be online")
	}
}

func TestObserverReadMethodsIgnoreDetachedOwnerInputMutations(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	observationLinks := map[string]linkInstanceState{
		"link-committed": {
			ID:          "link-committed",
			GroupID:     "main",
			PeerZone:    "node-b.catofes.",
			ActualState: "up",
		},
	}
	observationReconcile := &ipsecObservationSummary{DesiredLinks: 1}
	appConfig := defaultAppConfig()
	appConfig.Observer.Enabled = true
	service := newTestDaemonFromOwners(
		&AppContext{Config: appConfig}, verified, checkpoint, runtime, config, time.Second,
	)
	setTestIPsecObservation(service, observationLinks, observationReconcile)
	srv := newObserverServer(service, appConfig.Observer)
	if srv == nil {
		t.Fatal("observer server is nil")
	}
	committedRev := service.StateStore.Meta().Revision

	observationLinks["link-uncommitted"] = linkInstanceState{ID: "link-uncommitted"}
	observationReconcile.DesiredLinks = 99

	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
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
	if data["state_revision"] != float64(committedRev) || data["link_instances"] != float64(1) || data["desired_links"] != float64(1) {
		t.Fatalf("status data = %#v, want committed rev=%d link_instances=1 desired_links=1", data, committedRev)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/links", nil)
	rr = httptest.NewRecorder()
	srv.handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("links code = %d, want %d; body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode links error: %v", err)
	}
	linksData := resp.Data.(map[string]any)
	if linksData["desired_links"] != float64(1) {
		t.Fatalf("links data = %#v, want desired_links=1 from committed snapshot", linksData)
	}
}
