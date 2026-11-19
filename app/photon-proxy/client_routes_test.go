package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
)

func TestClientRouteAdminPersistsChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "routes.db")
	state, initial, err := openRouteState(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	newClient := func(clientEntry) *chainClient { return &chainClient{} }
	manager := newRouteManager(t.Context(), state, newClient)
	t.Cleanup(func() {
		manager.close()
		_ = state.Close()
	})
	if err := manager.start(initial, nil); err != nil {
		t.Fatal(err)
	}
	admin := routeAdminHandler(manager)
	request := func(status int, method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		response := httptest.NewRecorder()
		admin.ServeHTTP(response, httptest.NewRequest(method, "/v1/routes"+path, strings.NewReader(body)))
		if response.Code != status {
			t.Fatalf("%s %s = %d, want %d, response %s", method, path, response.Code, status, response.Body)
		}
		return response
	}
	first := request(http.StatusCreated, "POST", "", `{"name":"first","hops":["b.example./public-v6"]}`)
	var created routeInfo
	if err := json.Unmarshal(first.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	listen, err := netip.ParseAddrPort(created.Listen)
	if err != nil || !listen.Addr().IsLoopback() || listen.Port() == 0 {
		t.Fatalf("invalid automatic listen address %q", created.Listen)
	}
	request(http.StatusConflict, "POST", "", `{"name":"other","hops":["b.example./public-v6"],"listen":"`+created.Listen+`"}`)
	request(http.StatusBadRequest, "PUT", "/first", `{"hops":["b.example./public-v6"],"listen":"127.0.0.1:0"}`)
	update := request(http.StatusOK, "PUT", "/first", `{"hops":["c.example./photon"],"udp_prefixes":["10.0.0.0/8"]}`)
	var changed routeInfo
	if err := json.Unmarshal(update.Body.Bytes(), &changed); err != nil || changed.Listen != created.Listen {
		t.Fatalf("route replacement changed the port: %+v, %v", changed, err)
	}
	request(http.StatusCreated, "POST", "", `{"name":"temporary","hops":["b.example./public-v6"]}`)
	request(http.StatusNoContent, "DELETE", "/temporary", "")
	request(http.StatusNotFound, "DELETE", "/temporary", "")
	manager.close()
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}

	seed := map[string]clientRoute{"yaml": {Listen: "127.0.0.1:1080", Hops: []string{"b.example./public-v6"}}}
	reopened, stored, err := openRouteState(path, seed)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	entry := stored["first"]
	if len(stored) != 1 || entry.Listen != created.Listen || len(entry.Hops) != 1 || entry.Hops[0] != "c.example./photon" ||
		len(entry.UDPPrefixes) != 1 || entry.UDPPrefixes[0] != "10.0.0.0/8" {
		t.Fatalf("unexpected restored routes: %+v", stored)
	}
}
