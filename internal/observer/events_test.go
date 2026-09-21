package observer

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEventsMethodNotAllowed(t *testing.T) {
	srv := newTestServer()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/events", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status code = %d, want %d", rr.Code, http.StatusMethodNotAllowed)
	}
}

func TestEventsInitialFrame(t *testing.T) {
	srv := newTestServer()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/api/v1/events", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusOK)
	}
	if body := rr.Body.String(); !strings.Contains(body, "event: connected") {
		t.Fatalf("initial connected SSE frame was not written: %q", body)
	}
}

func TestRecentEventsMethodNotAllowed(t *testing.T) {
	srv := newTestServer()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/events/recent", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status code = %d, want %d", rr.Code, http.StatusMethodNotAllowed)
	}
}

type recentEventsResponse struct {
	OK   bool `json:"ok"`
	Data struct {
		Events []Event `json:"events"`
	} `json:"data"`
}

func getRecentEvents(t *testing.T, srv *Server) recentEventsResponse {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/events/recent", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusOK)
	}
	var resp recentEventsResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response error: %v", err)
	}
	return resp
}

func TestRecentEventsBufferDisabled(t *testing.T) {
	srv := newTestServer()
	srv.Hub().Broadcast(Event{Type: "link_updated"})
	resp := getRecentEvents(t, srv)
	if !resp.OK {
		t.Fatal("response OK should be true with buffering disabled")
	}
	if resp.Data.Events == nil || len(resp.Data.Events) != 0 {
		t.Errorf("events = %+v, want empty list when buffering is disabled", resp.Data.Events)
	}
}

func TestRecentEventsBuffered(t *testing.T) {
	srv := NewServer(testProvider{}, Config{
		Enabled:            true,
		EventBufferSeconds: 60,
	})
	srv.Hub().Broadcast(Event{Type: "link_updated", Payload: map[string]any{"link_ids": []string{"link-a"}}})
	srv.Hub().Broadcast(Event{Type: "peer_updated"})
	resp := getRecentEvents(t, srv)
	if !resp.OK {
		t.Fatal("response OK should be true")
	}
	if len(resp.Data.Events) != 2 {
		t.Fatalf("events len = %d, want 2", len(resp.Data.Events))
	}
	first := resp.Data.Events[0]
	if first.Type != "link_updated" {
		t.Errorf("first event type = %q, want link_updated (ascending order)", first.Type)
	}
	if first.Time == 0 {
		t.Error("event time should be filled by the hub")
	}
	payload, ok := first.Payload.(map[string]any)
	if !ok {
		t.Fatalf("first payload type = %T, want map", first.Payload)
	}
	ids, ok := payload["link_ids"].([]any)
	if !ok || len(ids) != 1 || ids[0] != "link-a" {
		t.Errorf("first payload link_ids = %v, want [link-a]", payload["link_ids"])
	}
	if resp.Data.Events[1].Type != "peer_updated" {
		t.Errorf("second event type = %q, want peer_updated", resp.Data.Events[1].Type)
	}
}

func TestRecentEventsPrunedByTimeWindow(t *testing.T) {
	srv := NewServer(testProvider{}, Config{
		Enabled:            true,
		EventBufferSeconds: 30,
	})
	old := Event{Type: "stale", Time: 1} // far in the past: pruned on next broadcast
	srv.Hub().Broadcast(old)
	srv.Hub().Broadcast(Event{Type: "fresh"})
	resp := getRecentEvents(t, srv)
	if len(resp.Data.Events) != 1 || resp.Data.Events[0].Type != "fresh" {
		t.Errorf("events = %+v, want only [fresh] after window prune", resp.Data.Events)
	}
}
