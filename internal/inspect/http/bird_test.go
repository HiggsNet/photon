package http

import (
	"encoding/json"
	"testing"

	"github.com/HiggsNet/photon/internal/inspect"
)

func TestBirdResponsePreservesObserverSchema(t *testing.T) {
	got := BirdResponse{
		Instances:          map[string]any{"phx-main": map[string]any{"state": "running"}},
		LastRoutingFailure: &inspect.FailureView{Code: inspect.FailureCodeRoutingReconcile, Message: "bird failed"},
	}
	data, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	failure, _ := decoded["last_routing_failure"].(map[string]any)
	if decoded["instances"] == nil || failure["code"] != inspect.FailureCodeRoutingReconcile || failure["message"] != "bird failed" {
		t.Fatalf("bird response fields missing: %#v", decoded)
	}
}
