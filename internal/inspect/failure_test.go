package inspect

import (
	"errors"
	"testing"
)

func TestBuildFailureMapsErrorAtInspectBoundary(t *testing.T) {
	failure := BuildFailure(FailureCodeRoutingReconcile, errors.New("bird unavailable"))
	if failure == nil || failure.Code != FailureCodeRoutingReconcile || failure.Message != "bird unavailable" {
		t.Fatalf("failure = %+v", failure)
	}
	if BuildFailure(FailureCodeRoutingReconcile, nil) != nil {
		t.Fatal("nil error must not produce a failure view")
	}
	if got := BuildFailure("", errors.New("boom")); got.Code != "unknown" {
		t.Fatalf("empty code = %q, want unknown", got.Code)
	}
}
