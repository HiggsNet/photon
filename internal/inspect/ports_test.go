package inspect

import "testing"

func TestRuntimePortSummariesPreserveUnknownValues(t *testing.T) {
	if got := DebugPortGenerationSummary(LinkRotation{RemoteGeneration: 1, StagedGeneration: 2}); got != "-/1/2" {
		t.Fatal(got)
	}
	if got := DebugPortSummary("[2001:db8::1]:4500", "192.0.2.1:30002", "192.0.2.1:30003"); got != "-/4500/30002/30003" {
		t.Fatal(got)
	}
	if got := DebugPortSummary("", "invalid", ""); got != "-/-/-/-" {
		t.Fatal(got)
	}
}
