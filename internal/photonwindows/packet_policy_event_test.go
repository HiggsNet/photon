package photonwindows

import (
	"reflect"
	"testing"
	"time"
)

func TestPacketPolicyCallerFactsOwnEvent(t *testing.T) {
	f := newPipelineFixture(t)
	f.learn(t)
	view := detachedPacketPolicyView(f.view)
	var first, second packetAuthorization
	if !f.p.prepareSnapshotInto(f.config, view, f.plan, f.now, &first) {
		t.Fatal("initial event rejected")
	}
	policy := f.p.policy
	next := f.now.Add(time.Nanosecond)
	if !f.p.prepareSnapshotInto(f.config, view, f.plan, next, &second) || f.p.policy != policy {
		t.Fatal("second event did not use the same signed policy")
	}
	if first.now != f.now || first.plan.EvaluatedAt != f.now || second.now != next || second.plan.EvaluatedAt != next {
		t.Fatal("one event changed another event's evaluation time")
	}
	first.now, first.plan.EvaluatedAt = next.Add(time.Hour), next.Add(time.Hour)
	if second.now != next || second.plan.EvaluatedAt != next || policy.facts.now != f.now {
		t.Fatal("caller facts changed shared policy or another event")
	}
	if !f.p.authorize(&second, f.packet(true), true) {
		t.Fatal("independent event lost its signed route authorization")
	}
	// Live lifecycle changes still invalidate facts that were already prepared.
	f.p.tunnel.generation++
	if f.p.authorize(&second, f.packet(true), true) {
		t.Fatal("caller facts bypassed the current generation gate")
	}
}

func TestPacketPolicyCallerFactsDenialClearsOutput(t *testing.T) {
	for _, scenario := range []string{"config", "expiry", "generation"} {
		t.Run(scenario, func(t *testing.T) {
			f := newPipelineFixture(t)
			f.learn(t)
			view := detachedPacketPolicyView(f.view)
			var facts packetAuthorization
			if !f.p.prepareSnapshotInto(f.config, view, f.plan, f.now, &facts) {
				t.Fatal("initial event rejected")
			}
			config, now := f.config, f.now
			switch scenario {
			case "config":
				config = nil
			case "expiry":
				now = f.p.tunnel.expiresAt
			case "generation":
				f.p.tunnel.generation++
			}
			if f.p.prepareSnapshotInto(config, view, f.plan, now, &facts) ||
				!reflect.DeepEqual(facts, packetAuthorization{}) || f.p.policy != nil ||
				f.p.authorize(&facts, f.packet(true), true) {
				t.Fatal("denied event retained deliverable caller facts")
			}
		})
	}
}

// Isolates event preparation and a real signed Babel route verdict. It uses
// fixture time and an in-memory device, so this is not a throughput benchmark.
func BenchmarkPacketAuthorizationEventWarm(b *testing.B) {
	f := newPipelineFixture(b)
	f.learn(b)
	view := detachedPacketPolicyView(f.view)
	packet := f.packet(true)
	var facts packetAuthorization
	if !f.p.prepareSnapshotInto(f.config, view, f.plan, f.now, &facts) || !f.p.authorize(&facts, packet, true) {
		b.Fatal("signed fixture did not authorize the event")
	}
	policy := f.p.policy
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if !f.p.prepareSnapshotInto(f.config, view, f.plan, f.now, &facts) || !f.p.authorize(&facts, packet, true) {
			b.Fatal("warm signed event rejected")
		}
	}
	if f.p.policy != policy {
		b.Fatal("benchmark did not retain the same valid signed-policy epoch")
	}
}
