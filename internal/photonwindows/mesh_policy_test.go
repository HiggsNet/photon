package photonwindows

import (
	"net"
	"testing"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

func TestMeshPolicyPendingAndLateResult(t *testing.T) {
	config, view, now, _ := gatewayPlanFixture(t)
	hint := planGateway(t.Context(), config, view, now, meshPolicyFixtureResolver())
	if hint.Selected == nil {
		t.Fatal("test requires a current planner hint", hint.Rejected)
	}

	worker := newMeshPolicyWorker(nil)
	peer := &meshPeer{config: *config, plan: hint}
	for range 2 {
		if got, pending := worker.project(peer, view.Revision, now); got != nil || !pending {
			t.Fatalf("uncomputed policy got=%v pending=%v", got, pending)
		}
	}
	if len(worker.requests) != 1 {
		t.Fatal("duplicate request while policy worker is pending")
	}
	first := <-worker.requests
	worker.finish(meshPolicyResult{request: first, projection: &meshPolicyProjection{
		request: first, deadline: now.Add(time.Second), lastWall: now,
	}}, view.Revision+1, now)
	if peer.policy.current != nil {
		t.Fatal("completion from an obsolete verified revision was published")
	}
	if got, pending := worker.project(peer, view.Revision+1, now); got != nil || !pending {
		t.Fatalf("obsolete policy got=%v pending=%v", got, pending)
	}
	second := <-worker.requests
	projection := &meshPolicyProjection{request: second, deadline: now.Add(time.Second), lastWall: now}
	worker.finish(meshPolicyResult{request: second, projection: projection}, view.Revision+1, now)
	peer.plan.EvaluatedAt = now.Add(time.Millisecond)
	peer.plan.Revision = view.Revision + 1
	if got, pending := worker.project(peer, view.Revision+1, now.Add(2*time.Millisecond)); got != projection || pending {
		t.Fatalf("equivalent planner refresh got=%v pending=%v", got, pending)
	}
	if got, pending := worker.project(peer, view.Revision+1, now.Add(time.Second)); got != nil || !pending {
		t.Fatalf("policy survived exact expiry got=%v pending=%v", got, pending)
	}
}

func TestMeshPolicyWorkerSettlesDeniedLocalBinding(t *testing.T) {
	config, view, now, _ := gatewayPlanFixture(t)
	hint := planGateway(t.Context(), config, view, now, meshPolicyFixtureResolver())
	if hint.Selected == nil {
		t.Fatal("test requires a current planner hint", hint.Rejected)
	}
	store := corestate.NewStore(view.State, nil, nil)
	revision := store.VerifiedRevision()
	defer store.Close()
	worker := newMeshPolicyWorker(store)
	go worker.run(t.Context())
	peer := &meshPeer{config: *config, plan: hint}
	if projection, pending := worker.project(peer, revision, now); projection != nil || !pending {
		t.Fatalf("initial policy got=%v pending=%v", projection, pending)
	}
	select {
	case result := <-worker.results:
		at := time.Now()
		worker.finish(result, revision, at)
		projection, pending := worker.project(peer, revision, at)
		if projection == nil || pending || projection.plan.Selected != nil || projection.attachmentErr == nil {
			t.Fatalf("missing local signed transport unexpectedly allowed: %v pending=%v", projection, pending)
		}
	case <-time.After(time.Second):
		t.Fatal("policy worker did not return")
	}
}

func meshPolicyFixtureResolver() gatewayResolvedHosts {
	return gatewayResolvedHosts{"gateway.example": {{IP: net.IPv4(192, 0, 2, 1)}}}
}

func TestMeshPolicyProjectionPinsInstalledSAAndStoreRevision(t *testing.T) {
	f := runtimeFixture(t)
	store := corestate.NewStore(f.view.State, nil, nil)
	defer store.Close()
	view := store.ReadView()
	peer := &meshPeer{config: *f.config, plan: f.plan}
	worker := newMeshPolicyWorker(store)
	if _, pending := worker.project(peer, view.Revision, f.now); !pending {
		t.Fatal("signed projection must be prepared by the worker")
	}
	request := <-worker.requests
	var inputs meshPolicyInputs
	projected := inputs.project(request, view, f.now)
	worker.finish(meshPolicyResult{request: request, projection: projected}, view.Revision, f.now)
	projection, pending := worker.project(peer, view.Revision, f.now)
	if pending || projection == nil || projection.attachmentErr != nil {
		t.Fatalf("signed attachment unavailable: %+v pending=%v", projection, pending)
	}
	f.p.local, f.p.peer = projection.attachment.local, projection.attachment.peer
	var facts packetAuthorization
	if !projection.packetFacts(f.p, f.now, &facts) {
		t.Fatal("signed projection rejected its pinned installed SA")
	}
	facts.revision++
	if f.p.preparedCurrent(&facts) {
		t.Fatal("final packet gate accepted facts pinned to another published revision")
	}
}

func TestMeshPolicyDeadlineKeepsMonotonicDelegationBoundary(t *testing.T) {
	config, view, _, _ := gatewayPlanFixture(t)
	now := time.Now()
	expiry := now.Add(50 * time.Millisecond)
	view.State.Network.Zones[config.Gateway.AllowedZones[0]].ParentProof = []*zone.Delegation{{ExpiresAt: &expiry}}
	var monotonic time.Time
	wall := packetPolicyDeadlineWithMonotonic(view, now, &monotonic)
	if monotonic != expiry || !wall.After(expiry.Round(0)) {
		t.Fatalf("deadline wall=%s monotonic=%s, want monotonic %s", wall, monotonic, expiry)
	}
}
