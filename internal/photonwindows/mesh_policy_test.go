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

func TestMeshPolicyProjectionPinsInstalledSAAndPolicy(t *testing.T) {
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
	next := view.Revision + 1
	continued, pending := worker.project(peer, next, f.now)
	if !pending || continued != projection || !f.p.preparedCurrent(&facts) {
		t.Fatal("new revision interrupted installed ESP policy before verification settled")
	}
	replacement := <-worker.requests
	denial := &meshPolicyProjection{
		request: replacement, deadline: f.now.Add(time.Minute), lastWall: f.now,
		plan: GatewayPlan{Rejected: "verified authorization withdrawn"},
	}
	worker.finish(meshPolicyResult{request: replacement, projection: denial}, next, f.now)
	if f.p.preparedCurrent(&facts) {
		t.Fatal("final packet gate retained facts from before verified denial")
	}
	if result, pending := worker.project(peer, next, f.now); result != denial || pending {
		t.Fatal("verified denial did not replace installed policy")
	}
}

func TestMeshPolicyDeadlineKeepsMonotonicDelegationBoundary(t *testing.T) {
	config, view, _, _ := gatewayPlanFixture(t)
	now := time.Now()
	expiry := now.Add(50 * time.Millisecond)
	view.State.Network.Zones[config.Gateway.AllowedZones[0]].ParentProof = []*zone.Delegation{{ExpiresAt: &expiry}}
	var monotonic time.Time
	wall := meshPolicySignedDeadline(view, now, &monotonic)
	if monotonic != expiry || !wall.After(expiry.Round(0)) {
		t.Fatalf("deadline wall=%s monotonic=%s, want monotonic %s", wall, monotonic, expiry)
	}
}

func TestMeshPolicyRevisionGraceDoesNotExtendOrOverrideExpiry(t *testing.T) {
	for _, test := range []struct {
		name     string
		deadline time.Duration
		change   func(*meshPeer)
		checkAt  time.Duration
	}{
		{name: "grace", deadline: time.Minute, checkAt: meshPolicyRevisionGrace},
		{name: "known expiry", deadline: time.Second, checkAt: time.Second},
		{name: "changed hint", deadline: time.Minute, checkAt: time.Second,
			change: func(p *meshPeer) { p.plan.Selected.Contact.Address = "192.0.2.2" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			config, view, now, _ := gatewayPlanFixture(t)
			hint := planGateway(t.Context(), config, view, now, meshPolicyFixtureResolver())
			if hint.Selected == nil {
				t.Fatal("test requires a current planner hint", hint.Rejected)
			}
			peer := &meshPeer{config: *config, plan: hint}
			worker := newMeshPolicyWorker(nil)
			worker.project(peer, view.Revision, now)
			request := <-worker.requests
			installed := &meshPolicyProjection{
				request: request, deadline: now.Add(test.deadline), lastWall: now, plan: hint,
			}
			worker.finish(meshPolicyResult{request: request, projection: installed}, view.Revision, now)

			if got, pending := worker.project(peer, view.Revision+1, now); got != installed || !pending {
				t.Fatalf("expected existing ESP policy while refresh pending, got=%v pending=%t", got, pending)
			}
			newer := <-worker.requests
			worker.finish(meshPolicyResult{request: newer, projection: &meshPolicyProjection{
				request: newer, deadline: now.Add(time.Minute), lastWall: now, plan: hint,
			}}, view.Revision+2, now.Add(time.Millisecond))
			// A later revision must not extend the grace or install an older result.
			if got, pending := worker.project(peer, view.Revision+2, now.Add(2*time.Millisecond)); got != installed || !pending {
				t.Fatalf("stale result replaced the original installed policy: got=%v pending=%t", got, pending)
			}
			if test.change != nil {
				test.change(peer)
			}
			if test.name == "grace" {
				// Keep the equivalent DNS hint fresh so the grace is the
				// boundary under test, rather than the hint's own lifetime.
				peer.plan.EvaluatedAt = now.Add(test.checkAt - time.Second)
				if got, pending := worker.project(peer, view.Revision+2, peer.plan.EvaluatedAt); got != installed || !pending {
					t.Fatalf("installed policy expired before grace ended: got=%v pending=%t", got, pending)
				}
			}
			if got, pending := worker.project(peer, view.Revision+2, now.Add(test.checkAt)); got != nil || !pending {
				t.Fatalf("installed policy survived validity boundary: got=%v pending=%t", got, pending)
			}
		})
	}
}

func TestMeshPolicySoftRefreshDoesNotInterruptInstalledPolicy(t *testing.T) {
	config, view, now, _ := gatewayPlanFixture(t)
	hint := planGateway(t.Context(), config, view, now, meshPolicyFixtureResolver())
	if hint.Selected == nil {
		t.Fatal("test requires a current planner hint", hint.Rejected)
	}
	peer := &meshPeer{config: *config, plan: hint}
	worker := newMeshPolicyWorker(nil)
	worker.project(peer, view.Revision, now)
	request := <-worker.requests
	installed := &meshPolicyProjection{request: request, plan: hint, lastWall: now, refreshAt: now.Add(time.Second)}
	worker.finish(meshPolicyResult{request: request, projection: installed}, view.Revision, now)

	soft := installed.refreshAt
	if got, pending := worker.project(peer, view.Revision, soft); got != installed || pending || len(worker.requests) != 1 {
		t.Fatalf("soft refresh interrupted settled policy or was not queued: got=%v pending=%t", got, pending)
	}
	refresh := <-worker.requests
	refreshResult := &meshPolicyProjection{request: refresh, plan: hint, lastWall: soft, refreshAt: soft.Add(time.Minute)}
	if got, pending := worker.project(peer, view.Revision+1, soft); got != installed || !pending {
		t.Fatalf("new revision during soft refresh lost original policy: got=%v pending=%t", got, pending)
	}
	worker.finish(meshPolicyResult{request: refresh, projection: refreshResult}, view.Revision+1, soft)
	if peer.policy.current != installed {
		t.Fatal("obsolete soft refresh replaced installed policy")
	}
}

func TestMeshPolicySignedDeadlineIsIndependentOfSoftAge(t *testing.T) {
	now := time.Unix(10_000, 0)
	network := zone.NewNetworkState()
	view := corestate.View{State: &corestate.VerifiedState{Network: network}}
	var monotonic time.Time
	if hard := meshPolicySignedDeadline(view, now, &monotonic); !hard.IsZero() {
		t.Fatalf("no signed transition, got hard deadline %s", hard)
	}
	root := zone.NewZoneState(zone.RootZone, nil)
	network.Zones[zone.RootZone] = root
	future := now.Add(2 * packetPolicyMaxAge)
	root.Revocations["child."] = &zone.DelegationRevocation{RevokedAt: future.Unix()}
	if hard := meshPolicySignedDeadline(view, now, &monotonic); !hard.Equal(future) {
		t.Fatalf("hard deadline = %s, want exact revocation time %s", hard, future)
	}
	if deadline := packetPolicyDeadline(view, now); !deadline.Equal(now.Add(packetPolicyMaxAge)) {
		t.Fatalf("ordinary synchronous cache interval changed: %s", deadline)
	}
}
