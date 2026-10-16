package photonwindows

import (
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestGatewayObservationBoundsDetachesAndExcludesTransportKey(t *testing.T) {
	plan := GatewayPlan{Revision: 17, EvaluatedAt: time.Unix(1000, 0), Rejected: strings.Repeat("x", 300)}
	for range 300 {
		plan.Candidates = append(plan.Candidates, GatewayCandidate{Zone: zone.ZonePath(strings.Repeat("z", 300)), Rejected: strings.Repeat("r", 300), PublicKey: []byte("public-key-not-needed-for-diagnosis")})
	}
	out := observeGatewayPlan(plan, GatewayPlan{Rejected: "no current gateway"})
	plan.Candidates[0].Rejected = "changed"
	if out.PlanRevision != 17 || !out.EvaluatedAt.Equal(plan.EvaluatedAt) || len(out.Candidates) == 0 || len(out.Candidates) > 256 || !out.CandidatesTruncated || len(out.Rejected) > 256 || out.RevalidationRejected != "no current gateway" {
		t.Fatalf("unbounded or mislabeled gateway sample: revision=%d entries=%d truncated=%t", out.PlanRevision, len(out.Candidates), out.CandidatesTruncated)
	}
	if len(out.Candidates[0].Zone) > 256 || len(out.Candidates[0].Rejected) > 256 || out.Candidates[0].Rejected == "changed" {
		t.Fatal("gateway candidate sample is unbounded or aliases owner state")
	}
	data, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "public_key") || strings.Contains(string(data), "public-key-not-needed") {
		t.Fatal("diagnostic sample exposed unneeded key material")
	}
}

func TestGatewayObservationDoesNotPromoteOldSelectionAfterRevocation(t *testing.T) {
	config, view, now, _ := gatewayPlanFixture(t)
	plan := planGatewaySelection(t.Context(), config, view, now, gatewayResolvedHosts{"gateway.example": {{IP: net.ParseIP("192.0.2.4")}}}, nil)
	if plan.Selected == nil {
		t.Fatalf("fixture did not select a signed gateway: %+v", plan)
	}
	delete(view.State.Network.Zones[plan.Selected.Zone].Records, ipsec.RecordKeyTransportKey)
	view.Revision = corestate.VerifiedRevision(uint64(view.Revision) + 1)
	current := revalidateActiveGateway(config, view, plan, now.Add(time.Second))
	out := observeGatewayPlan(plan, current)
	if out.Selected != "" || out.RevalidationRejected == "" || len(out.Candidates) == 0 || !out.EvaluatedAt.Equal(plan.EvaluatedAt) {
		t.Fatalf("old planner selection was promoted to current gateway: %+v", out)
	}
}

func TestGatewayObservationBoundsEncodedEscapedCandidates(t *testing.T) {
	plan := GatewayPlan{}
	for range 256 {
		plan.Candidates = append(plan.Candidates, GatewayCandidate{Zone: zone.ZonePath(strings.Repeat("\x01", 256)), Rejected: strings.Repeat("\x02", 256)})
	}
	out := observeGatewayPlan(plan, GatewayPlan{})
	encoded, err := json.Marshal(out.Candidates)
	if err != nil || !out.CandidatesTruncated || len(out.Candidates) == 0 || len(encoded) > 128<<10 {
		t.Fatalf("escaped candidates exceed frame budget: entries=%d bytes=%d truncated=%t error=%v", len(out.Candidates), len(encoded), out.CandidatesTruncated, err)
	}
}

func TestRuntimeObservationDistinguishesGatewayPlanFromAuthenticatedSA(t *testing.T) {
	f, leaf := observationFixture(t)
	f.p.tunnel.phase = 2
	out := observeRuntime(f.config, f.view, f.plan, f.now, f.p.tunnel.socket, f.p.tunnel, leaf, nil)
	if out.IKE.Phase != "auth" || out.IKE.Live || out.IKE.ChildLive || out.Babel.Live || out.Babel.Local.IsValid() || out.TunnelReady || out.Gateway.Selected == "" {
		t.Fatalf("planner selection was presented as authenticated control plane: %+v", out)
	}
}
