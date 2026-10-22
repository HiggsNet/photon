package photonwindows

import (
	"encoding/json"
	"time"
)

// These are planner diagnostics, not proof of an authenticated or usable SA.
// Keep the original sample time/revision so a previous planner rejection cannot
// be confused with current trust. Never expose transport keys or private data.
type GatewayObservation struct {
	PlanRevision         uint64                        `json:"plan_revision"`
	EvaluatedAt          time.Time                     `json:"evaluated_at"`
	Selected             string                        `json:"selected,omitempty"`
	Rejected             string                        `json:"rejected,omitempty"`
	RevalidationRejected string                        `json:"revalidation_rejected,omitempty"`
	Candidates           []GatewayCandidateObservation `json:"candidates"`
	CandidatesTruncated  bool                          `json:"candidates_truncated"`
}

type GatewayCandidateObservation struct {
	Zone     string `json:"zone"`
	Rejected string `json:"rejected,omitempty"`
}

func observeGatewayPlan(plan, current GatewayPlan) GatewayObservation {
	out := GatewayObservation{
		PlanRevision: uint64(plan.Revision), EvaluatedAt: plan.EvaluatedAt,
		Rejected: boundedObservationText(plan.Rejected), RevalidationRejected: boundedObservationText(current.Rejected),
	}
	if current.Selected != nil {
		out.Selected = boundedObservationText(string(current.Selected.Zone))
	}
	encodedBytes := 2
	for _, candidate := range plan.Candidates {
		if len(out.Candidates) == 256 {
			out.CandidatesTruncated = true
			break
		}
		sample := GatewayCandidateObservation{
			Zone: boundedObservationText(string(candidate.Zone)), Rejected: boundedObservationText(candidate.Rejected),
		}
		encoded, _ := json.Marshal(sample)
		// Account for JSON escaping too, leaving control-frame space for peers,
		// routes and the other detached observations without truncating JSON.
		if encodedBytes+len(encoded)+1 > 128<<10 {
			out.CandidatesTruncated = true
			break
		}
		encodedBytes += len(encoded) + 1
		out.Candidates = append(out.Candidates, sample)
	}
	return out
}

func observedIKEPhase(phase uint8) string {
	switch phase {
	case 0:
		return "idle"
	case 1:
		return "init"
	case 2:
		return "auth"
	case 3:
		return "established"
	default:
		return "unknown"
	}
}
