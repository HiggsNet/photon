package photonwindows

import "time"

// IKEFailureObservation describes a rejected packet or failed local attempt,
// never an authenticated peer assertion. Historical means the attempt ended or
// subsequently progressed successfully; it is not a current session failure.
type IKEFailureObservation struct {
	Event          string    `json:"event"`
	Message        string    `json:"message"`
	At             time.Time `json:"at"`
	Phase          string    `json:"phase"`
	Gateway        string    `json:"gateway"`
	RemoteEndpoint string    `json:"remote_endpoint"`
	Generation     uint64    `json:"generation"`
	Historical     bool      `json:"historical"`
}

// Owned by the existing tunnel event loop, alongside its retransmission state.
// This contains no packets, keys, independently refreshed state or persistence.
type tunnelDiagnostic struct {
	gateway, remote string
	generation      uint64
	lastEvent       string
	lastEventAt     time.Time
	retryAt         time.Time
	failure         *IKEFailureObservation
	rejection       *IKEFailureObservation
}

func (t *gatewayTunnel) observeEvent(event string, now time.Time, err error) {
	if t.phase != 0 && t.plan.Selected != nil {
		t.diagnostic.gateway = boundedObservationText(string(t.plan.Selected.Zone))
		t.diagnostic.remote = t.peer.String()
		t.diagnostic.generation = t.generation
	}
	t.diagnostic.lastEvent, t.diagnostic.lastEventAt = event, now
	if err != nil {
		t.diagnostic.failure = &IKEFailureObservation{Event: event, Message: boundedObservationText(err.Error()), At: now, Phase: observedIKEPhase(t.phase), Gateway: t.diagnostic.gateway, RemoteEndpoint: t.diagnostic.remote, Generation: t.diagnostic.generation}
		if event == "packet_rejected" {
			copy := *t.diagnostic.failure
			t.diagnostic.rejection = &copy
		}
	}
}

func (t *gatewayTunnel) observeProgress() {
	if t.diagnostic.failure != nil {
		t.diagnostic.failure.Historical = true
	}
	if t.diagnostic.rejection != nil {
		t.diagnostic.rejection.Historical = true
	}
}

func (t *gatewayTunnel) observeIKE() IKEObservation {
	out := IKEObservation{Phase: observedIKEPhase(t.phase), AttemptActive: t.phase != 0, AttemptGateway: t.diagnostic.gateway, AttemptRemoteEndpoint: t.diagnostic.remote, AttemptGeneration: t.diagnostic.generation, RetryAt: t.diagnostic.retryAt, LastEvent: t.diagnostic.lastEvent, LastEventAt: t.diagnostic.lastEventAt}
	if t.phase != 0 {
		if t.plan.Selected != nil {
			out.AttemptGateway = boundedObservationText(string(t.plan.Selected.Zone))
		}
		out.AttemptRemoteEndpoint, out.AttemptGeneration = t.peer.String(), t.generation
		if len(t.pending) != 0 {
			out.SendAttempts, out.NextRetransmitAt = t.attempts, t.retryAt
		}
	}
	if t.diagnostic.failure != nil {
		copy := *t.diagnostic.failure
		out.LastFailure = &copy
	}
	if t.diagnostic.rejection != nil {
		copy := *t.diagnostic.rejection
		out.LastRejection = &copy
	}
	return out
}
