package inspect

const (
	FailureCodeIPsecReconcile    = "ipsec_reconcile_failed"
	FailureCodeIPsecLink         = "ipsec_link_failed"
	FailureCodeIPsecTakeover     = "ipsec_takeover_failed"
	FailureCodeRoutingReconcile  = "routing_reconcile_failed"
	FailureCodeBirdInstance      = "bird_instance_failed"
	FailureCodeBirdQuery         = "bird_query_failed"
	FailureCodeFirewallReconcile = "firewall_reconcile_failed"
	FailureCodeFirewallInstance  = "firewall_instance_failed"
	FailureCodeHealthProbe       = "health_probe_failed"
	FailureCodeGossipObjectPull  = "gossip_object_pull_failed"
	FailureCodeBirdFilter        = "bird_filter_failed"
	FailureCodeServiceRecord     = "service_record_invalid"
	FailureCodeRevocationCleanup = "revocation_cleanup_failed"
)

// FailureView is the canonical inspect representation of a process-local
// failure. Code is stable for automation; Message is diagnostic text.
type FailureView struct {
	Code    string `json:"code"`
	Message string `json:"message,omitempty"`
}

func BuildFailure(code string, err error) *FailureView {
	if err == nil {
		return nil
	}
	if code == "" {
		code = "unknown"
	}
	return &FailureView{Code: code, Message: err.Error()}
}
