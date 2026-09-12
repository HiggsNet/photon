package inspect

const (
	FailureCodeIPsecReconcile    = "ipsec_reconcile_failed"
	FailureCodeRoutingReconcile  = "routing_reconcile_failed"
	FailureCodeFirewallReconcile = "firewall_reconcile_failed"
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
