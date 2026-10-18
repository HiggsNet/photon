//go:build linux

package photonopenwrt

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

type serviceActionFixture struct {
	h                    *Handler
	mu                   sync.Mutex
	doc                  map[string]any
	calls                []string
	queryError, setError bool
	onSet                func()
}

func newServiceActionFixture(t *testing.T) *serviceActionFixture {
	t.Helper()
	h, path, _ := fixture(t)
	if err := os.WriteFile(path, []byte("valid"), 0600); err != nil {
		t.Fatal(err)
	}
	x := &serviceActionFixture{h: h, doc: map[string]any{}}
	h.options.Run = func(_ context.Context, name string, args ...string) ([]byte, error) {
		x.mu.Lock()
		defer x.mu.Unlock()
		x.calls = append(x.calls, name+" "+strings.Join(args, " "))
		if name == "ubus" && slices.Equal(args, []string{"call", "service", "list", serviceActionQuery}) {
			if x.queryError {
				return nil, errors.New("ubus unavailable")
			}
			return json.Marshal(x.doc)
		}
		if name == "ubus" && len(args) == 4 && slices.Equal(args[:3], []string{"call", "service", "set"}) {
			if x.onSet != nil {
				x.onSet()
			}
			if x.setError {
				return nil, errors.New("ubus set rejected")
			}
			var job map[string]any
			if err := json.Unmarshal([]byte(args[3]), &job); err != nil {
				t.Fatal(err)
			}
			if job["name"] != serviceActionName {
				t.Fatal(job)
			}
			instance := job["instances"].(map[string]any)["main"].(map[string]any)
			if _, ok := instance["respawn"]; ok {
				t.Fatal("one-shot task acquired respawn", job)
			}
			command := instance["command"].([]any)
			if len(command) != 2 || command[0] != h.options.InitPath || (command[1] != "stop" && command[1] != "restart") {
				t.Fatal("nonliteral task command", command)
			}
			instance["running"] = true
			delete(job, "name")
			x.doc = map[string]any{serviceActionName: job}
			return []byte(`{}`), nil
		}
		if name == "ubus" {
			return []byte(`{"photon":{"instances":{"main":{"running":false}}}}`), nil
		}
		if name == "uci" && len(args) == 3 && args[0] == "-q" && args[1] == "get" {
			if args[2] == "photon.main.config_file" {
				return []byte(path), nil
			}
			return []byte("1"), nil
		}
		if name == h.options.InitPath && (slices.Equal(args, []string{"stop"}) || slices.Equal(args, []string{"restart"})) {
			t.Fatal("slow init action ran in the RPC process group", args)
		}
		return nil, nil
	}
	return x
}

func (x *serviceActionFixture) finish(exit int) {
	x.mu.Lock()
	defer x.mu.Unlock()
	instance := x.doc[serviceActionName].(map[string]any)["instances"].(map[string]any)["main"].(map[string]any)
	instance["running"], instance["exit_code"] = false, exit
}

func taskSnapshot(t *testing.T, x *serviceActionFixture) map[string]any {
	t.Helper()
	return invoke(t, x.h, "snapshot", map[string]any{})["service"].(map[string]any)["action"].(map[string]any)
}

func TestServiceActionSubmitsThenReportsRealCompletion(t *testing.T) {
	x := newServiceActionFixture(t)
	initial := taskSnapshot(t, x)
	if initial["running"] != false || initial["action"] != "" || initial["exit_code"] != nil {
		t.Fatal(initial)
	}
	reply := invoke(t, x.h, "service", map[string]any{"action": "stop"})
	if reply["ok"] != true || reply["scheduled"] != true || reply["action"] != "stop" {
		t.Fatal(reply)
	}
	state := taskSnapshot(t, x)
	if state["running"] != true || state["action"] != "stop" || state["exit_code"] != nil {
		t.Fatal("submission pretended completion", state)
	}
	x.finish(0)
	state = taskSnapshot(t, x)
	if state["running"] != false || state["exit_code"] != float64(0) || state["error"] != nil {
		t.Fatal(state)
	}
	// A new RPC process reads and validates the inactive procd record, then
	// reuses it. Completion does not depend on any local daemon/job ledger.
	x.h = New(x.h.options)
	reply = invoke(t, x.h, "service", map[string]any{"action": "restart"})
	if reply["ok"] != true || reply["scheduled"] != true {
		t.Fatal(reply)
	}
	if state := taskSnapshot(t, x); state["running"] != true || state["action"] != "restart" {
		t.Fatal(state)
	}
}

func TestServiceActionRejectsAllServiceWritesWhileRunning(t *testing.T) {
	x := newServiceActionFixture(t)
	if reply := invoke(t, x.h, "service", map[string]any{"action": "stop"}); reply["ok"] != true {
		t.Fatal(reply)
	}
	x.calls = nil
	for _, action := range []string{"start", "stop", "restart", "enable", "disable"} {
		if reply := invoke(t, x.h, "service", map[string]any{"action": action}); reply["ok"] != false {
			t.Fatal("active task overwritten", action, reply)
		}
	}
	for _, call := range x.calls {
		if call != "ubus call service list "+serviceActionQuery {
			t.Fatal("active task allowed a write", x.calls)
		}
	}
}

func TestServiceActionFailedCompletionMayRetry(t *testing.T) {
	x := newServiceActionFixture(t)
	if err := x.h.service(t.Context(), "stop"); err != nil {
		t.Fatal(err)
	}
	x.finish(7)
	state := taskSnapshot(t, x)
	if state["running"] != false || state["exit_code"] != float64(7) || state["error"] == nil {
		t.Fatal("failed task hidden", state)
	}
	if err := x.h.service(t.Context(), "stop"); err != nil {
		t.Fatal("finished error permanently blocked retry", err)
	}
}

func TestServiceActionRejectsUnknownOrForeignState(t *testing.T) {
	for _, kind := range []string{"query-error", "null-response", "service-owner", "disabled-autostart", "extra-instance", "command", "extra-argument", "instance-owner", "action-data", "respawn", "respawn-policy", "env", "missing-running", "missing-exit"} {
		t.Run(kind, func(t *testing.T) {
			x := newServiceActionFixture(t)
			if err := x.h.service(t.Context(), "stop"); err != nil {
				t.Fatal(err)
			}
			x.finish(0)
			service := x.doc[serviceActionName].(map[string]any)
			instances := service["instances"].(map[string]any)
			instance := instances["main"].(map[string]any)
			switch kind {
			case "query-error":
				x.queryError = true
			case "null-response":
				x.doc = nil
			case "service-owner":
				service["data"] = map[string]any{"owner": "foreign"}
			case "disabled-autostart":
				service["autostart"] = false
			case "extra-instance":
				instances["other"] = instance
			case "command":
				instance["command"] = []string{"/bin/sh", "stop"}
			case "extra-argument":
				instance["command"] = []string{x.h.options.InitPath, "stop", "foreign"}
			case "instance-owner":
				instance["data"] = map[string]any{"owner": "foreign", "action": "stop"}
			case "action-data":
				instance["data"].(map[string]any)["action"] = "restart"
			case "respawn":
				instance["respawn"] = map[string]any{"retry": 5}
			case "respawn-policy":
				instance["respawn_policy"] = map[string]any{"max_retries": 5}
			case "env":
				instance["env"] = map[string]any{"PHOTON_CONFIG": "foreign"}
			case "missing-running":
				delete(instance, "running")
			case "missing-exit":
				delete(instance, "exit_code")
			}
			x.calls = nil
			if err := x.h.service(t.Context(), "stop"); err == nil {
				t.Fatal("foreign/unknown task was reused")
			}
			for _, call := range x.calls {
				if call != "ubus call service list "+serviceActionQuery {
					t.Fatal("ownership failure mutated service", x.calls)
				}
			}
			state := taskSnapshot(t, x)
			if state["running"] != nil || state["exit_code"] != nil || state["error"] == nil {
				t.Fatal("unknown task pretended completion", state)
			}
		})
	}
}

func TestServiceActionRejectedSubmissionDoesNotReportScheduled(t *testing.T) {
	x := newServiceActionFixture(t)
	x.setError = true
	reply := invoke(t, x.h, "service", map[string]any{"action": "stop"})
	if reply["ok"] != false || reply["scheduled"] != nil || reply["error"] == nil {
		t.Fatal(reply)
	}
	if len(x.doc) != 0 {
		t.Fatal("rejected job appeared running", x.doc)
	}
}

func TestServiceActionRestartValidatesBeforeSubmission(t *testing.T) {
	x := newServiceActionFixture(t)
	x.h.options.Validate = func(string) error { return errors.New("invalid config") }
	if reply := invoke(t, x.h, "service", map[string]any{"action": "restart"}); reply["ok"] != false {
		t.Fatal(reply)
	}
	if len(x.doc) != 0 {
		t.Fatal("invalid restart was submitted", x.doc)
	}
}

func TestServiceActionSubmissionLockPreventsConcurrentOverride(t *testing.T) {
	x := newServiceActionFixture(t)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	x.onSet = func() { close(entered); <-release }
	go func() { done <- x.h.service(context.Background(), "stop") }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("submission did not reach procd")
	}
	other := New(x.h.options)
	err := other.service(t.Context(), "disable")
	close(release)
	if err == nil {
		t.Fatal("concurrent RPC ignored the service action lock")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if state := taskSnapshot(t, x); state["running"] != true || state["action"] != "stop" {
		t.Fatal(state)
	}
}
