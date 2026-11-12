package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	inspecttext "github.com/HiggsNet/photon/internal/inspect/text"
	"github.com/HiggsNet/photon/pkg/firewall"
)

type waitingRuntimeFirewall struct {
	firewall.DryRunDriver
	started chan struct{}
	release chan struct{}
	err     error
}

func (d *waitingRuntimeFirewall) Apply(ctx context.Context, _ *firewall.FirewallDesiredState) (firewall.FirewallApplyResult, error) {
	close(d.started)
	select {
	case <-d.release:
		return firewall.FirewallApplyResult{}, d.err
	case <-ctx.Done():
		return firewall.FirewallApplyResult{}, ctx.Err()
	}
}

func TestRuntimeOperationRemainsQueryableDuringSystemIO(t *testing.T) {
	for _, failed := range []bool{false, true} {
		name := "success"
		if failed {
			name = "failure"
		}
		t.Run(name, func(t *testing.T) {
			verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
			appConfig := defaultAppConfig()
			appConfig.Firewall.Instances = []firewall.FirewallInstanceSpec{{ID: "host", NetNS: "host", IsHost: true, Enabled: true, Mode: firewall.ModeManaged, Backend: firewall.BackendAuto}}
			service := newTestDaemonFromOwners(&testApp{Config: appConfig}, verified, checkpoint, runtime, config, time.Second)
			defer service.Close()
			driver := &waitingRuntimeFirewall{started: make(chan struct{}), release: make(chan struct{})}
			driver.Backend = firewall.BackendNFT
			if failed {
				driver.err = errors.New("injected system failure")
			}
			installTestFirewallDriver(service, driver)
			service.firewallDirty = true
			done := make(chan error, 1)
			finished := make(chan struct{})
			go func() {
				defer close(finished)
				_, err := service.flushFirewallReconcile(t.Context())
				done <- err
			}()
			defer func() { close(driver.release); <-finished }()
			select {
			case <-driver.started:
			case <-time.After(time.Second):
				t.Fatal("system operation did not start")
			}
			revision := service.State.Common.VerifiedRevision()
			cli := controlViewRequestViaPipe[inspect.StatusView](t, service, controlRequest{Method: "status_view"})
			if !cli.OK || cli.View.CurrentOperation == nil {
				t.Fatal("CLI could not inspect the running operation")
			}
			var rendered bytes.Buffer
			if err := inspecttext.WriteStatus(&rendered, cli.View); err != nil || !strings.Contains(rendered.String(), "firewall / apply") {
				t.Fatalf("CLI progress = %q, %v", rendered.String(), err)
			}
			srv := newObserverServer(service, observerConfig{Enabled: true})
			request := httptest.NewRequest("GET", "/api/v1/status", nil)
			response := httptest.NewRecorder()
			srv.Handler().ServeHTTP(response, request)
			var web struct {
				OK   bool                     `json:"ok"`
				Data inspect.DaemonStatusView `json:"data"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &web); err != nil || !web.OK || web.Data.CurrentOperation == nil {
				t.Fatalf("Web progress = %s, %v", response.Body.String(), err)
			}
			operation := web.Data.CurrentOperation
			if operation.Component != "firewall" || operation.Phase != "apply" || !operation.StartedAt.Equal(cli.View.CurrentOperation.StartedAt) || !operation.Deadline.Equal(cli.View.CurrentOperation.Deadline) {
				t.Fatalf("CLI and Web describe different operations: %+v / %+v", cli.View.CurrentOperation, operation)
			}
			if operation.Deadline.Sub(operation.StartedAt) > defaultReconcileOperationTimeout || operation.ElapsedMillis < 0 {
				t.Fatalf("invalid operation timing: %+v", operation)
			}
			if got := service.State.Common.VerifiedRevision(); got != revision {
				t.Fatal("querying runtime progress changed persistent state")
			}
			// Finish explicitly so both success and failure must clear progress.
			driver.release <- struct{}{}
			if err := <-done; !errors.Is(err, driver.err) {
				t.Fatalf("system result = %v, want %v", err, driver.err)
			}
			if service.linuxObservation.operationSnapshot() != nil {
				t.Fatal("completed operation remained visible")
			}
		})
	}
}
