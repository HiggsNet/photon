package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/photonlinux"

	"github.com/HiggsNet/photon/internal/inspect"
	"github.com/HiggsNet/photon/internal/observer"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/firewall"
)

func TestFirewallObservationDoesNotAdvancePersistentRevision(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	summary := &firewall.FirewallObservation{
		Backend:     firewall.BackendNone,
		LastRunUnix: 200,
		Instances: map[string]*firewall.FirewallInstanceObservation{
			"overlay": {Backend: firewall.BackendNone, Generation: 1, LastRunUnix: 200, PolicyHash: "same"},
		},
	}
	rt := &AppContext{Config: defaultAppConfig()}
	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, config, time.Second)
	rev := uint64(service.State.Common.VerifiedRevision())
	service.publishFirewallObservation(rev, summary)
	if got := uint64(service.State.Common.VerifiedRevision()); got != rev {
		t.Fatalf("firewall observation revision = %d, want unchanged %d", got, rev)
	}
	got := service.linuxObservation.firewallSnapshot()
	if got == nil || got.LastRunUnix != 200 || got.Instances["overlay"].PolicyHash != "same" {
		t.Fatalf("firewall observation = %+v", got)
	}
	summary.Instances["overlay"].PolicyHash = "mutated-input"
	got.Instances["overlay"].PolicyHash = "mutated-snapshot"
	if latest := service.linuxObservation.firewallSnapshot(); latest.Instances["overlay"].PolicyHash != "same" {
		t.Fatalf("firewall observation shares mutable entries: %+v", latest)
	}
}

func TestParseConfigYAMLFirewallOverlay(t *testing.T) {
	config := defaultAppConfig()
	input := `
netns:
  default:
    kind: name
    name: photontesth2
    create: true
    forwarding:
      transit: false
      allow_prefixes:
        - 10.42.0.0/16
firewall:
  instances:
    - id: photontesth2
      netns: photontesth2
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	if len(config.Firewall.Instances) != 1 {
		t.Fatalf("expected 1 firewall instance, got %d", len(config.Firewall.Instances))
	}
	inst := config.Firewall.Instances[0]
	policy := config.Netns.ForwardingPolicy(inst.NetNS)
	if policy.Transit {
		t.Error("transit should be false")
	}
	if len(policy.AllowPrefixes) != 1 {
		t.Errorf("allow_prefixes len = %d, want 1", len(policy.AllowPrefixes))
	}
}

func TestParseConfigYAMLFirewallInlineHooksRejectsBothFamily(t *testing.T) {
	config := defaultAppConfig()
	input := `
netns:
  default:
    kind: name
    name: photon
firewall:
  instances:
    - id: photon
      iptables_hooks:
        both:
          pre_input:
            - '-j ACCEPT'
`
	err := parseConfigYAML(input, config)
	if err == nil || !strings.Contains(err.Error(), "field both not found") {
		t.Fatalf("parseConfigYAML error = %v, want strict rejection of both", err)
	}
}

func TestParseConfigYAMLFirewallRejectsRemovedExternalChainHooks(t *testing.T) {
	config := defaultAppConfig()
	err := parseConfigYAML(`
netns:
  default:
    kind: name
    name: photon
firewall:
  instances:
    - id: photon
      hooks:
        pre_input: admin_input
`, config)
	if err == nil || !strings.Contains(err.Error(), "field hooks not found") {
		t.Fatalf("parseConfigYAML error = %v, want strict rejection of removed hooks", err)
	}
}

func TestParseConfigYAMLFirewallOverlayDefaultsToDefaultNetNS(t *testing.T) {
	config := defaultAppConfig()
	input := `
netns:
  default:
    kind: name
    name: photontesth2
    create: true
firewall:
  instances:
    - id: photontesth2
      mode: managed
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	if len(config.Firewall.Instances) != 1 {
		t.Fatalf("expected 1 firewall instance, got %d", len(config.Firewall.Instances))
	}
	inst := config.Firewall.Instances[0]
	if inst.NetNS != "default" {
		t.Fatalf("NetNS = %s, want default", inst.NetNS)
	}
	if inst.IsHost {
		t.Fatal("defaulted netns instance should not be host")
	}
}

func TestParseConfigYAMLFirewallHostDefaultsForIPsecRange(t *testing.T) {
	config := defaultAppConfig()
	input := `
ipsec:
  port_mode: range
  port_range:
    from: 30000
    to: 30099
firewall:
  instances:
    - id: host-ipsec
      host: true
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	if len(config.Firewall.Instances) != 1 {
		t.Fatalf("expected 1 firewall instance, got %d", len(config.Firewall.Instances))
	}
	inst := config.Firewall.Instances[0]
	if !inst.HostPorts.IKE || !inst.HostPorts.NATT {
		t.Fatalf("range mode host ports = %+v, want IKE/NATT enabled by default", inst.HostPorts)
	}
	if !inst.RedirectGrace.Enabled {
		t.Fatal("range mode should enable redirect_grace by default")
	}
}

func TestParseConfigYAMLFirewallHostRangeDefaultsCanBeDisabled(t *testing.T) {
	config := defaultAppConfig()
	input := `
ipsec:
  port_mode: range
  port_range:
    from: 30000
    to: 30099
firewall:
  instances:
    - id: host-ipsec
      host: true
      host_ports:
        ike: false
        natt: false
      redirect_grace:
        disabled: true
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	inst := config.Firewall.Instances[0]
	if inst.HostPorts.IKE || inst.HostPorts.NATT {
		t.Fatalf("explicit host port disables ignored: %+v", inst.HostPorts)
	}
	if inst.RedirectGrace.Enabled {
		t.Fatal("explicit redirect_grace disabled should override range default")
	}
}

func TestParseConfigYAMLFirewallUnknownNetns(t *testing.T) {
	config := defaultAppConfig()
	input := `
firewall:
  instances:
    - id: photontesth2
      netns: nonexistent
`
	if err := parseConfigYAML(input, config); err == nil || !strings.Contains(err.Error(), `netns "nonexistent" not found`) {
		t.Errorf("expected unknown netns error, got %v", err)
	}
}

func TestParseConfigYAMLFirewallRejectsIndependentUpstreamPattern(t *testing.T) {
	config := defaultAppConfig()
	input := `
netns:
  default:
    kind: name
    name: photon
firewall:
  instances:
    - id: photon
      upstream_patterns: ["phv*"]
`
	err := parseConfigYAML(input, config)
	if err == nil || !strings.Contains(err.Error(), "upstream_patterns") {
		t.Fatalf("error = %v, want upstream_patterns rejected; configure routing.instances[].upstream.mesh.interface", err)
	}
}

func TestReconcileFirewall_NoInstances(t *testing.T) {
	d := &Daemon{
		State: newState(nil, corestate.NewStore(&corestate.VerifiedState{}, nil), &photonlinux.LinuxState{}),
		App:   &AppContext{Config: &appConfig{}},
	}
	if err := d.reconcileFirewall(context.Background()); err != nil {
		t.Fatalf("reconcileFirewall with no instances: %v", err)
	}
}

type captureFirewallOwnerDriver struct {
	firewall.DryRunDriver
	owners  []firewall.Owner
	onApply func()
}

func (d *captureFirewallOwnerDriver) ListOwned(ctx context.Context, owner firewall.Owner) (firewall.FirewallObservedState, error) {
	d.owners = append(d.owners, owner)
	return firewall.FirewallObservedState{}, nil
}

func (d *captureFirewallOwnerDriver) Apply(ctx context.Context, plan firewall.FirewallPlan, desired *firewall.FirewallDesiredState) (firewall.FirewallApplyResult, error) {
	if d.onApply != nil {
		d.onApply()
	}
	return d.DryRunDriver.Apply(ctx, plan, desired)
}

type blockingFirewallDriver struct {
	firewall.DryRunDriver
	started chan struct{}
	unblock chan struct{}
}

func (d *blockingFirewallDriver) Apply(ctx context.Context, plan firewall.FirewallPlan, desired *firewall.FirewallDesiredState) (firewall.FirewallApplyResult, error) {
	close(d.started)
	select {
	case <-d.unblock:
	case <-ctx.Done():
		return firewall.FirewallApplyResult{}, ctx.Err()
	}
	return d.DryRunDriver.Apply(ctx, plan, desired)
}

func TestReconcileFirewallUsesScopeForOwnedObjects(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	appConfig := defaultAppConfig()
	appConfig.Firewall.Instances = []firewall.FirewallInstanceSpec{
		{
			ID:            "photon",
			NetNS:         "default",
			Enabled:       true,
			Mode:          firewall.ModeManaged,
			Backend:       firewall.BackendNone,
			DefaultPolicy: firewall.DefaultPolicyDrop,
		},
		{
			ID:        "host-ipsec",
			NetNS:     "host",
			IsHost:    true,
			Enabled:   true,
			Mode:      firewall.ModeManaged,
			Backend:   firewall.BackendNone,
			HostPorts: firewall.HostPortConfig{IKE: true, NATT: true},
		},
	}
	rt := &AppContext{
		Config: appConfig,
		Clock:  func() time.Time { return time.Unix(7000, 0) },
	}
	driver := &captureFirewallOwnerDriver{}
	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, config, time.Second)
	installTestFirewallDriver(service, driver)
	if err := service.reconcileFirewall(context.Background()); err != nil {
		t.Fatalf("reconcileFirewall: %v", err)
	}
	if len(driver.owners) != 2 {
		t.Fatalf("owners = %+v, want two instances", driver.owners)
	}
	if driver.owners[0].InstanceID != "default" {
		t.Fatalf("overlay owner scope = %q, want default", driver.owners[0].InstanceID)
	}
	if driver.owners[1].InstanceID != "host" {
		t.Fatalf("host owner scope = %q, want host", driver.owners[1].InstanceID)
	}
}

func TestLongFirewallReconcileDoesNotBlockCommittedReaders(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	appConfig := defaultAppConfig()
	appConfig.Observer.Enabled = true
	appConfig.Firewall.Instances = []firewall.FirewallInstanceSpec{{
		ID:            "photontesth2",
		NetNS:         "photontesth2",
		Enabled:       true,
		Mode:          firewall.ModeManaged,
		Backend:       firewall.BackendNone,
		DefaultPolicy: firewall.DefaultPolicyDrop,
	}}
	rt := &AppContext{
		Config: appConfig,
		Clock:  func() time.Time { return time.Unix(7020, 0) },
	}
	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, config, time.Second)
	driver := &blockingFirewallDriver{
		started: make(chan struct{}),
		unblock: make(chan struct{}),
	}
	installTestFirewallDriver(service, driver)

	done := make(chan error, 1)
	go func() {
		done <- service.reconcileFirewall(context.Background())
	}()
	select {
	case <-driver.started:
	case <-time.After(time.Second):
		close(driver.unblock)
		t.Fatal("firewall reconcile did not enter blocking apply")
	}

	committedRev := uint64(service.State.Common.VerifiedRevision())
	statusDone := make(chan controlViewResponse[inspect.DaemonStatusView], 1)
	go func() {
		statusDone <- controlViewRequestViaPipe[inspect.DaemonStatusView](t, service, controlRequest{Method: "daemon_status_view"})
	}()
	select {
	case status := <-statusDone:
		if !status.OK || status.View.StateRevision != committedRev {
			close(driver.unblock)
			t.Fatalf("status response = %#v, want committed revision %d", status, committedRev)
		}
	case <-time.After(time.Second):
		close(driver.unblock)
		t.Fatal("control status blocked behind firewall reconcile apply")
	}

	srv := newObserverServer(service, appConfig.Observer)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	rr := httptest.NewRecorder()
	observerDone := make(chan struct{})
	go func() {
		srv.handler().ServeHTTP(rr, req)
		close(observerDone)
	}()
	select {
	case <-observerDone:
		if rr.Code != http.StatusOK {
			close(driver.unblock)
			t.Fatalf("observer status code = %d, want %d; body=%s", rr.Code, http.StatusOK, rr.Body.String())
		}
		var resp observer.APIResponse
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			close(driver.unblock)
			t.Fatalf("decode observer status: %v", err)
		}
		data := resp.Data.(map[string]any)
		if data["state_revision"] != float64(committedRev) {
			close(driver.unblock)
			t.Fatalf("observer status data = %#v, want committed revision %d", data, committedRev)
		}
	case <-time.After(time.Second):
		close(driver.unblock)
		t.Fatal("observer status blocked behind firewall reconcile apply")
	}

	close(driver.unblock)
	if err := <-done; err != nil {
		t.Fatalf("reconcileFirewall: %v", err)
	}
}

func TestReconcileFirewallStaleCommitPreservesNewRevision(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	appConfig := defaultAppConfig()
	appConfig.Firewall.Instances = []firewall.FirewallInstanceSpec{{
		ID:            "photontesth2",
		NetNS:         "photontesth2",
		Enabled:       true,
		Mode:          firewall.ModeManaged,
		Backend:       firewall.BackendNone,
		DefaultPolicy: firewall.DefaultPolicyDrop,
	}}
	rt := &AppContext{
		Config: appConfig,
		Clock:  func() time.Time { return time.Unix(7010, 0) },
	}
	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, config, time.Second)
	baseRev := uint64(service.State.Common.VerifiedRevision())
	driver := &captureFirewallOwnerDriver{}
	driver.onApply = func() {
		if _, err := advanceTestVerifiedRevision(service.State.Common, time.Unix(7010, 1)); err != nil {
			t.Fatalf("advance state revision during firewall apply: %v", err)
		}
		driver.onApply = nil
	}
	installTestFirewallDriver(service, driver)

	if err := service.reconcileFirewall(context.Background()); err != nil {
		t.Fatalf("reconcileFirewall: %v", err)
	}
	if !service.firewallDirty {
		t.Fatal("firewallDirty = false, want stale firewall summary commit to schedule another reconcile")
	}
	common := service.State.Common.ReadView()
	rev := uint64(common.Revision)
	if rev != baseRev+1 {
		t.Fatalf("state revision = %d, want only external update at %d", rev, baseRev+1)
	}
	if observation := service.linuxObservation.firewallSnapshot(); observation != nil {
		t.Fatalf("firewall observation = %+v, want stale summary discarded", observation)
	}
}

func TestFirewallReconcileDirtyIntervalAndRecover(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	appConfig := defaultAppConfig()
	appConfig.Firewall.Instances = []firewall.FirewallInstanceSpec{{
		ID:            "photontesth2",
		NetNS:         "photontesth2",
		Enabled:       true,
		Mode:          firewall.ModeManaged,
		Backend:       firewall.BackendNone,
		DefaultPolicy: firewall.DefaultPolicyDrop,
	}}
	rt := &AppContext{
		Config: appConfig,
		Clock:  func() time.Time { return time.Unix(7000, 0) },
	}
	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, config, time.Second)

	if service.firewallReconcileInterval() != defaultFirewallReconcileInterval {
		t.Fatalf("firewall interval = %s, want %s", service.firewallReconcileInterval(), defaultFirewallReconcileInterval)
	}
	base := time.Unix(7000, 0)
	if got := nextFirewallReconcileTime(base, 5*time.Second); !got.Equal(base.Add(5 * time.Second)) {
		t.Fatalf("nextFirewallReconcileTime = %s, want %s", got, base.Add(5*time.Second))
	}
	if got := nextFirewallReconcileTime(base, 0); !got.IsZero() {
		t.Fatalf("nextFirewallReconcileTime disabled = %s, want zero", got)
	}
	if service.flushFirewallReconcile(context.Background()) {
		t.Fatal("flushFirewallReconcile should be false when not dirty")
	}

	service.recoverFirewallOnStart(context.Background())
	if service.firewallDirty {
		t.Fatal("recoverFirewallOnStart should flush and clear firewallDirty")
	}
	observation := service.linuxObservation.firewallSnapshot()
	if observation == nil || observation.Instances["photontesth2"] == nil {
		t.Fatalf("firewall observation missing after recover: %+v", observation)
	}
	entry := observation.Instances["photontesth2"]
	if entry.PolicyHash == "" || entry.OwnedObjects == 0 || entry.LastRunUnix != 7000 {
		t.Fatalf("firewall reconcile entry = %+v, want hash/objects/last run", entry)
	}
}

func TestBuildFirewallDebugView(t *testing.T) {
	instances := []firewall.FirewallInstanceSpec{
		{ID: "photontesth2", NetNS: "photontesth2", IsHost: false, Enabled: true, Mode: firewall.ModeManaged, Backend: firewall.BackendAuto, DefaultPolicy: firewall.DefaultPolicyDrop,
			NativeHooks: firewall.NativeHooks{
				NFT:      firewall.InlineHookRules{PreInput: []string{"counter"}},
				IPTables: firewall.IPTablesInlineHooks{IPv4: firewall.InlineHookRules{PreInput: []string{"-j ACCEPT"}}},
			}},
		{ID: "host", NetNS: "host", IsHost: true, Enabled: true, Mode: firewall.ModeManaged, HostPorts: firewall.HostPortConfig{IKE: true, NATT: true}, RedirectGrace: firewall.RedirectGrace{Enabled: true}},
	}
	snapshot := &firewall.FirewallObservation{
		Backend: "dry-run",
		Instances: map[string]*firewall.FirewallInstanceObservation{
			"photontesth2": {Backend: firewall.BackendNFT, Generation: 5, OwnedObjects: 10, PolicyHash: "abc123"},
		},
	}
	view := buildFirewallDebugView(nil, instances, snapshot)
	if view.Backend != "dry-run" {
		t.Fatalf("backend = %q, want dry-run", view.Backend)
	}
	if len(view.Instances) != 2 {
		t.Fatalf("instances = %d, want 2", len(view.Instances))
	}
	if got := view.Instances[0]; got.ID != "photontesth2" || got.Generation != 5 || got.OwnedObjects != 10 || got.PolicyHash != "abc123" {
		t.Fatalf("first instance = %+v, want reconcile fields", got)
	}
	if got := view.Instances[0]; got.ResolvedBackend != firewall.BackendNFT || len(got.InlineHooks) != 2 || got.InlineHooks[0].State != "active" || got.InlineHooks[1].State != "inactive" {
		t.Fatalf("first instance inline hooks = %+v, resolved backend %q", got.InlineHooks, got.ResolvedBackend)
	}
	if got := view.Instances[1]; !got.IsHost || !got.HostIKE || !got.HostNATT || !got.RedirectGrace {
		t.Fatalf("host instance = %+v, want host flags", got)
	}
}

func TestFilterFirewallDebugInstances(t *testing.T) {
	instances := []firewall.FirewallInstanceSpec{
		{ID: "overlay", NetNS: "photon"},
		{ID: "host-ipsec", NetNS: "host", IsHost: true},
	}
	if got := filterFirewallDebugInstances(instances, "photon", false); len(got) != 1 || got[0].ID != "overlay" {
		t.Fatalf("netns filter = %+v", got)
	}
	if got := filterFirewallDebugInstances(instances, "", true); len(got) != 1 || got[0].ID != "host-ipsec" {
		t.Fatalf("host filter = %+v", got)
	}
}
