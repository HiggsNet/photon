package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/urfave/cli/v3"
)

func TestDebugRoutingCommandsAreConsolidated(t *testing.T) {
	debug := cmdDebug()
	routing := debugCommandByName(t, debug.Commands, "routing")
	if routing.Hidden {
		t.Fatal("canonical routing command must be visible")
	}

	wantChildren := []string{"status", "routes", "bird", "ip", "reload"}
	if len(routing.Commands) != len(wantChildren) {
		t.Fatalf("routing subcommands = %d, want %d", len(routing.Commands), len(wantChildren))
	}
	for i, want := range wantChildren {
		if got := routing.Commands[i].Name; got != want {
			t.Errorf("routing subcommand %d = %q, want %q", i, got, want)
		}
		if routing.Commands[i].Hidden {
			t.Errorf("canonical routing subcommand %q is hidden", want)
		}
	}

	bird := debugCommandByName(t, routing.Commands, "bird")
	wantBirdChildren := []string{"status", "interface", "filter", "route"}
	if len(bird.Commands) != len(wantBirdChildren) {
		t.Fatalf("bird subcommands = %d, want %d", len(bird.Commands), len(wantBirdChildren))
	}
	for i, want := range wantBirdChildren {
		if got := bird.Commands[i].Name; got != want {
			t.Errorf("bird subcommand %d = %q, want %q", i, got, want)
		}
	}

	ip := debugCommandByName(t, routing.Commands, "ip")
	if len(ip.Commands) != 1 || ip.Commands[0].Name != "route" {
		t.Fatalf("routing ip subcommands = %#v, want route", ip.Commands)
	}

	for _, name := range []string{"route", "routes", "babel", "babeld", "bird-dump", "routing-reload"} {
		if commandByName(debug.Commands, name) != nil {
			t.Errorf("legacy debug command %q must be removed", name)
		}
	}
}

func TestDebugHelpOnlyAdvertisesRoutingEntryPoint(t *testing.T) {
	command := rootCommand()
	var stdout, stderr strings.Builder
	command.Writer = &stdout
	command.ErrWriter = &stderr

	if err := command.Run(context.Background(), []string{"photon", "debug", "--help"}); err != nil {
		t.Fatalf("debug help: %v\nstderr:\n%s", err, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "routing") || !strings.Contains(out, "Inspect and reconcile routing") {
		t.Fatalf("debug help does not advertise the routing entry point:\n%s", out)
	}
	for _, legacy := range []string{"route ", "routes ", "babel ", "babeld ", "bird-dump ", "routing-reload "} {
		if strings.Contains(out, legacy) {
			t.Errorf("debug help still advertises legacy command %q:\n%s", strings.TrimSpace(legacy), out)
		}
	}
}

func debugCommandByName(t *testing.T, commands []*cli.Command, name string) *cli.Command {
	t.Helper()
	if command := commandByName(commands, name); command != nil {
		return command
	}
	t.Fatalf("command %q not found", name)
	return nil
}

func commandByName(commands []*cli.Command, name string) *cli.Command {
	for _, command := range commands {
		if command.Name == name {
			return command
		}
	}
	return nil
}

func TestDebugRoutesFallbackComputesAuthorizedRouteSet(t *testing.T) {
	verified, checkpoint, runtime, _ := buildTestRoutingOwners(t)
	now := time.Unix(4000, 0)

	appConfig := defaultAppConfig()
	appConfig.DataDir = t.TempDir()
	rt := &AppContext{
		Config:         appConfig,
		StatePath:      filepath.Join(t.TempDir(), "photon.db"),
		Clock:          func() time.Time { return now },
		DisableControl: true,
	}
	seedPartitionedStateDB(t, rt.StatePath, verified, checkpoint, runtime)

	var buf strings.Builder
	if err := debugRoutesWithRuntime(rt, &buf); err != nil {
		t.Fatalf("debugRoutesWithRuntime: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "local_zone: node-a.catofes.") {
		t.Errorf("expected local_zone node-a.catofes., got:\n%s", out)
	}
	if !strings.Contains(out, "10.0.0.0/24") {
		t.Errorf("expected local export prefix 10.0.0.0/24, got:\n%s", out)
	}
	if !strings.Contains(out, "zone node-a.catofes.") {
		t.Errorf("expected node-a.catofes. authorized zone, got:\n%s", out)
	}
	if !strings.Contains(out, "zone node-b.catofes.") {
		t.Errorf("expected node-b.catofes. authorized zone, got:\n%s", out)
	}
	if !strings.Contains(out, "10.1.0.0/24") {
		t.Errorf("expected remote prefix 10.1.0.0/24, got:\n%s", out)
	}
	if strings.Contains(out, "authorization_errors:") && strings.Contains(out, "route_unauthorized") {
		t.Errorf("did not expect authorization errors, got:\n%s", out)
	}
}

func TestDebugRouteExplainsPrefix(t *testing.T) {
	verified, checkpoint, runtime, _ := buildTestRoutingOwners(t)
	now := time.Unix(4000, 0)

	appConfig := defaultAppConfig()
	appConfig.DataDir = t.TempDir()
	rt := &AppContext{
		Config:         appConfig,
		StatePath:      filepath.Join(t.TempDir(), "photon.db"),
		Clock:          func() time.Time { return now },
		DisableControl: true,
	}
	seedPartitionedStateDB(t, rt.StatePath, verified, checkpoint, runtime)

	var buf strings.Builder
	if err := debugRouteWithRuntime(rt, "10.0.0.0/24", &buf); err != nil {
		t.Fatalf("debugRouteWithRuntime: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "prefix: 10.0.0.0/24") {
		t.Errorf("expected canonical prefix, got:\n%s", out)
	}
	if !strings.Contains(out, "local_export: true") {
		t.Errorf("expected local_export true, got:\n%s", out)
	}
	if !strings.Contains(out, "authorized: true") {
		t.Errorf("expected authorized true, got:\n%s", out)
	}
	if !strings.Contains(out, "announcing_zones: node-a.catofes.") {
		t.Errorf("expected announcing zone node-a.catofes., got:\n%s", out)
	}
	if !strings.Contains(out, "assignment_assigned_to: node-a.catofes.") {
		t.Errorf("expected assignment to node-a.catofes., got:\n%s", out)
	}
}

func TestDebugBabelRequiresOnlineDaemon(t *testing.T) {
	appConfig := defaultAppConfig()
	appConfig.DataDir = t.TempDir()
	rt := &AppContext{
		Config:         appConfig,
		Clock:          func() time.Time { return time.Unix(4000, 0) },
		DisableControl: true,
	}

	var buf strings.Builder
	if err := debugBabelWithRuntime(rt, &buf); err == nil || !strings.Contains(err.Error(), "requires a running daemon") {
		t.Fatalf("debugBabelWithRuntime error = %v", err)
	}
}
