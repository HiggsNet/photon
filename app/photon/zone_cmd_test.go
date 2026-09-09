package main

import (
	"context"
	"slices"
	"testing"

	"github.com/urfave/cli/v3"
)

func TestShowFlagsWorkBeforeAndAfterSubcommand(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "before show", args: []string{"photon", "view", "--filter", "parent", "--verbose", "show"}},
		{name: "after show", args: []string{"photon", "view", "show", "--filter", "child", "--verbose"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var filter string
			var verbose bool
			view := &cli.Command{
				Name: "view",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "filter"},
					&cli.BoolFlag{Name: "verbose"},
				},
				Commands: []*cli.Command{{
					Name: "show",
					Flags: []cli.Flag{
						&cli.StringFlag{Name: "filter"},
						&cli.BoolFlag{Name: "verbose"},
					},
					Action: func(_ context.Context, cmd *cli.Command) error {
						filter = effectiveStringFlag(cmd, "filter")
						verbose = effectiveBoolFlag(cmd, "verbose")
						return nil
					},
				}},
			}
			root := &cli.Command{Name: "photon", Commands: []*cli.Command{view}}
			if err := root.Run(context.Background(), tt.args); err != nil {
				t.Fatalf("Run: %v", err)
			}
			if !verbose {
				t.Fatal("verbose flag was not inherited")
			}
			if tt.name == "before show" && filter != "parent" {
				t.Fatalf("filter = %q, want parent", filter)
			}
			if tt.name == "after show" && filter != "child" {
				t.Fatalf("filter = %q, want child", filter)
			}
		})
	}
}

func TestHumanCommandsUsePlaneOrientedShowViews(t *testing.T) {
	root := rootCommand()
	if commandByName(root.Commands, "status") == nil {
		t.Fatal("root command does not expose status")
	}
	if commandByName(root.Commands, "db") != nil {
		t.Fatal("root command unexpectedly exposes low-level db")
	}
	for _, name := range []string{"root", "keygen", "join", "delegate", "zone", "record", "ipam", "records", "verify", "recovery", "gc", "sync"} {
		if commandByName(root.Commands, name) != nil {
			t.Errorf("root command unexpectedly exposes %s", name)
		}
	}

	gossip := commandByName(root.Commands, "gossip")
	if gossip == nil {
		t.Fatal("root command does not expose gossip")
	}
	for _, name := range []string{"root", "keygen", "join", "delegate", "zone", "record", "peer"} {
		if commandByName(gossip.Commands, name) == nil {
			t.Errorf("gossip command does not expose %s", name)
		}
	}

	zoneCommand := commandByName(gossip.Commands, "zone")
	show := commandByName(zoneCommand.Commands, "show")
	requireCommandFlags(t, show, "filter", "verbose")
	requireCommandFlags(t, zoneCommand, "filter", "verbose")
	if commandFlagByName(show, "history") != nil {
		t.Fatal("zone show still exposes diagnostic history")
	}

	recordCommand := commandByName(gossip.Commands, "record")
	requireCommandFlags(t, recordCommand, "filter", "verbose")
	list := commandByName(recordCommand.Commands, "list")
	requireCommandFlags(t, list, "filter", "verbose")
	get := commandByName(recordCommand.Commands, "get")
	requireCommandFlags(t, get, "verbose")
	if commandFlagByName(get, "history") != nil {
		t.Fatal("record get still exposes diagnostic history")
	}
	peerCommand := commandByName(gossip.Commands, "peer")
	if !slices.Contains(peerCommand.Aliases, "peers") {
		t.Fatal("gossip peer command does not expose peers alias")
	}
	requireCommandFlags(t, commandByName(peerCommand.Commands, "show"), "filter", "verbose")

	links := commandByName(root.Commands, "links")
	requireCommandFlags(t, commandByName(links.Commands, "show"), "filter", "verbose")
	health := commandByName(root.Commands, "health")
	requireCommandFlags(t, health, "sort", "verbose")
	daemon := commandByName(root.Commands, "daemon")
	requireCommandFlags(t, daemon, "interval", "cpu-profile", "cpu-profile-duration")

	route := commandByName(root.Commands, "route")
	requireCommandFlags(t, commandByName(route.Commands, "show"), "filter", "verbose")
	if commandByName(route.Commands, "ipam") == nil {
		t.Fatal("route command does not expose ipam")
	}

	debug := commandByName(root.Commands, "debug")
	if commandByName(debug.Commands, "health") != nil {
		t.Fatal("health should be a root command, not a debug subcommand")
	}
	debugZone := commandByName(debug.Commands, "zone")
	requireCommandFlags(t, debugZone, "json", "history")
	debugRecord := commandByName(debug.Commands, "record")
	requireCommandFlags(t, debugRecord, "history")
	if commandByName(debug.Commands, "verify") == nil {
		t.Fatal("debug command does not expose verify")
	}
	if commandByName(debug.Commands, "db") == nil {
		t.Fatal("debug command does not expose db")
	}

	advanced := commandByName(root.Commands, "advanced")
	for _, name := range []string{"sync", "recovery"} {
		if commandByName(advanced.Commands, name) == nil {
			t.Errorf("advanced command does not expose %s", name)
		}
	}
	if commandByName(advanced.Commands, "gc") != nil {
		t.Error("advanced command still exposes obsolete BIRD diagnostic-state gc")
	}

	firewall := commandByName(root.Commands, "firewall")
	showFirewall := commandByName(firewall.Commands, "show")
	requireCommandFlags(t, showFirewall, "filter", "verbose")
}

func commandFlagByName(command *cli.Command, name string) cli.Flag {
	if command == nil {
		return nil
	}
	for _, flag := range command.Flags {
		if slices.Contains(flag.Names(), name) {
			return flag
		}
	}
	return nil
}

func requireCommandFlags(t *testing.T, command *cli.Command, names ...string) {
	t.Helper()
	if command == nil {
		t.Fatal("command is nil")
	}
	for _, name := range names {
		if commandFlagByName(command, name) == nil {
			t.Errorf("command %s missing flag %s", command.Name, name)
		}
	}
}
