package main

import (
	"context"
	"strings"

	pingdebug "github.com/HiggsNet/photon/internal/ping"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/routing/bird"
	"github.com/urfave/cli/v3"
)

func cmdDebug() *cli.Command {
	return &cli.Command{
		Name:  "debug",
		Usage: "Diagnostic inspection commands",
		Commands: []*cli.Command{
			cmdVerify(),
			{
				Name:      "peer",
				Usage:     "Show diagnostic state for a peer",
				UsageText: "photon debug peer <peer-id>",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 1 {
						return cli.Exit("usage: photon debug peer <peer-id>", 1)
					}
					return debugPeer(cmd.Args().First())
				},
			},
			{
				Name:      "zone",
				Usage:     "Show diagnostic state for a zone",
				UsageText: "photon debug zone <zone> [--json] [--history]",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "json", Usage: "Print the full diagnostic zone structure as JSON"},
					&cli.BoolFlag{Name: "history", Usage: "Include bounded record history in JSON output"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 1 {
						return cli.Exit("usage: photon debug zone <zone> [--json] [--history]", 1)
					}
					if cmd.Bool("history") && !cmd.Bool("json") {
						return cli.Exit("--history requires --json", 1)
					}
					return debugZone(zone.ZonePath(cmd.Args().First()), cmd.Bool("json"), cmd.Bool("history"))
				},
			},
			{
				Name:      "record",
				Usage:     "Show one full record structure as JSON",
				UsageText: "photon debug record <zone> <key> [--history N]",
				Flags: []cli.Flag{
					&cli.IntFlag{Name: "history", Usage: "Include up to N previous versions"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 2 {
						return cli.Exit("usage: photon debug record <zone> <key> [--history N]", 1)
					}
					return debugRecord(zone.ZonePath(cmd.Args().Get(0)), cmd.Args().Get(1), cmd.Int("history"))
				},
			},
			{
				Name:      "records",
				Usage:     "List active records in local state",
				UsageText: "photon debug records [zone] [--prefix key-prefix] [--values]",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "prefix", Usage: "Only show records whose key has this prefix"},
					&cli.BoolFlag{Name: "values", Usage: "Print record values"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() > 1 {
						return cli.Exit("usage: photon debug records [zone] [--prefix key-prefix] [--values]", 1)
					}
					zoneArg := zone.ZonePath("")
					if cmd.Args().Len() == 1 {
						zoneArg = zone.ZonePath(cmd.Args().First())
					}
					return debugRecords(zoneArg, cmd.String("prefix"), cmd.Bool("values"))
				},
			},
			{
				Name:  "endpoints",
				Usage: "Show local endpoint candidates and discovered peer endpoints",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return debugEndpoints()
				},
			},
			{
				Name:      "links",
				Usage:     "Show IPsec link instances and reconcile state",
				UsageText: "photon debug links [--filter peer-or-link]",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "filter", Aliases: []string{"f"}, Usage: "Only show links matching peer zone, instance id, link_id, runtime id, interface, or SA name"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() > 1 {
						return cli.Exit("usage: photon debug links [--filter peer-or-link]", 1)
					}
					filter := cmd.String("filter")
					if cmd.Args().Len() == 1 {
						filter = cmd.Args().First()
					}
					return debugLinks(filter)
				},
			},
			{
				Name:        "routing",
				Usage:       "Inspect and reconcile routing",
				UsageText:   "photon debug routing [status | routes [prefix] | bird ... | ip route | reload]",
				Description: "Run without a subcommand to show routing instance status.",
				Commands:    debugRoutingCommands(),
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 0 {
						return cli.Exit("usage: photon debug routing [status|routes|bird|reload]", 1)
					}
					return debugBabel(ctx, cmd)
				},
			},
			{
				Name:  "admission",
				Usage: "Show auto-join admission diagnostics",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return debugAdmission()
				},
			},
			{
				Name:      "firewall",
				Usage:     "Show firewall reconcile state and owned objects",
				UsageText: "photon debug firewall [--netns <name> | --host] [--json]",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "netns", Usage: "Only show the firewall instance for this netns or instance id"},
					&cli.BoolFlag{Name: "host", Usage: "Only show host firewall instances"},
					&cli.BoolFlag{Name: "json", Usage: "Print JSON instead of text"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return debugFirewall(ctx, cmd)
				},
			},
			{
				Name:  "peers",
				Usage: "Show dynamic peer management lifecycle status",
				Description: "Display the derived lifecycle state of every known peer.\n" +
					"States include: eligible, discovered, connecting, active, stale, offline, policy_denied, config_error, revoked.",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return debugPeers(ctx)
				},
			},
			{
				Name:  "revoke-impact",
				Usage: "Show revocation impact and cleanup status for revoked zones",
				Description: "Display the affected subtree, link instances, sync peers, " +
					"configured-but-revoked peers, IPAM prefixes and per-layer cleanup status " +
					"for every currently-revoked zone.",
				UsageText: "photon debug revoke-impact [zone]",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					zoneArg := ""
					if cmd.Args().Len() > 0 {
						zoneArg = cmd.Args().First()
					}
					return debugRevokeImpact(ctx, zoneArg)
				},
			},
			{
				Name:      "rotate-port",
				Usage:     "Manually rotate the local advertised IPsec ports",
				UsageText: "photon debug rotate-port [--direct]",
				Description: "Ask the running daemon to force the local ipsec/ports record to the next generation. " +
					"Requires ipsec.port_mode=range, preserves the previous generation for ipsec.port_previous_grace, " +
					"and triggers sync plus firewall/IPsec reconcile. --direct writes the local DB only for recovery.",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "direct", Usage: "Write the local DB directly without daemon sync or data-plane reconcile"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 0 {
						return cli.Exit("usage: photon debug rotate-port [--direct]", 1)
					}
					return debugRotatePort(cmd.Bool("direct"))
				},
			},
			{
				Name:      "rotate",
				Usage:     "Show rotate runtime expectations and observed SAs",
				UsageText: "photon debug rotate [--filter peer-or-link]",
				Description: "Print current and staged generation runtime names, XFRM interface ids, tunnel addresses, " +
					"stored reconcile SAs and live StrongSwan SAs for links involved in port/data-plane rotate debugging.",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "filter", Aliases: []string{"f"}, Usage: "Only show links matching peer zone, instance id, link_id, runtime id, interface, or SA name"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() > 1 {
						return cli.Exit("usage: photon debug rotate [--filter peer-or-link]", 1)
					}
					filter := cmd.String("filter")
					if cmd.Args().Len() == 1 {
						filter = cmd.Args().First()
					}
					return debugRotate(ctx, filter)
				},
			},
			{
				Name:      "ping",
				Usage:     "Ping the remote StrongSwan peer over each IPsec SA for a zone",
				UsageText: "photon debug ping <zone> [--count N] [--timeout D] [--family ipv4|ipv6] [--role active|old|staged]",
				Description: "Send ICMP echo requests to the peer tunnel address of every IPsec link instance " +
					"matching the peer zone, across IPv4/IPv6 underlay paths and across both the old and new SA during a rotate. " +
					"Runs in the CLI process (requires root/CAP_NET_RAW and netns access).",
				Flags: []cli.Flag{
					&cli.IntFlag{Name: "count", Aliases: []string{"c"}, Usage: "ICMP requests per target (default 4, or health.burst)"},
					&cli.DurationFlag{Name: "timeout", Usage: "Per-request timeout (default 1s, or health.timeout)"},
					&cli.StringFlag{Name: "family", Usage: "Restrict to the ipv4 or ipv6 underlay path"},
					&cli.StringFlag{Name: "role", Usage: "Restrict to SA role: active, old, or staged"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 1 {
						return cli.Exit("usage: photon debug ping <zone> [--count N] [--timeout D] [--family ipv4|ipv6] [--role active|old|staged]", 1)
					}
					return debugPing(ctx, zone.ZonePath(cmd.Args().First()), pingdebug.Options{
						Count:   cmd.Int("count"),
						Timeout: cmd.Duration("timeout"),
						Family:  strings.ToLower(strings.TrimSpace(cmd.String("family"))),
						Role:    strings.ToLower(strings.TrimSpace(cmd.String("role"))),
					})
				},
			},
			cmdDB(),
		},
	}
}

func debugRoutingCommands() []*cli.Command {
	return []*cli.Command{
		{
			Name:      "status",
			Usage:     "Show BIRD/Babel routing instance state",
			UsageText: "photon debug routing status",
			Action: func(ctx context.Context, cmd *cli.Command) error {
				if cmd.Args().Len() != 0 {
					return cli.Exit("usage: photon debug routing status", 1)
				}
				return debugBabel(ctx, cmd)
			},
		},
		{
			Name:      "routes",
			Usage:     "Show announced/authorized routes with a BIRD cross-view",
			UsageText: "photon debug routing routes [prefix]",
			Action: func(ctx context.Context, cmd *cli.Command) error {
				switch cmd.Args().Len() {
				case 0:
					return debugRoutes(ctx, cmd)
				case 1:
					return debugRoute(ctx, cmd)
				default:
					return cli.Exit("usage: photon debug routing routes [prefix]", 1)
				}
			},
		},
		{
			Name:        "bird",
			Usage:       "Inspect the live BIRD/Babel RIB and protocol state",
			UsageText:   "photon debug routing bird <status|interface|filter|route> [--netns name]",
			Description: "These commands query the live BIRD control socket; route output is the BIRD RIB, not the kernel FIB.",
			Commands:    debugRoutingBirdCommands(),
		},
		{
			Name:      "ip",
			Usage:     "Inspect the kernel network stack in routing namespaces",
			UsageText: "photon debug routing ip route [--netns name] [--family ipv4|ipv6|all]",
			Commands: []*cli.Command{
				{
					Name:      "route",
					Usage:     "Show the kernel FIB in routing namespaces",
					UsageText: "photon debug routing ip route [--netns name] [--family ipv4|ipv6|all]",
					Flags: []cli.Flag{
						&cli.StringFlag{Name: "netns", Usage: "Only show this netns or routing instance id"},
						&cli.StringFlag{Name: "family", Value: "all", Usage: "Address family: ipv4, ipv6, or all"},
					},
					Action: func(ctx context.Context, cmd *cli.Command) error {
						if cmd.Args().Len() != 0 {
							return cli.Exit("usage: "+cmd.UsageText, 1)
						}
						return debugRoutingIPRoute(ctx, cmd.String("netns"), cmd.String("family"))
					},
				},
			},
		},
		{
			Name:      "reload",
			Usage:     "Trigger daemon routing reconcile",
			UsageText: "photon debug routing reload",
			Action: func(ctx context.Context, cmd *cli.Command) error {
				if cmd.Args().Len() != 0 {
					return cli.Exit("usage: photon debug routing reload", 1)
				}
				return debugRoutingReload(ctx, cmd)
			},
		},
	}
}

func debugRoutingBirdCommands() []*cli.Command {
	type birdCommand struct {
		name  string
		usage string
		view  bird.DebugView
	}
	specs := []birdCommand{
		{name: "status", usage: "Show live BIRD status, protocols, Babel neighbors, routes, and entries", view: bird.DebugStatus},
		{name: "interface", usage: "Show interfaces visible to BIRD", view: bird.DebugInterface},
		{name: "filter", usage: "Show active filter symbols and generated filter definitions", view: bird.DebugFilter},
		{name: "route", usage: "Show routes learned by the Babel protocol", view: bird.DebugRoute},
	}
	commands := make([]*cli.Command, 0, len(specs))
	for _, spec := range specs {
		view := spec.view
		commands = append(commands, &cli.Command{
			Name:      spec.name,
			Usage:     spec.usage,
			UsageText: "photon debug routing bird " + spec.name + " [--netns name]",
			Flags:     debugBirdFlags(),
			Action: func(ctx context.Context, cmd *cli.Command) error {
				if cmd.Args().Len() != 0 {
					return cli.Exit("usage: "+cmd.UsageText, 1)
				}
				return debugBird(ctx, cmd.String("netns"), view)
			},
		})
	}
	return commands
}

func debugBirdFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{Name: "netns", Usage: "Only dump the BIRD instance for this netns or instance id"},
	}
}
