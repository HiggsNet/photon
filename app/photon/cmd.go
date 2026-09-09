package main

import (
	"context"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/urfave/cli/v3"
)

func rootCommand() *cli.Command {
	return &cli.Command{
		Name:        "photon",
		Usage:       "Photon zone authority CLI",
		Description: "A command-line tool for managing Photon zones, keys, records, and sync.",
		Commands: []*cli.Command{
			cmdStatus(),
			cmdGossip(),
			cmdLinks(),
			cmdRoute(),
			cmdService(),
			cmdFirewall(),
			cmdHealth(),
			cmdVersion(),
			cmdDaemon(),
			cmdAdvanced(),
			cmdDebug(),
		},
	}
}

func cmdStatus() *cli.Command {
	return &cli.Command{
		Name:      "status",
		Usage:     "Show the current Photon node status",
		UsageText: "photon status",
		Action: func(_ context.Context, cmd *cli.Command) error {
			if cmd.Args().Len() != 0 {
				return cli.Exit("usage: photon status", 1)
			}
			return showStatus()
		},
	}
}

func cmdHealth() *cli.Command {
	return &cli.Command{
		Name:        "health",
		Usage:       "Show link health probe state",
		UsageText:   "photon health [--sort peer|rtt] [--verbose]",
		Description: "Display per-link health, loss, latency, jitter, and rotate cutover readiness.",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "sort", Value: "peer", Usage: "Sort rows by peer or latency (peer|rtt)"},
			&cli.BoolFlag{Name: "verbose", Aliases: []string{"v"}, Usage: "Show link/probe IDs, interfaces, tunnel addresses, packet counts, RTT percentiles, and errors"},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			if cmd.Args().Len() != 0 {
				return cli.Exit("usage: photon health [--sort peer|rtt] [--verbose]", 1)
			}
			return showHealth(cmd.String("sort"), cmd.Bool("verbose"))
		},
	}
}

func cmdGossip() *cli.Command {
	return &cli.Command{
		Name:  "gossip",
		Usage: "Gossip identity, trust, zone, record, and peer commands",
		Commands: []*cli.Command{
			cmdRoot(),
			cmdKeygen(),
			cmdJoin(),
			cmdDelegate(),
			cmdZone(),
			cmdRecord(),
			cmdPeer(),
		},
	}
}

func cmdAdvanced() *cli.Command {
	return &cli.Command{
		Name:        "advanced",
		Usage:       "Low-level synchronization, recovery, and maintenance commands",
		Description: "Commands for manual synchronization, state recovery, and local maintenance. Most installations only need the daemon.",
		Commands: []*cli.Command{
			cmdSync(),
			cmdRecovery(),
		},
	}
}

func cmdFirewall() *cli.Command {
	return &cli.Command{
		Name:  "firewall",
		Usage: "Show and manage local dynamic firewall policy",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "filter", Aliases: []string{"f"}, Usage: "Only show matching instance ids, scopes, policies, backends, prefixes, or services"},
			&cli.BoolFlag{Name: "verbose", Aliases: []string{"v"}, Usage: "Show transit filters, services, host policy, generation, and owned-object details"},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			if cmd.Args().Len() != 0 {
				return cli.Exit("usage: photon firewall [--filter text] [--verbose]", 1)
			}
			return showFirewall(cmd.String("filter"), cmd.Bool("verbose"))
		},
		Commands: []*cli.Command{
			{
				Name:      "show",
				Usage:     "Show local firewall policy",
				UsageText: "photon firewall show [--filter text] [--verbose]",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "filter", Aliases: []string{"f"}, Usage: "Only show matching instance ids, scopes, policies, backends, prefixes, or services"},
					&cli.BoolFlag{Name: "verbose", Aliases: []string{"v"}, Usage: "Show transit filters, services, host policy, generation, and owned-object details"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 0 {
						return cli.Exit("usage: photon firewall show [--filter text] [--verbose]", 1)
					}
					return showFirewall(effectiveStringFlag(cmd, "filter"), effectiveBoolFlag(cmd, "verbose"))
				},
			},
			{
				Name: "endpoint", Usage: "Manage forwarded endpoint ACLs",
				Commands: []*cli.Command{
					{
						Name: "apply", UsageText: "photon firewall endpoint apply <name> --destination <ip> [--scope ip | --protocol <tcp|udp> --port <port>] --allow-zone <selector>...",
						Flags: []cli.Flag{
							&cli.StringFlag{Name: "destination", Required: true},
							&cli.StringFlag{Name: "scope", Value: endpointACLScopePort},
							&cli.StringFlag{Name: "protocol"},
							&cli.UintFlag{Name: "port"},
							&cli.StringSliceFlag{Name: "allow-zone", Required: true},
						},
						Action: func(ctx context.Context, cmd *cli.Command) error {
							if cmd.Args().Len() != 1 || cmd.Uint("port") > 65535 {
								return cli.Exit("invalid endpoint ACL arguments", 1)
							}
							return applyEndpointACL(cmd.Args().First(), cmd.String("destination"), cmd.String("scope"), cmd.String("protocol"), uint16(cmd.Uint("port")), cmd.StringSlice("allow-zone"))
						},
					},
					{
						Name: "remove", UsageText: "photon firewall endpoint remove <name>",
						Action: func(ctx context.Context, cmd *cli.Command) error {
							if cmd.Args().Len() != 1 {
								return cli.Exit("usage: photon firewall endpoint remove <name>", 1)
							}
							return removeEndpointACL(cmd.Args().First())
						},
					},
					{
						Name: "list", UsageText: "photon firewall endpoint list",
						Action: func(ctx context.Context, cmd *cli.Command) error {
							if cmd.Args().Len() != 0 {
								return cli.Exit("usage: photon firewall endpoint list", 1)
							}
							return listEndpointACLs()
						},
					},
				},
			},
		},
	}
}

func cmdService() *cli.Command {
	return &cli.Command{
		Name:      "service",
		Usage:     "Show and manage signed application service records",
		UsageText: "photon service [--filter text] [--local] [--all] [--verbose]",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "filter", Aliases: []string{"f"}, Usage: "Only show services matching id, type, owner, region, endpoint, or status"},
			&cli.BoolFlag{Name: "local", Usage: "Only show services published by the managed zone"},
			&cli.BoolFlag{Name: "all", Usage: "Include withdrawn services"},
			&cli.BoolFlag{Name: "verbose", Aliases: []string{"v"}, Usage: "Show version, update time, record key, and parse errors"},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			if cmd.Args().Len() != 0 {
				return cli.Exit("usage: photon service [--filter text] [--local] [--all] [--verbose]", 1)
			}
			return showServices(cmd.String("filter"), cmd.Bool("all"), cmd.Bool("local"), cmd.Bool("verbose"))
		},
		Commands: []*cli.Command{
			{
				Name:      "show",
				Aliases:   []string{"list"},
				Usage:     "Show publicly advertised services",
				UsageText: "photon service show [--filter text] [--local] [--all] [--verbose]",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "filter", Aliases: []string{"f"}, Usage: "Only show services matching id, type, owner, region, endpoint, or status"},
					&cli.BoolFlag{Name: "local", Usage: "Only show services published by the managed zone"},
					&cli.BoolFlag{Name: "all", Usage: "Include withdrawn services"},
					&cli.BoolFlag{Name: "verbose", Aliases: []string{"v"}, Usage: "Show version, update time, record key, and parse errors"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 0 {
						return cli.Exit("usage: photon service show [--filter text] [--local] [--all] [--verbose]", 1)
					}
					return showServices(
						effectiveStringFlag(cmd, "filter"),
						effectiveBoolFlag(cmd, "all"),
						effectiveBoolFlag(cmd, "local"),
						effectiveBoolFlag(cmd, "verbose"),
					)
				},
			},
			{
				Name:      "mine",
				Usage:     "Show services published by the managed zone",
				UsageText: "photon service mine [--filter text] [--all] [--verbose]",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "filter", Aliases: []string{"f"}, Usage: "Only show local services matching id, type, region, endpoint, or status"},
					&cli.BoolFlag{Name: "all", Usage: "Include withdrawn services"},
					&cli.BoolFlag{Name: "verbose", Aliases: []string{"v"}, Usage: "Show version, update time, record key, and parse errors"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 0 {
						return cli.Exit("usage: photon service mine [--filter text] [--all] [--verbose]", 1)
					}
					return showServices(
						effectiveStringFlag(cmd, "filter"),
						effectiveBoolFlag(cmd, "all"),
						true,
						effectiveBoolFlag(cmd, "verbose"),
					)
				},
			},
			{
				Name:                      "publish",
				Usage:                     "Publish a SOCKS5 endpoint owned by the managed zone",
				UsageText:                 "photon service publish --endpoint <region,address,port>... [--direct]",
				DisableSliceFlagSeparator: true,
				Flags: []cli.Flag{
					&cli.StringSliceFlag{Name: "endpoint", Usage: "Endpoint as region,address,port; repeat for multiple networks"},
					&cli.StringFlag{Name: "region", Usage: "Legacy single-endpoint region"},
					&cli.StringFlag{Name: "address", Usage: "Legacy single-endpoint address"},
					&cli.UintFlag{Name: "port", Value: 3128},
					&cli.BoolFlag{Name: "direct", Usage: "Write the local DB directly"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 0 || cmd.Uint("port") > 65535 {
						return cli.Exit("usage: photon service publish --endpoint <region,address,port>...", 1)
					}
					endpoints, err := parseSOCKS5EndpointFlags(cmd.StringSlice("endpoint"), cmd.String("region"), cmd.String("address"), uint16(cmd.Uint("port")))
					if err != nil {
						return err
					}
					return publishSOCKS5Endpoints(endpoints, cmd.Bool("direct"))
				},
			},
			{
				Name:      "withdraw",
				Usage:     "Withdraw a previously published SOCKS5 endpoint",
				UsageText: "photon service withdraw [--direct]",
				Flags:     []cli.Flag{&cli.BoolFlag{Name: "direct", Usage: "Write the local DB directly"}},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 0 {
						return cli.Exit("usage: photon service withdraw [--direct]", 1)
					}
					return withdrawSOCKS5Service(cmd.Bool("direct"))
				},
			},
		},
	}
}

func cmdVersion() *cli.Command {
	return &cli.Command{
		Name:  "version",
		Usage: "Show build version information",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			if cmd.Args().Len() != 0 {
				return cli.Exit("usage: photon version", 1)
			}
			return writeVersion(os.Stdout)
		},
	}
}

func cmdRoot() *cli.Command {
	return &cli.Command{
		Name:  "root",
		Usage: "Root zone management commands",
		Commands: []*cli.Command{
			{
				Name:        "init",
				Usage:       "Initialize a root state file",
				Description: "Create a new state database containing only the root zone.",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 0 {
						return cli.Exit("usage: photon gossip root init", 1)
					}
					return initRootState()
				},
			},
			{
				Name:        "pubkey",
				Usage:       "Show the root zone public key",
				Description: "Display the public key of the root zone authority.",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 0 {
						return cli.Exit("usage: photon gossip root pubkey", 1)
					}
					return rootPubkey()
				},
			},
		},
	}
}

func cmdKeygen() *cli.Command {
	return &cli.Command{
		Name:      "keygen",
		Usage:     "Generate a new Ed25519 key pair",
		UsageText: "photon gossip keygen <file>",
		Description: "Generate a new Ed25519 private key and write it to the specified JSON file.\n" +
			"The public key is printed to stdout.",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			if cmd.Args().Len() != 1 {
				return cli.Exit("usage: photon gossip keygen <file>", 1)
			}
			return keygen(cmd.Args().First())
		},
	}
}

func cmdJoin() *cli.Command {
	return &cli.Command{
		Name:  "join",
		Usage: "Join request and acceptance commands",
		Commands: []*cli.Command{
			{
				Name:      "request",
				Usage:     "Create a join request for a zone",
				UsageText: "photon gossip join request <zone> <key.json> [request.b64]\n   photon gossip join request --from-config [request.b64]",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "from-config", Usage: "Create the request from managed_zone and identity.key_path in config.yaml"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Bool("from-config") {
						if cmd.Args().Len() > 1 {
							return cli.Exit("usage: photon gossip join request --from-config [request.b64]", 1)
						}
						return writeJoinRequestFromConfig(cmd.Args().First())
					}
					if cmd.Args().Len() < 2 || cmd.Args().Len() > 3 {
						return cli.Exit("usage: photon gossip join request <zone> <key.json> [request.b64]", 1)
					}
					return createJoinRequest(zone.ZonePath(cmd.Args().Get(0)), cmd.Args().Get(1), cmd.Args().Get(2))
				},
			},
			{
				Name:      "accept",
				Usage:     "Accept a join bundle",
				UsageText: "photon gossip join accept [--direct] <bundle-b64|bundle-file> [key.json]",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "direct", Usage: "Write the local DB directly without contacting the daemon"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() < 1 || cmd.Args().Len() > 2 {
						return cli.Exit("usage: photon gossip join accept <bundle-b64|bundle-file> [key.json]", 1)
					}
					return acceptJoinBundle(cmd.Args().Get(0), cmd.Args().Get(1), cmd.Bool("direct"))
				},
			},
		},
	}
}

func cmdDelegate() *cli.Command {
	return &cli.Command{
		Name:  "delegate",
		Usage: "Delegation management commands",
		Commands: []*cli.Command{
			{
				Name:      "issue",
				Usage:     "Issue a delegation from a join request",
				UsageText: "photon gossip delegate issue [--permissions <permissions>] [--direct] <request-b64|request-file> [bundle.b64]",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "permissions", Usage: "Comma-separated permissions for the delegated zone"},
					&cli.BoolFlag{Name: "direct", Usage: "Write the local DB directly without contacting the daemon"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() < 1 || cmd.Args().Len() > 2 {
						return cli.Exit("usage: photon gossip delegate issue [--permissions <permissions>] [--direct] <request-b64|request-file> [bundle.b64]", 1)
					}
					permissions, err := parseOptionalDelegationPermissions(cmd.String("permissions"))
					if err != nil {
						return err
					}
					return issueDelegation(cmd.Args().Get(0), cmd.Args().Get(1), permissions, cmd.Bool("direct"))
				},
			},
			{
				Name:      "grant",
				Usage:     "Add permissions to an existing delegated zone",
				UsageText: "photon gossip delegate grant [--direct] <zone> <permission>[,<permission>...] [bundle.b64]",
				Description: "Increase the delegated zone authority epoch, add permissions to its authorized keys, " +
					"and re-sign the parent delegation.",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "direct", Usage: "Write the local DB directly without contacting the daemon"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() < 2 || cmd.Args().Len() > 3 {
						return cli.Exit("usage: photon gossip delegate grant <zone> <permission>[,<permission>...] [bundle.b64]", 1)
					}
					permissions, err := parseAuthorityPermissions([]string{cmd.Args().Get(1)})
					if err != nil {
						return err
					}
					return grantDelegationPermissions(zone.ZonePath(cmd.Args().Get(0)), permissions, cmd.Args().Get(2), cmd.Bool("direct"))
				},
			},
			{
				Name:      "revoke",
				Usage:     "Revoke a child zone delegation",
				UsageText: "photon gossip delegate revoke [--direct] <zone> [reason]",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "direct", Usage: "Write the local DB directly without contacting the daemon"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() < 1 || cmd.Args().Len() > 2 {
						return cli.Exit("usage: photon gossip delegate revoke <zone> [reason]", 1)
					}
					reason := ""
					if cmd.Args().Len() == 2 {
						reason = cmd.Args().Get(1)
					}
					return revokeDelegation(zone.ZonePath(cmd.Args().Get(0)), reason, cmd.Bool("direct"))
				},
			},
		},
	}
}

func parseOptionalDelegationPermissions(raw string) ([]zone.Permission, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	return parseAuthorityPermissions([]string{raw})
}

func effectiveStringFlag(cmd *cli.Command, name string) string {
	for _, current := range cmd.Lineage() {
		if localFlagSet(current, name) {
			return current.String(name)
		}
	}
	return cmd.String(name)
}

func effectiveBoolFlag(cmd *cli.Command, name string) bool {
	for _, current := range cmd.Lineage() {
		if localFlagSet(current, name) {
			return current.Bool(name)
		}
	}
	return cmd.Bool(name)
}

func localFlagSet(cmd *cli.Command, name string) bool {
	return slices.Contains(cmd.LocalFlagNames(), name)
}

func cmdZone() *cli.Command {
	return &cli.Command{
		Name:      "zone",
		Usage:     "Show known zones",
		UsageText: "photon gossip zone [zone] [--filter text] [--verbose]",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "filter", Aliases: []string{"f"}, Usage: "Only show zones whose path contains this text"},
			&cli.BoolFlag{Name: "verbose", Aliases: []string{"v"}, Usage: "Show parent, permissions, history, revocation, and authority details"},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			if cmd.Args().Len() > 1 {
				return cli.Exit("usage: photon gossip zone [zone] [--filter text] [--verbose]", 1)
			}
			filter := cmd.String("filter")
			if cmd.Args().Len() == 1 {
				if filter != "" {
					return cli.Exit("zone argument and --filter cannot be used together", 1)
				}
				filter = cmd.Args().First()
			}
			return showZones(filter, cmd.Bool("verbose"))
		},
		Commands: []*cli.Command{
			{
				Name:      "show",
				Usage:     "Show known zones",
				UsageText: "photon gossip zone show [zone] [--filter text] [--verbose]",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "filter", Aliases: []string{"f"}, Usage: "Only show zones whose path contains this text"},
					&cli.BoolFlag{Name: "verbose", Aliases: []string{"v"}, Usage: "Show parent, permissions, history, revocation, and authority details"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() > 1 {
						return cli.Exit("usage: photon gossip zone show [zone] [--filter text] [--verbose]", 1)
					}
					filter := effectiveStringFlag(cmd, "filter")
					if cmd.Args().Len() == 1 {
						if filter != "" {
							return cli.Exit("zone argument and --filter cannot be used together", 1)
						}
						filter = cmd.Args().First()
					}
					return showZones(filter, effectiveBoolFlag(cmd, "verbose"))
				},
			},
		},
	}
}

func cmdRecord() *cli.Command {
	return &cli.Command{
		Name:      "record",
		Usage:     "Browse and manage records",
		UsageText: "photon gossip record [zone] [--filter text] [--verbose]",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "filter", Aliases: []string{"f"}, Usage: "Only show records whose key, type, or value contains this text"},
			&cli.BoolFlag{Name: "verbose", Aliases: []string{"v"}, Usage: "Show versions, timestamps, and history counts"},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			if cmd.Args().Len() > 1 {
				return cli.Exit("usage: photon gossip record [zone] [--filter text] [--verbose]", 1)
			}
			path := zone.ZonePath("")
			if cmd.Args().Len() == 1 {
				path = zone.ZonePath(cmd.Args().First())
			}
			return showRecords(path, cmd.String("filter"), cmd.Bool("verbose"))
		},
		Commands: []*cli.Command{
			{
				Name:      "list",
				Usage:     "Browse records in a human-readable form",
				UsageText: "photon gossip record list [zone] [--filter text] [--verbose]",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "filter", Aliases: []string{"f"}, Usage: "Only show records whose key, type, or value contains this text"},
					&cli.BoolFlag{Name: "verbose", Aliases: []string{"v"}, Usage: "Show versions, timestamps, and history counts"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() > 1 {
						return cli.Exit("usage: photon gossip record list [zone] [--filter text] [--verbose]", 1)
					}
					path := zone.ZonePath("")
					if cmd.Args().Len() == 1 {
						path = zone.ZonePath(cmd.Args().First())
					}
					return showRecords(path, cmd.String("filter"), cmd.Bool("verbose"))
				},
			},
			{
				Name:      "put",
				Usage:     "Store a record in a zone",
				UsageText: "photon gossip record put [--direct] <zone> <key> <value> [type]",
				Description: "Store a key-value record in the specified zone.\n" +
					"Optional type defaults to 'policy.string'.",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "direct", Usage: "Write the local DB directly without contacting the daemon"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() < 3 || cmd.Args().Len() > 4 {
						return cli.Exit("usage: photon gossip record put <zone> <key> <value> [type]", 1)
					}
					recordType := "policy.string"
					if cmd.Args().Len() > 3 {
						recordType = cmd.Args().Get(3)
					}
					return putRecord(zone.ZonePath(cmd.Args().Get(0)), cmd.Args().Get(1), []byte(cmd.Args().Get(2)), recordType, cmd.Bool("direct"))
				},
			},
			{
				Name:      "get",
				Usage:     "Show one record in a human-readable form",
				UsageText: "photon gossip record get <zone> <key> [--verbose]",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "verbose", Aliases: []string{"v"}, Usage: "Show version, timestamp, and history count"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 2 {
						return cli.Exit("usage: photon gossip record get <zone> <key> [--verbose]", 1)
					}
					return getRecord(zone.ZonePath(cmd.Args().Get(0)), cmd.Args().Get(1), cmd.Bool("verbose"))
				},
			},
		},
	}
}

func cmdPeer() *cli.Command {
	return &cli.Command{
		Name:      "peer",
		Aliases:   []string{"peers"},
		Usage:     "Show gossip peer connectivity and sync state",
		UsageText: "photon gossip peer [peer] [--filter text] [--verbose]",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "filter", Aliases: []string{"f"}, Usage: "Only show peers matching gossip id, endpoint, status, or error"},
			&cli.BoolFlag{Name: "verbose", Aliases: []string{"v"}, Usage: "Show endpoint, retry, relay, datagram, and object-pull diagnostics"},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			if cmd.Args().Len() > 1 {
				return cli.Exit("usage: photon gossip peer [peer] [--filter text] [--verbose]", 1)
			}
			filter := cmd.String("filter")
			if cmd.Args().Len() == 1 {
				if filter != "" {
					return cli.Exit("peer argument and --filter cannot be used together", 1)
				}
				filter = cmd.Args().First()
			}
			return showPeers(filter, cmd.Bool("verbose"))
		},
		Commands: []*cli.Command{
			{
				Name:      "show",
				Usage:     "Show gossip peer connectivity and sync state",
				UsageText: "photon gossip peer show [peer] [--filter text] [--verbose]",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "filter", Aliases: []string{"f"}, Usage: "Only show peers matching gossip id, endpoint, status, or error"},
					&cli.BoolFlag{Name: "verbose", Aliases: []string{"v"}, Usage: "Show endpoint, retry, relay, datagram, and object-pull diagnostics"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() > 1 {
						return cli.Exit("usage: photon gossip peer show [peer] [--filter text] [--verbose]", 1)
					}
					filter := effectiveStringFlag(cmd, "filter")
					if cmd.Args().Len() == 1 {
						if filter != "" {
							return cli.Exit("peer argument and --filter cannot be used together", 1)
						}
						filter = cmd.Args().First()
					}
					return showPeers(filter, effectiveBoolFlag(cmd, "verbose"))
				},
			},
		},
	}
}

func cmdLinks() *cli.Command {
	return &cli.Command{
		Name:      "links",
		Usage:     "Show transport link state",
		UsageText: "photon links [link-or-peer] [--filter text] [--verbose]",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "filter", Aliases: []string{"f"}, Usage: "Only show links matching peer, id, group, endpoint, interface, or SA"},
			&cli.BoolFlag{Name: "verbose", Aliases: []string{"v"}, Usage: "Show tunnel, SA, rotation, health, owner, and routing details"},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			if cmd.Args().Len() > 1 {
				return cli.Exit("usage: photon links [link-or-peer] [--filter text] [--verbose]", 1)
			}
			filter := cmd.String("filter")
			if cmd.Args().Len() == 1 {
				if filter != "" {
					return cli.Exit("link argument and --filter cannot be used together", 1)
				}
				filter = cmd.Args().First()
			}
			return showLinks(filter, cmd.Bool("verbose"))
		},
		Commands: []*cli.Command{
			{
				Name:      "show",
				Usage:     "Show transport link state",
				UsageText: "photon links show [link-or-peer] [--filter text] [--verbose]",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "filter", Aliases: []string{"f"}, Usage: "Only show links matching peer, id, group, endpoint, interface, or SA"},
					&cli.BoolFlag{Name: "verbose", Aliases: []string{"v"}, Usage: "Show tunnel, SA, rotation, health, owner, and routing details"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() > 1 {
						return cli.Exit("usage: photon links show [link-or-peer] [--filter text] [--verbose]", 1)
					}
					filter := effectiveStringFlag(cmd, "filter")
					if cmd.Args().Len() == 1 {
						if filter != "" {
							return cli.Exit("link argument and --filter cannot be used together", 1)
						}
						filter = cmd.Args().First()
					}
					return showLinks(filter, effectiveBoolFlag(cmd, "verbose"))
				},
			},
		},
	}
}

func cmdRoute() *cli.Command {
	return &cli.Command{
		Name:      "route",
		Usage:     "Show and manage routes and IPAM",
		UsageText: "photon route [--filter text] [--all] [--verbose]",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "filter", Aliases: []string{"f"}, Usage: "Only show routes matching prefix, zone, tag, state, controller, or authorization"},
			&cli.BoolFlag{Name: "all", Usage: "Include withdrawn announcements"},
			&cli.BoolFlag{Name: "verbose", Aliases: []string{"v"}, Usage: "Show controller, authorization, version, and record key"},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			if cmd.Args().Len() != 0 {
				return cli.Exit("usage: photon route [--filter text] [--all] [--verbose]", 1)
			}
			return showRoutes(cmd.String("filter"), cmd.Bool("all"), cmd.Bool("verbose"))
		},
		Commands: []*cli.Command{
			{
				Name:      "show",
				Usage:     "Show route announcements",
				UsageText: "photon route show [--filter text] [--all] [--verbose]",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "filter", Aliases: []string{"f"}, Usage: "Only show routes matching prefix, zone, tag, state, controller, or authorization"},
					&cli.BoolFlag{Name: "all", Usage: "Include withdrawn announcements"},
					&cli.BoolFlag{Name: "verbose", Aliases: []string{"v"}, Usage: "Show controller, authorization, version, and record key"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 0 {
						return cli.Exit("usage: photon route show [--filter text] [--all] [--verbose]", 1)
					}
					return showRoutes(
						effectiveStringFlag(cmd, "filter"),
						effectiveBoolFlag(cmd, "all"),
						effectiveBoolFlag(cmd, "verbose"),
					)
				},
			},
			{
				Name:      "announce",
				Usage:     "Announce a route prefix",
				UsageText: "photon route announce [--direct] <zone> <prefix>",
				Description: "Announce a CIDR prefix from the specified zone.\n" +
					"The prefix is canonicalized before storage (e.g. 10.0.1.1/24 becomes 10.0.1.0/24).",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "direct", Usage: "Write the local DB directly without daemon routing reconcile"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 2 {
						return cli.Exit("usage: photon route announce <zone> <prefix>", 1)
					}
					return announceRoute(zone.ZonePath(cmd.Args().Get(0)), cmd.Args().Get(1), cmd.Bool("direct"))
				},
			},
			{
				Name:      "withdraw",
				Usage:     "Withdraw a route prefix",
				UsageText: "photon route withdraw [--direct] <zone> <prefix>",
				Description: "Withdraw a previously announced CIDR prefix from the specified zone.\n" +
					"The prefix is canonicalized before lookup.",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "direct", Usage: "Write the local DB directly without daemon routing reconcile"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 2 {
						return cli.Exit("usage: photon route withdraw <zone> <prefix>", 1)
					}
					return withdrawRoute(zone.ZonePath(cmd.Args().Get(0)), cmd.Args().Get(1), cmd.Bool("direct"))
				},
			},
			cmdIPAM(),
		},
	}
}

func cmdVerify() *cli.Command {
	return &cli.Command{
		Name:        "verify",
		Usage:       "Verify zone chain integrity",
		UsageText:   "photon debug verify <zone>",
		Description: "Verify the delegation chain for a zone.",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			if cmd.Args().Len() != 1 {
				return cli.Exit("usage: photon debug verify <zone>", 1)
			}
			return verifyChain(zone.ZonePath(cmd.Args().First()))
		},
	}
}

func cmdDaemon() *cli.Command {
	return &cli.Command{
		Name:        "daemon",
		Usage:       "Run the local Photon daemon",
		Description: "Run gossip serving and periodic outbound sync through the Phase 3 daemon service.",
		Flags: []cli.Flag{
			&cli.IntFlag{Name: "interval", Value: int(defaultDaemonInterval.Seconds()), Usage: "Outbound sync interval in seconds"},
			&cli.StringFlag{Name: "cpu-profile", Usage: "Write a bounded CPU profile to a new absolute local path"},
			&cli.DurationFlag{Name: "cpu-profile-duration", Value: defaultCPUProfileDuration, Usage: "CPU profile duration (maximum 30m)"},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			if cmd.Args().Len() != 0 {
				return cli.Exit("usage: photon daemon [--interval seconds] [--cpu-profile absolute-path] [--cpu-profile-duration duration]", 1)
			}
			interval := time.Duration(cmd.Int("interval")) * time.Second
			return daemonRunProfiled(ctx, interval, cmd.String("cpu-profile"), cmd.Duration("cpu-profile-duration"))
		},
	}
}

func cmdSync() *cli.Command {
	return &cli.Command{
		Name:  "sync",
		Usage: "Gossip sync commands",
		Commands: []*cli.Command{
			{
				Name:        "status",
				Usage:       "Show sync and peer status",
				Description: "Display current sync configuration, known peers, and zone digests.",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "verbose", Aliases: []string{"v"}, Usage: "Show bootstrap and allowlist details"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return syncStatus(cmd.Bool("verbose"))
				},
			},
			{
				Name:        "serve",
				Usage:       "Start the gossip sync server",
				Description: "Listen for incoming sync messages and respond to pings/pongs.",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return syncServe(ctx)
				},
			},
			{
				Name:        "run",
				Usage:       "Run gossip serving and periodic outbound sync",
				Description: "Listen for incoming sync messages while periodically syncing bootstrap peers.",
				Flags: []cli.Flag{
					&cli.IntFlag{Name: "interval", Value: 5, Usage: "Outbound sync interval in seconds"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return daemonRun(ctx, time.Duration(cmd.Int("interval"))*time.Second)
				},
			},
			{
				Name:      "once",
				Usage:     "Run a single sync round with a peer",
				UsageText: "photon advanced sync once <peer-id>",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 1 {
						return cli.Exit("usage: photon advanced sync once <peer-id>", 1)
					}
					return syncOnce(cmd.Args().First())
				},
			},
		},
	}
}

func cmdDB() *cli.Command {
	return &cli.Command{
		Name:  "db",
		Usage: "Low-level database inspection commands",
		Commands: []*cli.Command{
			{
				Name:      "dump",
				Usage:     "Dump all database buckets and keys",
				UsageText: "photon debug db dump [zone]",
				Description: "Print every bucket and key in the state database.\n" +
					"If a zone is provided, only that zone bucket is shown (plus meta).",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() > 1 {
						return cli.Exit("usage: photon debug db dump [zone]", 1)
					}
					filter := ""
					if cmd.Args().Len() > 0 {
						filter = cmd.Args().First()
					}
					return dbDump(filter)
				},
			},
			{
				Name:        "stats",
				Usage:       "Show database bucket statistics",
				Description: "Print the number of keys and total size per bucket.",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 0 {
						return cli.Exit("usage: photon debug db stats", 1)
					}
					return dbStats()
				},
			},
		},
	}
}
