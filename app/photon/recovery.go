package main

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	photonlinux "github.com/HiggsNet/photon/internal/photonlinux"
	"github.com/HiggsNet/photon/pkg/core/gossip"
	corehost "github.com/HiggsNet/photon/pkg/core/host"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/urfave/cli/v3"
)

func cmdRecovery() *cli.Command {
	return &cli.Command{
		Name:  "recovery",
		Usage: "Explicit state recovery commands",
		Commands: []*cli.Command{
			{
				Name:      "export-zone",
				Usage:     "Export a signed zone snapshot to a file or stdout",
				UsageText: "photon advanced recovery export-zone <zone> [snapshot.b64]",
				Description: "Export the active ZoneSnapshot from the local state as base64 JSON.\n" +
					"This is useful when an offline root/admin node needs to carry signed records to an online peer.",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() < 1 || cmd.Args().Len() > 2 {
						return cli.Exit("usage: photon advanced recovery export-zone <zone> [snapshot.b64]", 1)
					}
					return recoveryExportZone(zone.ZonePath(cmd.Args().Get(0)), cmd.Args().Get(1))
				},
			},
			{
				Name:      "import-zone",
				Usage:     "Import a signed zone snapshot from a file or payload",
				UsageText: "photon advanced recovery import-zone [--direct] <snapshot-b64|snapshot-file>",
				Description: "Import a signed ZoneSnapshot into the local state after normal signature and delegation-chain verification.\n" +
					"This accepts snapshots created by advanced recovery export-zone.",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "direct", Usage: "Write the local DB directly without contacting the daemon"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 1 {
						return cli.Exit("usage: photon advanced recovery import-zone <snapshot-b64|snapshot-file>", 1)
					}
					return recoveryImportZone(cmd.Args().First(), cmd.Bool("direct"))
				},
			},
			{
				Name:      "pull-zone",
				Usage:     "Recover a signed zone snapshot from a peer",
				UsageText: "photon advanced recovery pull-zone <zone> --from <peer-id>",
				Description: "Pull a ZoneSnapshot over object-pull TCP and apply it after normal signature and delegation-chain verification.\n" +
					"This explicit recovery path may restore this node's managed zone, unlike ordinary gossip sync.",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "from", Usage: "Peer ID to pull the snapshot from", Required: true},
					&cli.IntFlag{Name: "timeout", Value: 5, Usage: "Recovery pull timeout in seconds"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 1 {
						return cli.Exit("usage: photon advanced recovery pull-zone <zone> --from <peer-id>", 1)
					}
					timeout := time.Duration(cmd.Int("timeout")) * time.Second
					return recoveryPullZone(ctx, zone.ZonePath(cmd.Args().First()), cmd.String("from"), timeout)
				},
			},
			{
				Name:        "pull-chain",
				Usage:       "Recover a zone and its ancestor chain from a peer",
				UsageText:   "photon advanced recovery pull-chain <zone> --from <peer-id>",
				Description: "Pull root-to-zone snapshots in trust-chain order, so deeper delegated zones can be recovered from an empty bootstrap DB.",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "from", Usage: "Peer ID to pull snapshots from", Required: true},
					&cli.IntFlag{Name: "timeout", Value: 5, Usage: "Total recovery pull timeout in seconds"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 1 {
						return cli.Exit("usage: photon advanced recovery pull-chain <zone> --from <peer-id>", 1)
					}
					timeout := time.Duration(cmd.Int("timeout")) * time.Second
					return recoveryPullChain(ctx, zone.ZonePath(cmd.Args().First()), cmd.String("from"), timeout)
				},
			},
			{
				Name:      "cleanup-ipsec",
				Usage:     "Tear down locally managed IPsec links",
				UsageText: "photon advanced recovery cleanup-ipsec [--orphans] [--direct]",
				Description: "Explicitly terminate Photon-managed StrongSwan connections and delete their XFRM interfaces.\n" +
					"This is intended for local recovery after system networking state becomes inconsistent.",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "orphans", Usage: "Also terminate/unload Photon-named StrongSwan connections not referenced by local state"},
					&cli.BoolFlag{Name: "direct", Usage: "Run cleanup in this process without contacting the daemon"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 0 {
						return cli.Exit("usage: photon advanced recovery cleanup-ipsec [--orphans]", 1)
					}
					return recoveryCleanupIPsec(ctx, cmd.Bool("orphans"), cmd.Bool("direct"))
				},
			},
			{
				Name:      "purge-revoked",
				Usage:     "Remove revoked zones' local residue (dry-run by default)",
				UsageText: "photon advanced recovery purge-revoked [--zone <zone>] [--apply] [--direct]",
				Description: "Hard-delete the local residue of revoked zones: their ZoneState bodies in the DB, " +
					"plus LinkInstances and SyncPeers entries pointing at them.\n" +
					"Without --apply this only prints a preview and changes nothing. " +
					"Without --zone every currently-revoked zone is targeted; with --zone only that zone " +
					"(which must be revoked) and its descendant subtree are targeted. " +
					"Parent revocation tombstones are always preserved so revoked names cannot be re-delegated " +
					"at a stale epoch, and the local node's own managed-zone identity chain is never touched.",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "zone", Usage: "Limit the purge to a single revoked zone (and its subtree)"},
					&cli.BoolFlag{Name: "apply", Usage: "Actually delete; without it the command only prints a preview"},
					&cli.BoolFlag{Name: "direct", Usage: "Apply cleanup in this process without contacting the daemon"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 0 {
						return cli.Exit("usage: photon advanced recovery purge-revoked [--zone <zone>] [--apply]", 1)
					}
					return recoveryPurgeRevoked(ctx, cmd.Bool("apply"), zone.ZonePath(cmd.String("zone")), cmd.Bool("direct"))
				},
			},
		},
	}
}

func recoveryExportZone(path zone.ZonePath, outPath string) error {
	if !path.Valid() {
		return zone.ErrInvalidZonePath
	}
	rt, err := NewAppContext()
	if err != nil {
		return err
	}
	boltStore, startup, err := openLinuxDaemonState(rt)
	if err != nil {
		return err
	}
	defer boltStore.Close()
	defer startup.Common.Close()
	view := startup.Common.ReadView()
	if view.State == nil {
		return errors.New("common state is not initialized")
	}
	snapshot, err := corestate.Snapshot(view.State.Network, path)
	if err != nil {
		return err
	}
	if outPath == "" {
		text, err := encodeBase64JSON(snapshot)
		if err != nil {
			return err
		}
		fmt.Println(text)
		return nil
	}
	if err := writeBase64JSONFile(outPath, 0o644, snapshot); err != nil {
		return err
	}
	fmt.Printf("exported zone %s snapshot: %s\n", path, outPath)
	return nil
}

func recoveryImportZone(input string, direct bool) error {
	var snapshot corestate.ZoneSnapshot
	if err := readBase64JSONOrJSON(input, &snapshot); err != nil {
		return err
	}
	rt, err := NewAppContext()
	if err != nil {
		return err
	}
	rt.DisableControl = direct
	if result, revocations, ok, err := importRecoveryZoneViaControl(rt, &snapshot); err != nil {
		return err
	} else if ok {
		printRecoveryImportResult(result, revocations, " via daemon")
		return nil
	}
	if !direct {
		logControlFallback("recovery_import_zone")
	}
	boltStore, startup, err := openLinuxDaemonState(rt)
	if err != nil {
		return err
	}
	defer boltStore.Close()
	defer startup.Common.Close()
	view := startup.Common.ReadView()
	if view.State == nil {
		return errors.New("common state is not initialized")
	}
	config := gossipStartupConfigFromAppConfig(rt.Config, view.State)
	limits := syncLimits(config)
	limits.MaxBytes = 8 << 20
	imported, err := startup.Common.ImportRecoverySnapshot(context.Background(), corestate.RecoveryImport{
		Snapshot: &snapshot,
		Limits:   limits,
	}, rt.Now())
	if err != nil {
		return err
	}
	if imported.Apply == nil {
		return errors.New("recovery import returned no result")
	}
	view = startup.Common.ReadView()
	revocations := 0
	if view.State != nil && view.State.Network != nil {
		if zs := view.State.Network.Zones[imported.Apply.Zone]; zs != nil {
			revocations = len(zs.Revocations)
		}
	}
	printRecoveryImportResult(imported.Apply, revocations, "")
	return nil
}

func printRecoveryImportResult(result *corestate.ApplyResult, revocations int, suffix string) {
	fmt.Printf("imported zone %s snapshot%s: network_changed=%t records_applied=%d delegations=%d revocations=%d\n",
		result.Zone, suffix, result.NetworkChanged, result.Records, result.Delegation, revocations)
}

func recoveryPullZone(ctx context.Context, path zone.ZonePath, peerID string, timeout time.Duration) error {
	if !path.Valid() {
		return zone.ErrInvalidZonePath
	}
	if peerID == "" {
		return errors.New("recovery peer is required")
	}
	if timeout <= 0 {
		return errors.New("recovery timeout must be positive")
	}
	return recoveryPullZones(ctx, []zone.ZonePath{path}, peerID, timeout)
}

func recoveryPullChain(ctx context.Context, path zone.ZonePath, peerID string, timeout time.Duration) error {
	if !path.Valid() {
		return zone.ErrInvalidZonePath
	}
	return recoveryPullZones(ctx, recoveryChainZones(path), peerID, timeout)
}

func recoveryPullZones(ctx context.Context, paths []zone.ZonePath, peerID string, timeout time.Duration) error {
	if len(paths) == 0 {
		return errors.New("recovery zone is required")
	}
	if peerID == "" {
		return errors.New("recovery peer is required")
	}
	if timeout <= 0 {
		return errors.New("recovery timeout must be positive")
	}
	rt, err := NewAppContext()
	if err != nil {
		return err
	}
	boltStore, startup, err := openLinuxDaemonState(rt)
	if err != nil {
		return err
	}
	defer boltStore.Close()
	defer startup.Common.Close()
	view := startup.Common.ReadView()
	if view.State == nil {
		return errors.New("common state is not initialized")
	}
	config := gossipStartupConfigFromAppConfig(rt.Config, view.State)
	limits := syncLimits(config)
	limits.MaxBytes = 8 << 20
	gossipDriver := corehost.NewGossipDriver(corehost.NewClock(rt.Now), corehost.DefaultEventBuffer, startup.Common, gossipDriverConfig(config, rt.Config, newAppLogger(rt.Config)))
	defer gossipDriver.Stop()

	deadline := time.Now().Add(timeout)
	pullExecutor := corehost.NewGossipObjectPullExecutor(corehost.GossipObjectPullExecutorConfig{
		Client: photonlinux.GossipObjectPullClient{},
		Now:    rt.Now,
	})
	results := make([]*corestate.ApplyResult, 0, len(paths))
	// Commit each ancestor before validating its child. An interrupted chain
	// recovery may leave a valid recovered prefix, never an unverified child.
	for _, path := range paths {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		input := gossipDriver.GossipDiscoveryInput(peerCleanupSuppressions(startup.Runtime.PeerCleanups))
		pullCtx, cancel := context.WithDeadline(ctx, deadline)
		completion := pullExecutor.PullFrom(pullCtx, input, gossip.StartObjectPullAction{PeerID: peerID, Zone: path})
		cancel()
		if completion.Err != nil {
			return fmt.Errorf("recover %s from %s: %w", path, peerID, completion.Err)
		}
		imported, err := startup.Common.ImportRecoverySnapshot(ctx, corestate.RecoveryImport{Snapshot: completion.Snapshot, Limits: limits}, rt.Now())
		if err != nil {
			return fmt.Errorf("recover %s from %s: %w", path, peerID, err)
		}
		if imported.Apply == nil {
			return fmt.Errorf("recover %s from %s: recovery import returned no result", path, peerID)
		}
		results = append(results, imported.Apply)
	}
	view = startup.Common.ReadView()
	for _, result := range results {
		revocations := 0
		if view.State != nil && view.State.Network != nil {
			if zs := view.State.Network.Zones[result.Zone]; zs != nil {
				revocations = len(zs.Revocations)
			}
		}
		fmt.Printf("recovered zone %s from %s: network_changed=%t records_applied=%d delegations=%d revocations=%d\n",
			result.Zone, peerID, result.NetworkChanged, result.Records, result.Delegation, revocations)
	}
	return nil
}

func recoveryChainZones(path zone.ZonePath) []zone.ZonePath {
	ancestors := path.Ancestors()
	out := make([]zone.ZonePath, 0, len(ancestors))
	for _, ancestor := range slices.Backward(ancestors) {
		out = append(out, ancestor)
	}
	return out
}

func recoveryPurgeRevoked(ctx context.Context, apply bool, target zone.ZonePath, direct bool) error {
	rt, err := NewAppContext()
	if err != nil {
		return err
	}
	rt.DisableControl = direct
	// Only --apply talks to the daemon so the running node can observe the
	// deletion and reconcile (tear down orphaned IPsec, etc.). A dry-run is a
	// pure local computation and never reaches the daemon.
	if apply {
		plan, controlled, err := purgeRevokedViaControl(rt, apply, target)
		if err != nil {
			return err
		}
		if controlled {
			printPurgePlan(plan, " via daemon")
			return nil
		}
		if !direct {
			logControlFallback("recovery_purge_revoked")
		}
	}
	boltStore, startup, err := openLinuxDaemonState(rt)
	if err != nil {
		return err
	}
	defer boltStore.Close()
	defer startup.Common.Close()
	now := rt.Now()
	commonPlan, err := startup.Common.PlanPurgeRevoked(now, target)
	if err != nil {
		return err
	}
	plan := mergePurgePlan(commonPlan, startup.Runtime)
	if apply {
		view := startup.Common.ReadView()
		runtimeCandidate := photonlinux.CloneRuntimeState(startup.Runtime)
		if err := cleanupPurgePlanIPsecLinks(ctx, rt, runtimeCandidate, plan); err != nil {
			return err
		}
		for _, peerID := range plan.SyncPeers {
			delete(runtimeCandidate.PeerCleanups, peerID)
		}
		if err := photonlinux.CommitRuntimeState(boltStore, view.Revision, runtimeCandidate); err != nil {
			return err
		}
		if _, err := startup.Common.PurgeRevoked(ctx, now, target); err != nil {
			return err
		}
	}
	printPurgePlan(plan, purgePlanSuffix(apply))
	if !apply {
		fmt.Println("(dry-run; pass --apply to delete)")
	}
	return nil
}

func cleanupPurgePlanIPsecLinks(ctx context.Context, rt *AppContext, runtime *linuxRuntimeState, plan *purgePlan) error {
	if plan == nil || len(plan.LinkInstances) == 0 {
		return nil
	}
	if rt == nil {
		return errors.New("runtime is nil")
	}
	platformDriver, err := newLinuxDriverForIPsecCleanup(rt.Config)
	if err != nil {
		return err
	}
	defer func() { _ = platformDriver.Close() }()
	_, err = cleanupLinuxDriverIPsecLinks(ctx, runtime, plan.LinkInstances, platformDriver, rt.Now())
	return err
}

func purgePlanSuffix(apply bool) string {
	if apply {
		return " applied"
	}
	return ""
}

func printPurgePlan(plan *purgePlan, suffix string) {
	if plan == nil {
		fmt.Printf("purge plan%s: unavailable\n", suffix)
		return
	}
	fmt.Printf("purge plan%s: zones=%d link_instances=%d sync_peers=%d\n",
		suffix, len(plan.Zones), len(plan.LinkInstances), len(plan.SyncPeers))
	zones := append([]zone.ZonePath(nil), plan.Zones...)
	inspect.SortZonePaths(zones)
	for _, z := range zones {
		fmt.Printf("  zone %s\n", z)
	}
	for _, id := range plan.LinkInstances {
		fmt.Printf("  link_instance %s\n", id)
	}
	syncPeers := append([]string(nil), plan.SyncPeers...)
	inspect.SortZoneStrings(syncPeers)
	for _, peerID := range syncPeers {
		fmt.Printf("  sync_peer %s\n", peerID)
	}
	skipped := append([]zone.ZonePath(nil), plan.ManagedZoneSkipped...)
	inspect.SortZonePaths(skipped)
	for _, z := range skipped {
		fmt.Printf("  skipped (local identity) %s\n", z)
	}
}
