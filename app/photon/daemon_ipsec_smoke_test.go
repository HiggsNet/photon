package main

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/photonlinux"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestDaemonReconcileUsesSystemXFRMDriverSmoke(t *testing.T) {
	if os.Getenv("PHOTON_IPSEC_XFRM_SMOKE") != "1" {
		t.Skip("set PHOTON_IPSEC_XFRM_SMOKE=1 to run the root/system XFRM smoke")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	now := time.Unix(4060, 0)
	addTestIPsecRecords(t, verified.Network.Zones["node-b.catofes."], "node-b.catofes.", now, ipsec.RoleIn)

	ns := "photon-daemon-xfrm-" + time.Now().UTC().Format("20060102150405")
	group := testIPsecLinkGroup()
	group.NetNS = ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: ns, Create: true}
	setTestIPsecOverlayIntent(t, verified.Network.Zones["node-b.catofes."], "node-b.catofes.", group, now)
	appConfig := defaultAppConfig()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{group}
	rt := &testApp{Config: appConfig, Clock: func() time.Time { return now }}
	t.Cleanup(func() {
		_, _ = appExecCommand(context.Background(), "ip", "netns", "delete", ns)
	})

	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, config, time.Second)
	installTestIPsecDrivers(service, &observedIPsecDriver{}, ipsec.NewSystemXFRMDriver(group.NetNS))
	service.recoverIPsecLinksOnStart(ctx)

	latestLinks, latestReconcile := readTestIPsecObservation(service)
	if latestReconcile == nil || latestReconcile.LastFailure != nil {
		t.Fatalf("ipsec reconcile = %+v, want successful system xfrm apply", latestReconcile)
	}
	if len(latestLinks) != 1 {
		t.Fatalf("link instances = %+v, want one system-applied link", latestLinks)
	}
	var inst ipsec.LinkInstance
	for _, item := range latestLinks {
		inst = item
	}
	if inst.ActualState != ipsec.LinkStateConnecting {
		t.Fatalf("instance state = %+v, want connecting after provider apply", inst)
	}
	if _, err := appExecCommand(ctx, "ip", "netns", "exec", ns, "ip", "link", "show", "dev", inst.InterfaceName); err != nil {
		t.Fatalf("daemon-created xfrm interface %s not visible in %s: %v", inst.InterfaceName, ns, err)
	}
	if _, err := appExecCommand(ctx, "ip", "netns", "exec", ns, "ip", "addr", "show", "dev", inst.InterfaceName); err != nil {
		t.Fatalf("daemon-assigned tunnel address not visible on %s/%s: %v", ns, inst.InterfaceName, err)
	}

	service.Config.IPsec.LinkGroups = nil
	service.recoverIPsecLinksOnStart(ctx)
	removedLinks, removedReconcile := readTestIPsecObservation(service)
	if removedReconcile == nil || removedReconcile.LastFailure != nil {
		t.Fatalf("teardown reconcile = %+v, want successful system xfrm teardown", removedReconcile)
	}
	if len(removedLinks) != 0 {
		t.Fatalf("link instances after teardown = %+v, want none", removedLinks)
	}
	if _, err := appExecCommand(ctx, "ip", "netns", "exec", ns, "ip", "link", "show", "dev", inst.InterfaceName); err == nil {
		t.Fatalf("daemon-created xfrm interface %s still exists after teardown", inst.InterfaceName)
	}
}

func TestDaemonStrongSwanReconcileBringupSmoke(t *testing.T) {
	if os.Getenv("PHOTON_IPSEC_XFRM_SMOKE") != "1" {
		t.Skip("set PHOTON_IPSEC_XFRM_SMOKE=1 to run the root/system StrongSwan daemon smoke")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 70*time.Second)
	defer cancel()

	suffix := time.Now().UTC().Format("20060102150405")
	nsA := "photon-daemon-ike-a-" + suffix
	nsB := "photon-daemon-ike-b-" + suffix
	viciA := "/tmp/charon-" + nsA + ".vici"
	viciB := "/tmp/charon-" + nsB + ".vici"
	t.Cleanup(func() {
		_, _ = appExecCommand(context.Background(), "ip", "netns", "delete", nsA)
		_, _ = appExecCommand(context.Background(), "ip", "netns", "delete", nsB)
		_ = os.Remove(viciA)
		_ = os.Remove(viciB)
	})

	runAppCommand(t, ctx, "ip", "netns", "add", nsA)
	runAppCommand(t, ctx, "ip", "netns", "add", nsB)
	runAppCommand(t, ctx, "ip", "link", "add", "hgdvetha", "type", "veth", "peer", "name", "hgdvethb")
	runAppCommand(t, ctx, "ip", "link", "set", "hgdvetha", "netns", nsA)
	runAppCommand(t, ctx, "ip", "link", "set", "hgdvethb", "netns", nsB)
	for _, args := range [][]string{
		{"netns", "exec", nsA, "ip", "link", "set", "lo", "up"},
		{"netns", "exec", nsB, "ip", "link", "set", "lo", "up"},
		{"netns", "exec", nsA, "ip", "addr", "add", "192.0.2.1/30", "dev", "hgdvetha"},
		{"netns", "exec", nsB, "ip", "addr", "add", "192.0.2.2/30", "dev", "hgdvethb"},
		{"netns", "exec", nsA, "ip", "link", "set", "hgdvetha", "up"},
		{"netns", "exec", nsB, "ip", "link", "set", "hgdvethb", "up"},
	} {
		runAppCommand(t, ctx, "ip", args...)
	}

	confA, err := writeDaemonStrongSwanConf(viciA)
	if err != nil {
		t.Fatalf("write strongswan.conf A: %v", err)
	}
	confB, err := writeDaemonStrongSwanConf(viciB)
	if err != nil {
		t.Fatalf("write strongswan.conf B: %v", err)
	}
	piddirA := t.TempDir()
	piddirB := t.TempDir()
	logA, err := os.CreateTemp("", "photon-daemon-charon-a-*.log")
	if err != nil {
		t.Fatalf("create charon A log: %v", err)
	}
	logB, err := os.CreateTemp("", "photon-daemon-charon-b-*.log")
	if err != nil {
		t.Fatalf("create charon B log: %v", err)
	}
	charonA := startDaemonTestCharonInNetNS(ctx, t, nsA, piddirA, confA, logA)
	charonB := startDaemonTestCharonInNetNS(ctx, t, nsB, piddirB, confB, logB)
	defer func() {
		_ = charonA.Process.Kill()
		_ = charonB.Process.Kill()
		_ = charonA.Wait()
		_ = charonB.Wait()
		_ = os.Remove(confA)
		_ = os.Remove(confB)
		_ = logA.Close()
		_ = logB.Close()
		_ = os.Remove(logA.Name())
		_ = os.Remove(logB.Name())
	}()
	clientA, err := waitDaemonTestVICI(ctx, viciA)
	if err != nil {
		t.Fatalf("connect to charon A VICI: %v", err)
	}
	defer clientA.Close()
	clientB, err := waitDaemonTestVICI(ctx, viciB)
	if err != nil {
		t.Fatalf("connect to charon B VICI: %v", err)
	}
	defer clientB.Close()
	defer func() {
		if t.Failed() {
			dumpCtx, dumpCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer dumpCancel()
			logDaemonTestFile(t, "charon A", logA.Name())
			logDaemonTestFile(t, "charon B", logB.Name())
			dumpDaemonSystemState(t, dumpCtx, nsA, nsB)
			dumpDaemonVICISAs(t, dumpCtx, viciA, "A")
			dumpDaemonVICISAs(t, dumpCtx, viciB, "B")
		}
	}()

	now := time.Unix(4140, 0)
	verifiedA, configA, verifiedB, configB := buildTestABVerifiedStates(t)
	runtimeA, runtimeB := &photonlinux.LinuxState{}, &photonlinux.LinuxState{}
	keyA, recordA := daemonTestTransportKey(t, now)
	keyB, recordB := daemonTestTransportKey(t, now)
	runtimeA.IPsecTransportKey = keyA
	runtimeB.IPsecTransportKey = keyB
	addDaemonTestIPsecRecords(t, verifiedA.Network.Zones["node-a.catofes."], "node-a.catofes.", "192.0.2.1", recordA, ipsec.RoleOut, now)
	addDaemonTestIPsecRecords(t, verifiedB.Network.Zones["node-b.catofes."], "node-b.catofes.", "192.0.2.2", recordB, ipsec.RoleIn, now)
	verifiedA.Network.Zones["node-b.catofes."] = verifiedB.Network.Zones["node-b.catofes."]
	verifiedB.Network.Zones["node-a.catofes."] = verifiedA.Network.Zones["node-a.catofes."]

	groupA := testIPsecLinkGroup()
	groupA.ConnectRules = nil
	groupA.NetNS = ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: nsA, Create: false}
	groupA.TunnelAddressSpec = ipsec.TunnelAddressSpec{Mode: ipsec.TunnelAddressDerivedLinkLocal, Family: ipsec.FamilyIPv6}
	groupA.Reconcile.RotateRetentionSeconds = 0
	groupB := testIPsecLinkGroup()
	groupB.ConnectRules = nil
	groupB.NetNS = ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: nsB, Create: false}
	groupB.TunnelAddressSpec = ipsec.TunnelAddressSpec{Mode: ipsec.TunnelAddressDerivedLinkLocal, Family: ipsec.FamilyIPv6}
	groupB.Reconcile.RotateRetentionSeconds = 0
	rtA := &testApp{Config: testDaemonIPsecAppConfig(t.TempDir(), "127.0.0.1:0", groupA), Clock: func() time.Time { return now }}
	rtB := &testApp{Config: testDaemonIPsecAppConfig(t.TempDir(), "127.0.0.1:0", groupB), Clock: func() time.Time { return now }}
	driverA := &ipsec.StrongSwanDriver{VICI: clientA, KeyDir: t.TempDir()}
	driverB := &ipsec.StrongSwanDriver{VICI: clientB, KeyDir: t.TempDir()}
	serviceA := newTestDaemonFromOwners(rtA, verifiedA, nil, runtimeA, configA, time.Second)
	installTestIPsecDrivers(serviceA, driverA, daemonTestXFRMDriver(groupA.NetNS, nsA))
	serviceB := newTestDaemonFromOwners(rtB, verifiedB, nil, runtimeB, configB, time.Second)
	installTestIPsecDrivers(serviceB, driverB, daemonTestXFRMDriver(groupB.NetNS, nsB))

	serviceB.recoverIPsecLinksOnStart(ctx)
	serviceA.recoverIPsecLinksOnStart(ctx)
	commonA := serviceA.State.Common.ReadView()
	persistedA := serviceA.State.ReadLinux()
	commonB := serviceB.State.Common.ReadView()
	persistedB := serviceB.State.ReadLinux()
	specA := daemonSystemDesiredSpec(t, commonA.State, persistedA.IPsecTransportKey, groupA, now)
	specB := daemonSystemDesiredSpec(t, commonB.State, persistedB.IPsecTransportKey, groupB, now)
	if err := waitDaemonTestSA(ctx, clientA, specA.TransportID); err != nil {
		t.Fatalf("wait for daemon SA on A: %v", err)
	}
	if err := waitDaemonTestSA(ctx, clientB, specB.TransportID); err != nil {
		t.Fatalf("wait for daemon SA on B: %v", err)
	}

	serviceA.recoverIPsecLinksOnStart(ctx)
	serviceB.recoverIPsecLinksOnStart(ctx)
	latestALinks, latestAReconcile := readTestIPsecObservation(serviceA)
	latestBLinks, latestBReconcile := readTestIPsecObservation(serviceB)
	assertDaemonSystemLinkUp(t, latestALinks, latestAReconcile, specA)
	assertDaemonSystemLinkUp(t, latestBLinks, latestBReconcile, specB)

	addTunnelRoute(t, ctx, nsA, specA)
	addTunnelRoute(t, ctx, nsB, specB)
	pingTunnelAddr(t, ctx, nsA, specA.PeerTunnelAddr, specA.InterfaceName)
	pingTunnelAddr(t, ctx, nsB, specB.PeerTunnelAddr, specB.InterfaceName)

	restartedCommonA := serviceA.State.Common.ReadView()
	restartedA := serviceA.State.ReadLinux()
	restartServiceA := newTestDaemonFromOwners(rtA, restartedCommonA.State, restartedCommonA.Gossip, restartedA, configA, time.Second)
	installTestIPsecDrivers(restartServiceA, &ipsec.StrongSwanDriver{VICI: clientA, KeyDir: t.TempDir()}, daemonTestXFRMDriver(groupA.NetNS, nsA))
	restartServiceA.recoverIPsecLinksOnStart(ctx)
	recoveredCommonA := restartServiceA.State.Common.ReadView()
	recoveredRuntimeA := restartServiceA.State.ReadLinux()
	recoveredALinks, recoveredAReconcile := readTestIPsecObservation(restartServiceA)
	assertDaemonSystemLinkUp(t, recoveredALinks, recoveredAReconcile, specA)
	if recoveredAReconcile == nil || len(recoveredAReconcile.Actions) != 1 {
		t.Fatalf("restart reconcile = %+v, want one recovery observation action", recoveredAReconcile)
	}
	restartAction := recoveredAReconcile.Actions[0].Action
	if restartAction != ipsec.ReconcileActionAdopt && restartAction != ipsec.ReconcileActionNoop {
		t.Fatalf("restart reconcile action = %s, want adopt or noop with existing SA", restartAction)
	}
	if count, err := daemonTestEstablishedSACount(ctx, clientA, specA.TransportID); err != nil {
		t.Fatalf("count node-a SAs after restart: %v", err)
	} else if count != 1 {
		t.Fatalf("node-a established SA count after restart = %d, want 1", count)
	}
	pingTunnelAddr(t, ctx, nsA, specA.PeerTunnelAddr, specA.InterfaceName)

	parent := recoveredCommonA.State.Network.Zones["catofes."]
	if parent == nil || parent.Delegations["node-b.catofes."] == nil {
		t.Fatalf("node-a state missing node-b delegation before revoke")
	}
	delegation := parent.Delegations["node-b.catofes."]
	parent.Revocations["node-b.catofes."] = &zone.DelegationRevocation{
		ChildZone:             "node-b.catofes.",
		ParentZone:            "catofes.",
		RevokedAuthorityEpoch: delegation.AuthorityEpoch,
		RevokedAuthorityHash:  delegation.AuthorityHash,
		Reason:                "ipsec root smoke revoke",
		RevokedAt:             now.Add(-time.Second).Unix(),
	}
	restartServiceA = newTestDaemonFromOwners(rtA, recoveredCommonA.State, recoveredCommonA.Gossip, recoveredRuntimeA, configA, time.Second)
	installTestIPsecDrivers(restartServiceA, &ipsec.StrongSwanDriver{VICI: clientA, KeyDir: t.TempDir()}, daemonTestXFRMDriver(groupA.NetNS, nsA))
	restartServiceA.recoverIPsecLinksOnStart(ctx)
	revokedALinks, revokedAReconcile := readTestIPsecObservation(restartServiceA)
	if len(revokedALinks) != 0 {
		t.Fatalf("node-a link instances after revoke = %+v, want none", revokedALinks)
	}
	if revokedAReconcile == nil || len(revokedAReconcile.Actions) != 1 || revokedAReconcile.Actions[0].Action != ipsec.ReconcileActionTeardown {
		t.Fatalf("revoke reconcile = %+v, want teardown", revokedAReconcile)
	}
	if !hasDebugSkip(revokedAReconcile.Skipped, "node-b.catofes.", ipsec.SkipRevokedZone) {
		t.Fatalf("revoke skips = %+v, want revoked node-b", revokedAReconcile.Skipped)
	}
	if err := waitDaemonTestNoSA(ctx, clientA, specA.TransportID); err != nil {
		t.Fatalf("node-a SA after revoke: %v", err)
	}
	if _, err := appExecCommand(ctx, "ip", "netns", "exec", nsA, "ip", "link", "show", "dev", specA.InterfaceName); err == nil {
		t.Fatalf("node-a xfrm interface %s still exists after revoke", specA.InterfaceName)
	}
	if out := pingTunnelAddrShouldFail(t, ctx, nsA, specA.PeerTunnelAddr, specA.InterfaceName); out != nil {
		t.Logf("post-revoke ping failed as expected: %s", string(out))
	}
}

func TestDaemonStrongSwanReconcileBringupDerivedPoolSmoke(t *testing.T) {
	if os.Getenv("PHOTON_IPSEC_XFRM_SMOKE") != "1" {
		t.Skip("set PHOTON_IPSEC_XFRM_SMOKE=1 to run the root/system StrongSwan daemon smoke")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 70*time.Second)
	defer cancel()

	suffix := time.Now().UTC().Format("20060102150405")
	nsA := "photon-daemon-pool-a-" + suffix
	nsB := "photon-daemon-pool-b-" + suffix
	viciA := "/tmp/charon-" + nsA + ".vici"
	viciB := "/tmp/charon-" + nsB + ".vici"
	t.Cleanup(func() {
		_, _ = appExecCommand(context.Background(), "ip", "netns", "delete", nsA)
		_, _ = appExecCommand(context.Background(), "ip", "netns", "delete", nsB)
		_ = os.Remove(viciA)
		_ = os.Remove(viciB)
	})

	runAppCommand(t, ctx, "ip", "netns", "add", nsA)
	runAppCommand(t, ctx, "ip", "netns", "add", nsB)
	runAppCommand(t, ctx, "ip", "link", "add", "hgdpoola", "type", "veth", "peer", "name", "hgdpoolb")
	runAppCommand(t, ctx, "ip", "link", "set", "hgdpoola", "netns", nsA)
	runAppCommand(t, ctx, "ip", "link", "set", "hgdpoolb", "netns", nsB)
	for _, args := range [][]string{
		{"netns", "exec", nsA, "ip", "link", "set", "lo", "up"},
		{"netns", "exec", nsB, "ip", "link", "set", "lo", "up"},
		{"netns", "exec", nsA, "ip", "addr", "add", "192.0.2.1/30", "dev", "hgdpoola"},
		{"netns", "exec", nsB, "ip", "addr", "add", "192.0.2.2/30", "dev", "hgdpoolb"},
		{"netns", "exec", nsA, "ip", "link", "set", "hgdpoola", "up"},
		{"netns", "exec", nsB, "ip", "link", "set", "hgdpoolb", "up"},
	} {
		runAppCommand(t, ctx, "ip", args...)
	}

	confA, err := writeDaemonStrongSwanConf(viciA)
	if err != nil {
		t.Fatalf("write strongswan.conf A: %v", err)
	}
	confB, err := writeDaemonStrongSwanConf(viciB)
	if err != nil {
		t.Fatalf("write strongswan.conf B: %v", err)
	}
	piddirA := t.TempDir()
	piddirB := t.TempDir()
	logA, err := os.CreateTemp("", "photon-daemon-charon-pool-a-*.log")
	if err != nil {
		t.Fatalf("create charon A log: %v", err)
	}
	logB, err := os.CreateTemp("", "photon-daemon-charon-pool-b-*.log")
	if err != nil {
		t.Fatalf("create charon B log: %v", err)
	}
	charonA := startDaemonTestCharonInNetNS(ctx, t, nsA, piddirA, confA, logA)
	charonB := startDaemonTestCharonInNetNS(ctx, t, nsB, piddirB, confB, logB)
	defer func() {
		_ = charonA.Process.Kill()
		_ = charonB.Process.Kill()
		_ = charonA.Wait()
		_ = charonB.Wait()
		_ = os.Remove(confA)
		_ = os.Remove(confB)
		_ = logA.Close()
		_ = logB.Close()
		_ = os.Remove(logA.Name())
		_ = os.Remove(logB.Name())
	}()
	clientA, err := waitDaemonTestVICI(ctx, viciA)
	if err != nil {
		t.Fatalf("connect to charon A VICI: %v", err)
	}
	defer clientA.Close()
	clientB, err := waitDaemonTestVICI(ctx, viciB)
	if err != nil {
		t.Fatalf("connect to charon B VICI: %v", err)
	}
	defer clientB.Close()
	defer func() {
		if t.Failed() {
			dumpCtx, dumpCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer dumpCancel()
			logDaemonTestFile(t, "charon A", logA.Name())
			logDaemonTestFile(t, "charon B", logB.Name())
			dumpDaemonSystemState(t, dumpCtx, nsA, nsB)
			dumpDaemonVICISAs(t, dumpCtx, viciA, "A")
			dumpDaemonVICISAs(t, dumpCtx, viciB, "B")
		}
	}()

	now := time.Unix(4140, 0)
	verifiedA, configA, verifiedB, configB := buildTestABVerifiedStates(t)
	runtimeA, runtimeB := &photonlinux.LinuxState{}, &photonlinux.LinuxState{}
	keyA, recordA := daemonTestTransportKey(t, now)
	keyB, recordB := daemonTestTransportKey(t, now)
	runtimeA.IPsecTransportKey = keyA
	runtimeB.IPsecTransportKey = keyB
	addDaemonTestIPsecRecords(t, verifiedA.Network.Zones["node-a.catofes."], "node-a.catofes.", "192.0.2.1", recordA, ipsec.RoleOut, now)
	addDaemonTestIPsecRecords(t, verifiedB.Network.Zones["node-b.catofes."], "node-b.catofes.", "192.0.2.2", recordB, ipsec.RoleIn, now)
	verifiedA.Network.Zones["node-b.catofes."] = verifiedB.Network.Zones["node-b.catofes."]
	verifiedB.Network.Zones["node-a.catofes."] = verifiedA.Network.Zones["node-a.catofes."]

	pool := netip.MustParsePrefix("10.88.0.0/24")
	groupA := testIPsecLinkGroup()
	groupA.ConnectRules = nil
	groupA.NetNS = ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: nsA, Create: false}
	groupA.TunnelAddressSpec = ipsec.TunnelAddressSpec{Mode: ipsec.TunnelAddressDerivedPool, Family: ipsec.FamilyIPv4, Pool: pool}
	groupB := testIPsecLinkGroup()
	groupB.ConnectRules = nil
	groupB.NetNS = ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: nsB, Create: false}
	groupB.TunnelAddressSpec = ipsec.TunnelAddressSpec{Mode: ipsec.TunnelAddressDerivedPool, Family: ipsec.FamilyIPv4, Pool: pool}
	setTestIPsecOverlayIntent(t, verifiedA.Network.Zones["node-a.catofes."], "node-a.catofes.", groupA, now)
	setTestIPsecOverlayIntent(t, verifiedA.Network.Zones["node-b.catofes."], "node-b.catofes.", groupB, now)
	setTestIPsecOverlayIntent(t, verifiedB.Network.Zones["node-a.catofes."], "node-a.catofes.", groupA, now)
	setTestIPsecOverlayIntent(t, verifiedB.Network.Zones["node-b.catofes."], "node-b.catofes.", groupB, now)

	rtA := &testApp{Config: testDaemonIPsecAppConfig(t.TempDir(), "127.0.0.1:0", groupA), Clock: func() time.Time { return now }}
	rtB := &testApp{Config: testDaemonIPsecAppConfig(t.TempDir(), "127.0.0.1:0", groupB), Clock: func() time.Time { return now }}
	driverA := &ipsec.StrongSwanDriver{VICI: clientA, KeyDir: t.TempDir()}
	driverB := &ipsec.StrongSwanDriver{VICI: clientB, KeyDir: t.TempDir()}
	serviceA := newTestDaemonFromOwners(rtA, verifiedA, nil, runtimeA, configA, time.Second)
	installTestIPsecDrivers(serviceA, driverA, daemonTestXFRMDriver(groupA.NetNS, nsA))
	serviceB := newTestDaemonFromOwners(rtB, verifiedB, nil, runtimeB, configB, time.Second)
	installTestIPsecDrivers(serviceB, driverB, daemonTestXFRMDriver(groupB.NetNS, nsB))

	serviceB.recoverIPsecLinksOnStart(ctx)
	serviceA.recoverIPsecLinksOnStart(ctx)
	commonA := serviceA.State.Common.ReadView()
	persistedA := serviceA.State.ReadLinux()
	latestALinks, latestAReconcile := readTestIPsecObservation(serviceA)
	commonB := serviceB.State.Common.ReadView()
	persistedB := serviceB.State.ReadLinux()
	latestBLinks, latestBReconcile := readTestIPsecObservation(serviceB)
	specA := daemonSystemDesiredSpec(t, commonA.State, persistedA.IPsecTransportKey, groupA, now)
	specB := daemonSystemDesiredSpec(t, commonB.State, persistedB.IPsecTransportKey, groupB, now)
	if err := waitDaemonTestSA(ctx, clientA, specA.TransportID); err != nil {
		t.Fatalf("wait for daemon SA on A: %v", err)
	}
	if err := waitDaemonTestSA(ctx, clientB, specB.TransportID); err != nil {
		t.Fatalf("wait for daemon SA on B: %v", err)
	}

	serviceA.recoverIPsecLinksOnStart(ctx)
	serviceB.recoverIPsecLinksOnStart(ctx)
	latestALinks, latestAReconcile = readTestIPsecObservation(serviceA)
	latestBLinks, latestBReconcile = readTestIPsecObservation(serviceB)
	assertDaemonSystemLinkUp(t, latestALinks, latestAReconcile, specA)
	assertDaemonSystemLinkUp(t, latestBLinks, latestBReconcile, specB)

	if !pool.Contains(specA.LocalTunnelAddr) || !pool.Contains(specA.PeerTunnelAddr) {
		t.Fatalf("derived pool addresses not in %s: local=%s peer=%s", pool, specA.LocalTunnelAddr, specA.PeerTunnelAddr)
	}
	if !specA.LocalTunnelAddr.Is4() || !specA.PeerTunnelAddr.Is4() {
		t.Fatalf("expected IPv4 derived pool addresses, got local=%s peer=%s", specA.LocalTunnelAddr, specA.PeerTunnelAddr)
	}

	addTunnelRoute(t, ctx, nsA, specA)
	addTunnelRoute(t, ctx, nsB, specB)
	pingTunnelAddr(t, ctx, nsA, specA.PeerTunnelAddr, specA.InterfaceName)
	pingTunnelAddr(t, ctx, nsB, specB.PeerTunnelAddr, specB.InterfaceName)
}

func TestDaemonStrongSwanPortRotationSmoke(t *testing.T) {
	if os.Getenv("PHOTON_IPSEC_XFRM_SMOKE") != "1" {
		t.Skip("set PHOTON_IPSEC_XFRM_SMOKE=1 to run the root/system StrongSwan port rotation smoke")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	suffix := time.Now().UTC().Format("20060102150405")
	nsA := "photon-daemon-rot-a-" + suffix
	nsB := "photon-daemon-rot-b-" + suffix
	viciA := "/tmp/charon-" + nsA + ".vici"
	viciB := "/tmp/charon-" + nsB + ".vici"
	t.Cleanup(func() {
		_, _ = appExecCommand(context.Background(), "ip", "netns", "delete", nsA)
		_, _ = appExecCommand(context.Background(), "ip", "netns", "delete", nsB)
		_ = os.Remove(viciA)
		_ = os.Remove(viciB)
	})

	runAppCommand(t, ctx, "ip", "netns", "add", nsA)
	runAppCommand(t, ctx, "ip", "netns", "add", nsB)
	runAppCommand(t, ctx, "ip", "link", "add", "hgdrota", "type", "veth", "peer", "name", "hgdrotb")
	runAppCommand(t, ctx, "ip", "link", "set", "hgdrota", "netns", nsA)
	runAppCommand(t, ctx, "ip", "link", "set", "hgdrotb", "netns", nsB)
	for _, args := range [][]string{
		{"netns", "exec", nsA, "ip", "link", "set", "lo", "up"},
		{"netns", "exec", nsB, "ip", "link", "set", "lo", "up"},
		{"netns", "exec", nsA, "ip", "addr", "add", "192.0.2.1/30", "dev", "hgdrota"},
		{"netns", "exec", nsB, "ip", "addr", "add", "192.0.2.2/30", "dev", "hgdrotb"},
		{"netns", "exec", nsA, "ip", "link", "set", "hgdrota", "up"},
		{"netns", "exec", nsB, "ip", "link", "set", "hgdrotb", "up"},
	} {
		runAppCommand(t, ctx, "ip", args...)
	}

	confA, err := writeDaemonStrongSwanConf(viciA)
	if err != nil {
		t.Fatalf("write strongswan.conf A: %v", err)
	}
	confB, err := writeDaemonStrongSwanConf(viciB)
	if err != nil {
		t.Fatalf("write strongswan.conf B: %v", err)
	}
	piddirA := t.TempDir()
	piddirB := t.TempDir()
	logA, err := os.CreateTemp("", "photon-daemon-charon-rot-a-*.log")
	if err != nil {
		t.Fatalf("create charon A log: %v", err)
	}
	logB, err := os.CreateTemp("", "photon-daemon-charon-rot-b-*.log")
	if err != nil {
		t.Fatalf("create charon B log: %v", err)
	}
	charonA := startDaemonTestCharonInNetNS(ctx, t, nsA, piddirA, confA, logA)
	charonB := startDaemonTestCharonInNetNS(ctx, t, nsB, piddirB, confB, logB)
	defer func() {
		_ = charonA.Process.Kill()
		_ = charonB.Process.Kill()
		_ = charonA.Wait()
		_ = charonB.Wait()
		_ = os.Remove(confA)
		_ = os.Remove(confB)
		_ = logA.Close()
		_ = logB.Close()
		_ = os.Remove(logA.Name())
		_ = os.Remove(logB.Name())
	}()
	clientA, err := waitDaemonTestVICI(ctx, viciA)
	if err != nil {
		t.Fatalf("connect to charon A VICI: %v", err)
	}
	defer clientA.Close()
	clientB, err := waitDaemonTestVICI(ctx, viciB)
	if err != nil {
		t.Fatalf("connect to charon B VICI: %v", err)
	}
	defer clientB.Close()
	defer func() {
		if t.Failed() {
			dumpCtx, dumpCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer dumpCancel()
			logDaemonTestFile(t, "charon A", logA.Name())
			logDaemonTestFile(t, "charon B", logB.Name())
			dumpDaemonSystemState(t, dumpCtx, nsA, nsB)
			dumpDaemonVICISAs(t, dumpCtx, viciA, "A")
			dumpDaemonVICISAs(t, dumpCtx, viciB, "B")
		}
	}()

	now := time.Unix(4140, 0)
	verifiedA, configA, verifiedB, configB := buildTestABVerifiedStates(t)
	runtimeA, runtimeB := &photonlinux.LinuxState{}, &photonlinux.LinuxState{}
	keyA, recordA := daemonTestTransportKey(t, now)
	keyB, recordB := daemonTestTransportKey(t, now)
	runtimeA.IPsecTransportKey = keyA
	runtimeB.IPsecTransportKey = keyB
	addDaemonTestIPsecRecords(t, verifiedA.Network.Zones["node-a.catofes."], "node-a.catofes.", "192.0.2.1", recordA, ipsec.RoleOut, now)
	addDaemonTestIPsecRecords(t, verifiedB.Network.Zones["node-b.catofes."], "node-b.catofes.", "192.0.2.2", recordB, ipsec.RoleIn, now)
	verifiedA.Network.Zones["node-b.catofes."] = verifiedB.Network.Zones["node-b.catofes."]
	verifiedB.Network.Zones["node-a.catofes."] = verifiedA.Network.Zones["node-a.catofes."]

	groupA := testIPsecLinkGroup()
	groupA.ConnectRules = nil
	groupA.NetNS = ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: nsA, Create: false}
	groupA.TunnelAddressSpec = ipsec.TunnelAddressSpec{Mode: ipsec.TunnelAddressDerivedLinkLocal, Family: ipsec.FamilyIPv6}
	groupB := testIPsecLinkGroup()
	groupB.ConnectRules = nil
	groupB.NetNS = ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: nsB, Create: false}
	groupB.TunnelAddressSpec = ipsec.TunnelAddressSpec{Mode: ipsec.TunnelAddressDerivedLinkLocal, Family: ipsec.FamilyIPv6}
	rtA := &testApp{Config: testDaemonIPsecAppConfig(t.TempDir(), "127.0.0.1:0", groupA), Clock: func() time.Time { return now }}
	rtB := &testApp{Config: testDaemonIPsecAppConfig(t.TempDir(), "127.0.0.1:0", groupB), Clock: func() time.Time { return now }}
	rotationDriverA := &ipsec.StrongSwanDriver{VICI: clientA, KeyDir: t.TempDir()}
	rotationDriverB := &ipsec.StrongSwanDriver{VICI: clientB, KeyDir: t.TempDir()}
	serviceA := newTestDaemonFromOwners(rtA, verifiedA, nil, runtimeA, configA, time.Second)
	installTestIPsecDrivers(serviceA, rotationDriverA, daemonTestXFRMDriver(groupA.NetNS, nsA))
	serviceB := newTestDaemonFromOwners(rtB, verifiedB, nil, runtimeB, configB, time.Second)
	installTestIPsecDrivers(serviceB, rotationDriverB, daemonTestXFRMDriver(groupB.NetNS, nsB))

	serviceB.recoverIPsecLinksOnStart(ctx)
	serviceA.recoverIPsecLinksOnStart(ctx)
	commonA := serviceA.State.Common.ReadView()
	persistedA := serviceA.State.ReadLinux()
	latestALinks, latestAReconcile := readTestIPsecObservation(serviceA)
	commonB := serviceB.State.Common.ReadView()
	persistedB := serviceB.State.ReadLinux()
	latestBLinks, latestBReconcile := readTestIPsecObservation(serviceB)
	specA := daemonSystemDesiredSpec(t, commonA.State, persistedA.IPsecTransportKey, groupA, now)
	specB := daemonSystemDesiredSpec(t, commonB.State, persistedB.IPsecTransportKey, groupB, now)
	if err := waitDaemonTestSA(ctx, clientA, specA.TransportID); err != nil {
		t.Fatalf("wait for daemon SA on A: %v", err)
	}
	if err := waitDaemonTestSA(ctx, clientB, specB.TransportID); err != nil {
		t.Fatalf("wait for daemon SA on B: %v", err)
	}

	serviceA.recoverIPsecLinksOnStart(ctx)
	serviceB.recoverIPsecLinksOnStart(ctx)
	latestALinks, latestAReconcile = readTestIPsecObservation(serviceA)
	latestBLinks, latestBReconcile = readTestIPsecObservation(serviceB)
	assertDaemonSystemLinkUp(t, latestALinks, latestAReconcile, specA)
	assertDaemonSystemLinkUp(t, latestBLinks, latestBReconcile, specB)
	addTunnelRoute(t, ctx, nsA, specA)
	addTunnelRoute(t, ctx, nsB, specB)
	pingTunnelAddr(t, ctx, nsA, specA.PeerTunnelAddr, specA.InterfaceName)
	pingTunnelAddr(t, ctx, nsB, specB.PeerTunnelAddr, specB.InterfaceName)

	// Rotate both peers to generation 2 on IKE port 500. The initial base
	// connection uses NAT-T port 4500, so the staged connection on port 500
	// gets independent IKE_SAs on both sides.
	const rotIKEPort uint16 = ipsec.DefaultIKEPort
	updateDaemonTestPortRecord(t, commonA.State.Network.Zones["node-a.catofes."], "node-a.catofes.", 2, rotIKEPort, now.Add(time.Minute))
	updateDaemonTestPortRecord(t, commonB.State.Network.Zones["node-a.catofes."], "node-a.catofes.", 2, rotIKEPort, now.Add(time.Minute))
	updateDaemonTestPortRecord(t, commonA.State.Network.Zones["node-b.catofes."], "node-b.catofes.", 2, rotIKEPort, now.Add(time.Minute))
	updateDaemonTestPortRecord(t, commonB.State.Network.Zones["node-b.catofes."], "node-b.catofes.", 2, rotIKEPort, now.Add(time.Minute))
	serviceA = newTestDaemonFromOwners(rtA, commonA.State, commonA.Gossip, persistedA, configA, time.Second)
	installTestIPsecDrivers(serviceA, rotationDriverA, daemonTestXFRMDriver(groupA.NetNS, nsA))
	serviceB = newTestDaemonFromOwners(rtB, commonB.State, commonB.Gossip, persistedB, configB, time.Second)
	installTestIPsecDrivers(serviceB, rotationDriverB, daemonTestXFRMDriver(groupB.NetNS, nsB))
	serviceB.recoverIPsecLinksOnStart(ctx)
	serviceA.recoverIPsecLinksOnStart(ctx)
	preparedALinks, preparedAReconcile := readTestIPsecObservation(serviceA)
	preparedBLinks, preparedBReconcile := readTestIPsecObservation(serviceB)
	instA := preparedALinks[ipsec.LinkInstanceID(specA)]
	if instA.RotatePhase != ipsec.RotatePhaseTestingNew || instA.StagedGeneration != 2 {
		t.Fatalf("prepared rotate instance A = %+v, want testing_new generation 2", instA)
	}
	instB := preparedBLinks[ipsec.LinkInstanceID(specB)]
	if instB.RotatePhase != ipsec.RotatePhaseTestingNew || instB.StagedGeneration != 2 {
		t.Fatalf("prepared rotate instance B = %+v, want testing_new generation 2", instB)
	}
	stagedIKEA := ipsec.RuntimeConnectionID(instA.LinkID, 2, instA.TransportKind)
	stagedIKEB := ipsec.RuntimeConnectionID(instB.LinkID, 2, instB.TransportKind)
	if instA.StagedIKEName != stagedIKEA {
		t.Fatalf("staged ike A = %q, want %q", instA.StagedIKEName, stagedIKEA)
	}
	if instB.StagedIKEName != stagedIKEB {
		t.Fatalf("staged ike B = %q, want %q", instB.StagedIKEName, stagedIKEB)
	}
	if err := waitDaemonTestSA(ctx, clientA, stagedIKEA); err != nil {
		t.Fatalf("wait for staged daemon SA on A: %v", err)
	}
	if err := waitDaemonTestSA(ctx, clientB, stagedIKEB); err != nil {
		t.Fatalf("wait for staged daemon SA on B: %v", err)
	}

	// Simulate that the staged SAs have been observed and the rotate retention
	// window has expired, so the next reconcile commits the rotation.
	for id, inst := range preparedALinks {
		inst.RotatePhase = ipsec.RotatePhaseDualRunning
		inst.RotateDeadline = now.Add(-time.Second).Unix()
		preparedALinks[id] = inst
	}
	for id, inst := range preparedBLinks {
		inst.RotatePhase = ipsec.RotatePhaseDualRunning
		inst.RotateDeadline = now.Add(-time.Second).Unix()
		preparedBLinks[id] = inst
	}
	setTestIPsecObservation(serviceA, preparedALinks, preparedAReconcile)
	serviceA.recoverIPsecLinksOnStart(ctx)
	setTestIPsecObservation(serviceB, preparedBLinks, preparedBReconcile)
	serviceB.recoverIPsecLinksOnStart(ctx)
	committedALinks, committedAReconcile := readTestIPsecObservation(serviceA)
	committedBLinks, committedBReconcile := readTestIPsecObservation(serviceB)
	rotatedSpecA := daemonSystemDesiredSpec(t, commonA.State, persistedA.IPsecTransportKey, groupA, now.Add(time.Minute))
	rotatedSpecB := daemonSystemDesiredSpec(t, commonB.State, persistedB.IPsecTransportKey, groupB, now.Add(time.Minute))
	// After commit the active XFRM interface and IKE name are the staged ones;
	// update the spec to match the committed instance before checking link state.
	committedInstA := committedALinks[ipsec.LinkInstanceID(rotatedSpecA)]
	rotatedSpecA.InterfaceName = committedInstA.InterfaceName
	rotatedSpecA.XFRMIfID = committedInstA.XFRMIfID
	committedInstB := committedBLinks[ipsec.LinkInstanceID(rotatedSpecB)]
	rotatedSpecB.InterfaceName = committedInstB.InterfaceName
	rotatedSpecB.XFRMIfID = committedInstB.XFRMIfID
	assertDaemonSystemLinkUp(t, committedALinks, committedAReconcile, rotatedSpecA)
	assertDaemonSystemLinkUp(t, committedBLinks, committedBReconcile, rotatedSpecB)
	if committedInstA.RotatePhase != ipsec.RotatePhaseIdle || committedInstA.StagedGeneration != 0 {
		t.Fatalf("committed rotate instance A = %+v, want idle with no staged generation", committedInstA)
	}
	if committedInstA.IKEName != stagedIKEA || committedInstA.RemoteGeneration != 2 {
		t.Fatalf("committed rotate instance A = %+v, want ike=%s remote_generation=2", committedInstA, stagedIKEA)
	}
	if committedInstB.RotatePhase != ipsec.RotatePhaseIdle || committedInstB.StagedGeneration != 0 {
		t.Fatalf("committed rotate instance B = %+v, want idle with no staged generation", committedInstB)
	}
	if committedInstB.IKEName != stagedIKEB || committedInstB.RemoteGeneration != 2 {
		t.Fatalf("committed rotate instance B = %+v, want ike=%s remote_generation=2", committedInstB, stagedIKEB)
	}
	if err := waitDaemonTestNoSA(ctx, clientA, specA.TransportID); err != nil {
		t.Fatalf("old daemon SA on A after rotate commit: %v", err)
	}
	if err := waitDaemonTestNoSA(ctx, clientB, specB.TransportID); err != nil {
		t.Fatalf("old daemon SA on B after rotate commit: %v", err)
	}
	if count, err := daemonTestEstablishedSACount(ctx, clientA, stagedIKEA); err != nil {
		t.Fatalf("count staged SA on A after commit: %v", err)
	} else if count != 1 {
		t.Fatalf("staged SA count on A after commit = %d, want 1", count)
	}
	if count, err := daemonTestEstablishedSACount(ctx, clientB, stagedIKEB); err != nil {
		t.Fatalf("count staged SA on B after commit: %v", err)
	} else if count != 1 {
		t.Fatalf("staged SA count on B after commit = %d, want 1", count)
	}
	addTunnelRoute(t, ctx, nsA, rotatedSpecA)
	addTunnelRoute(t, ctx, nsB, rotatedSpecB)
	pingTunnelAddr(t, ctx, nsA, rotatedSpecA.PeerTunnelAddr, rotatedSpecA.InterfaceName)
	pingTunnelAddr(t, ctx, nsB, rotatedSpecB.PeerTunnelAddr, rotatedSpecB.InterfaceName)
}

func TestDaemonRunGossipStrongSwanBringupSmoke(t *testing.T) {
	if os.Getenv("PHOTON_IPSEC_XFRM_SMOKE") != "1" {
		t.Skip("set PHOTON_IPSEC_XFRM_SMOKE=1 to run the root/system daemon gossip StrongSwan smoke")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	suffix := time.Now().UTC().Format("20060102150405")
	nsA := "photon-daemon-run-a-" + suffix
	nsB := "photon-daemon-run-b-" + suffix
	viciA := "/tmp/charon-" + nsA + ".vici"
	viciB := "/tmp/charon-" + nsB + ".vici"
	t.Cleanup(func() {
		_, _ = appExecCommand(context.Background(), "ip", "netns", "delete", nsA)
		_, _ = appExecCommand(context.Background(), "ip", "netns", "delete", nsB)
		_ = os.Remove(viciA)
		_ = os.Remove(viciB)
	})

	runAppCommand(t, ctx, "ip", "netns", "add", nsA)
	runAppCommand(t, ctx, "ip", "netns", "add", nsB)
	runAppCommand(t, ctx, "ip", "link", "add", "hgdruna", "type", "veth", "peer", "name", "hgdrunb")
	runAppCommand(t, ctx, "ip", "link", "set", "hgdruna", "netns", nsA)
	runAppCommand(t, ctx, "ip", "link", "set", "hgdrunb", "netns", nsB)
	for _, args := range [][]string{
		{"netns", "exec", nsA, "ip", "link", "set", "lo", "up"},
		{"netns", "exec", nsB, "ip", "link", "set", "lo", "up"},
		{"netns", "exec", nsA, "ip", "addr", "add", "192.0.2.1/30", "dev", "hgdruna"},
		{"netns", "exec", nsB, "ip", "addr", "add", "192.0.2.2/30", "dev", "hgdrunb"},
		{"netns", "exec", nsA, "ip", "link", "set", "hgdruna", "up"},
		{"netns", "exec", nsB, "ip", "link", "set", "hgdrunb", "up"},
	} {
		runAppCommand(t, ctx, "ip", args...)
	}

	confA, err := writeDaemonStrongSwanConf(viciA)
	if err != nil {
		t.Fatalf("write strongswan.conf A: %v", err)
	}
	confB, err := writeDaemonStrongSwanConf(viciB)
	if err != nil {
		t.Fatalf("write strongswan.conf B: %v", err)
	}
	piddirA := t.TempDir()
	piddirB := t.TempDir()
	logA, err := os.CreateTemp("", "photon-daemon-run-charon-a-*.log")
	if err != nil {
		t.Fatalf("create charon A log: %v", err)
	}
	logB, err := os.CreateTemp("", "photon-daemon-run-charon-b-*.log")
	if err != nil {
		t.Fatalf("create charon B log: %v", err)
	}
	charonA := startDaemonTestCharonInNetNS(ctx, t, nsA, piddirA, confA, logA)
	charonB := startDaemonTestCharonInNetNS(ctx, t, nsB, piddirB, confB, logB)
	defer func() {
		_ = charonA.Process.Kill()
		_ = charonB.Process.Kill()
		_ = charonA.Wait()
		_ = charonB.Wait()
		_ = os.Remove(confA)
		_ = os.Remove(confB)
		_ = logA.Close()
		_ = logB.Close()
		_ = os.Remove(logA.Name())
		_ = os.Remove(logB.Name())
	}()
	defer func() {
		if t.Failed() {
			dumpCtx, dumpCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer dumpCancel()
			logDaemonTestFile(t, "charon A", logA.Name())
			logDaemonTestFile(t, "charon B", logB.Name())
			dumpDaemonSystemState(t, dumpCtx, nsA, nsB)
		}
	}()

	clientA, err := waitDaemonTestVICI(ctx, viciA)
	if err != nil {
		t.Fatalf("connect to charon A VICI: %v", err)
	}
	defer clientA.Close()
	clientB, err := waitDaemonTestVICI(ctx, viciB)
	if err != nil {
		t.Fatalf("connect to charon B VICI: %v", err)
	}
	defer clientB.Close()

	verifiedA, configA, verifiedB, configB := buildTestABVerifiedStates(t)
	runtimeA, runtimeB := &photonlinux.LinuxState{}, &photonlinux.LinuxState{}
	now := time.Now()
	keyA, _ := daemonTestTransportKey(t, now)
	keyB, _ := daemonTestTransportKey(t, now)
	runtimeA.IPsecTransportKey = keyA
	runtimeB.IPsecTransportKey = keyB
	gossipA := freeDaemonTestUDPAddr(t)
	gossipB := freeDaemonTestUDPAddr(t)
	configA.ListenAddr = gossipA
	configB.ListenAddr = gossipB
	configA.Bootstrap = []syncConfigPeer{{ID: configB.PeerID, Addr: gossipB}}
	configB.Bootstrap = []syncConfigPeer{{ID: configA.PeerID, Addr: gossipA}}

	groupA := testIPsecLinkGroup()
	groupA.ConnectRules = nil
	groupA.NetNS = ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: nsA, Create: false}
	groupA.TunnelAddressSpec = ipsec.TunnelAddressSpec{Mode: ipsec.TunnelAddressDerivedLinkLocal, Family: ipsec.FamilyIPv6}
	groupB := testIPsecLinkGroup()
	groupB.ConnectRules = nil
	groupB.NetNS = ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: nsB, Create: false}
	groupB.TunnelAddressSpec = ipsec.TunnelAddressSpec{Mode: ipsec.TunnelAddressDerivedLinkLocal, Family: ipsec.FamilyIPv6}
	rtA := &testApp{Config: testDaemonIPsecAppConfig(t.TempDir(), "192.0.2.1:4500", groupA), Clock: time.Now}
	rtA.Config.IPsec.Role = ipsec.RoleOut
	rtA.Config.ListenAddr = gossipA
	rtB := &testApp{Config: testDaemonIPsecAppConfig(t.TempDir(), "192.0.2.2:4500", groupB), Clock: time.Now}
	rtB.Config.IPsec.Role = ipsec.RoleIn
	rtB.Config.ListenAddr = gossipB
	serviceA := newTestDaemonFromOwners(rtA, verifiedA, nil, runtimeA, configA, 200*time.Millisecond)
	serviceA.ControlSocketPath = filepath.Join(t.TempDir(), controlSocketName)
	installTestIPsecDrivers(serviceA, newDaemonTestStrongSwanDriver(t, viciA, clientA), daemonTestXFRMDriver(groupA.NetNS, nsA))
	serviceB := newTestDaemonFromOwners(rtB, verifiedB, nil, runtimeB, configB, 200*time.Millisecond)
	serviceB.ControlSocketPath = filepath.Join(t.TempDir(), controlSocketName)
	installTestIPsecDrivers(serviceB, newDaemonTestStrongSwanDriver(t, viciB, clientB), daemonTestXFRMDriver(groupB.NetNS, nsB))

	runCtx, stopDaemons := context.WithCancel(ctx)
	defer stopDaemons()
	errCh := make(chan error, 2)
	go func() { errCh <- serviceA.Run(runCtx) }()
	go func() { errCh <- serviceB.Run(runCtx) }()
	defer func() {
		stopDaemons()
		for range 2 {
			if err := <-errCh; err != nil {
				t.Fatalf("daemon Run returned error: %v", err)
			}
		}
	}()

	commonA, latestALinks, latestAReconcile, commonB, latestBLinks, latestBReconcile := waitDaemonRunGossipStrongSwanUp(ctx, t, serviceA, serviceB, groupA, groupB)
	persistedA := serviceA.State.ReadLinux()
	persistedB := serviceB.State.ReadLinux()
	specA := daemonSystemDesiredSpec(t, commonA.State, persistedA.IPsecTransportKey, groupA, time.Now())
	specB := daemonSystemDesiredSpec(t, commonB.State, persistedB.IPsecTransportKey, groupB, time.Now())
	assertGossipedIPsecRecords(t, commonA.State.Network, "node-b.catofes.")
	assertGossipedIPsecRecords(t, commonB.State.Network, "node-a.catofes.")
	assertDaemonSystemLinkUp(t, latestALinks, latestAReconcile, specA)
	assertDaemonSystemLinkUp(t, latestBLinks, latestBReconcile, specB)

	addTunnelRoute(t, ctx, nsA, specA)
	addTunnelRoute(t, ctx, nsB, specB)
	pingTunnelAddr(t, ctx, nsA, specA.PeerTunnelAddr, specA.InterfaceName)
	pingTunnelAddr(t, ctx, nsB, specB.PeerTunnelAddr, specB.InterfaceName)
}
