package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	photonlinux "github.com/HiggsNet/photon/internal/photonlinux"
	photonstate "github.com/HiggsNet/photon/internal/state"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func appExecCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

func runAppCommand(t *testing.T, ctx context.Context, name string, args ...string) {
	t.Helper()
	if out, err := appExecCommand(ctx, name, args...); err != nil {
		t.Fatalf("%s %s failed: %v\n%s", name, strings.Join(args, " "), err, string(out))
	}
}

func addTunnelRoute(t *testing.T, ctx context.Context, ns string, spec ipsec.TransportLinkSpec) {
	t.Helper()
	bits := 32
	if spec.PeerTunnelAddr.Is6() {
		bits = 128
	}
	args := []string{"netns", "exec", ns, "ip", "route", "replace", netip.PrefixFrom(spec.PeerTunnelAddr, bits).String(), "dev", spec.InterfaceName}
	if spec.PeerTunnelAddr.Is4() {
		args = append(args, "src", spec.LocalTunnelAddr.String())
	}
	runAppCommand(t, ctx, "ip", args...)
}

func pingTunnelAddr(t *testing.T, ctx context.Context, ns string, target netip.Addr, iface string) {
	t.Helper()
	if target.Is4() {
		runAppCommand(t, ctx, "ip", "netns", "exec", ns, "ping", "-c", "1", "-W", "3", target.String())
		return
	}
	runAppCommand(t, ctx, "ip", "netns", "exec", ns, "ping", "-6", "-c", "1", "-W", "3", target.String()+"%"+iface)
}

func pingTunnelAddrShouldFail(t *testing.T, ctx context.Context, ns string, target netip.Addr, iface string) []byte {
	t.Helper()
	var cmdArgs []string
	if target.Is4() {
		cmdArgs = []string{"netns", "exec", ns, "ping", "-c", "1", "-W", "1", target.String()}
	} else {
		cmdArgs = []string{"netns", "exec", ns, "ping", "-6", "-c", "1", "-W", "1", target.String() + "%" + iface}
	}
	out, err := appExecCommand(ctx, "ip", cmdArgs...)
	if err == nil {
		t.Fatalf("ping unexpectedly succeeded to %s", target)
	}
	return out
}

func writeDaemonStrongSwanConf(viciSocket string) (string, error) {
	f, err := os.CreateTemp("", "photon-daemon-strongswan-*.conf")
	if err != nil {
		return "", err
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, `charon {
	install_routes = no
	install_virtual_ip = no
	uniqueids = no
	stderr {
		default = 2
	}
	plugins {
		vici {
			socket = unix://%s
		}
	}
}
`, viciSocket)
	if err != nil {
		return "", err
	}
	return f.Name(), nil
}

func daemonTestXFRMDriver(defaultNetNS ipsec.NetNSSpec, stateNetNS string) ipsec.SystemXFRMDriver {
	driver := ipsec.NewSystemXFRMDriver(defaultNetNS)
	driver.StateNetNS = ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: stateNetNS, Create: false}
	return driver
}

func startDaemonTestCharonInNetNS(ctx context.Context, t *testing.T, ns, piddir, conf string, logFile *os.File) *exec.Cmd {
	t.Helper()
	script := fmt.Sprintf("mkdir -p /run && mount --bind %s /run && STRONGSWAN_CONF=%s exec charon --debug-cfg 2 --debug-ike 2 --debug-mgr 2", piddir, conf)
	cmd := exec.CommandContext(ctx, "unshare", "-m", "ip", "netns", "exec", ns, "bash", "-c", script)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		t.Fatalf("start charon in %s: %v", ns, err)
	}
	return cmd
}

func waitDaemonTestVICI(ctx context.Context, socket string) (*ipsec.GoviciClient, error) {
	for {
		if _, err := os.Stat(socket); err == nil {
			break
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("timeout waiting for vici socket %s", socket)
		default:
			time.Sleep(50 * time.Millisecond)
		}
	}
	var lastErr error
	for {
		client, err := ipsec.NewGoviciClient(socket)
		if err == nil {
			return client, nil
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("connect to %s: %w", socket, lastErr)
		default:
			time.Sleep(100 * time.Millisecond)
		}
	}
}

func waitDaemonTestSA(ctx context.Context, client *ipsec.GoviciClient, name string) error {
	for {
		events, err := client.CallStreaming(ctx, "list-sas", "list-sa", map[string]any{"ike": name})
		if err != nil {
			return err
		}
		if slices.ContainsFunc(events, daemonTestSAEstablished) {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for SA %s", name)
		default:
			time.Sleep(200 * time.Millisecond)
		}
	}
}

func waitDaemonTestNoSA(ctx context.Context, client *ipsec.GoviciClient, name string) error {
	for {
		count, err := daemonTestEstablishedSACount(ctx, client, name)
		if err != nil {
			return err
		}
		if count == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for SA %s teardown; established count=%d", name, count)
		default:
			time.Sleep(200 * time.Millisecond)
		}
	}
}

func daemonTestEstablishedSACount(ctx context.Context, client *ipsec.GoviciClient, name string) (int, error) {
	events, err := client.CallStreaming(ctx, "list-sas", "list-sa", map[string]any{"ike": name})
	if err != nil {
		return 0, err
	}
	count := 0
	for _, event := range events {
		if daemonTestSAEstablished(event) {
			count++
		}
	}
	return count, nil
}

func daemonTestSAEstablished(raw map[string]any) bool {
	for _, v := range raw {
		sa, ok := v.(map[string]any)
		if !ok {
			continue
		}
		if strings.EqualFold(daemonTestString(sa["state"]), "ESTABLISHED") {
			return true
		}
		children, _ := sa["child-sas"].(map[string]any)
		for _, cv := range children {
			child, ok := cv.(map[string]any)
			if ok && daemonTestString(child["state"]) == "INSTALLED" {
				return true
			}
		}
	}
	return false
}

func daemonTestString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case fmt.Stringer:
		return x.String()
	default:
		return fmt.Sprint(v)
	}
}

func assertDaemonSystemLinkUp(t *testing.T, links map[string]ipsec.LinkInstance, reconcile *ipsecObservationSummary, spec ipsec.TransportLinkSpec) {
	t.Helper()
	inst := links[ipsec.LinkInstanceID(spec)]
	if inst.ActualState != ipsec.LinkStateUp {
		t.Fatalf("link instance = %+v, want up", inst)
	}
	if reconcile == nil || len(reconcile.ActualSAs) == 0 {
		t.Fatalf("ipsec reconcile = %+v, want observed SAs", reconcile)
	}
	ikeName := inst.IKEName
	if ikeName == "" {
		ikeName = spec.TransportID
	}
	childName := inst.ChildSAName
	if childName == "" {
		childName = ipsec.ChildSAName(spec)
	}
	for _, sa := range reconcile.ActualSAs {
		// StrongSwan may append a rekey suffix (e.g. "-2") to IKE/child names.
		nameMatches := sa.Name == ikeName || strings.HasPrefix(sa.Name, ikeName+"-")
		childMatches := sa.ChildSA == childName || strings.HasPrefix(sa.ChildSA, childName+"-")
		if nameMatches && childMatches && (sa.XFRMIfID == 0 || sa.XFRMIfID == spec.XFRMIfID) && sa.Established {
			if sa.LocalIdentity != string(spec.LocalZone) || sa.RemoteIdentity != string(spec.PeerZone) {
				t.Fatalf("SA identities = %+v, want %s -> %s", sa, spec.LocalZone, spec.PeerZone)
			}
			return
		}
	}
	t.Fatalf("actual SAs = %+v, want established SA for %s", reconcile.ActualSAs, spec.TransportID)
}

func daemonSystemDesiredSpec(t *testing.T, verified *corestate.VerifiedState, key *photonstate.IPsecTransportKeyState, group ipsec.LinkGroupSpec, now time.Time) ipsec.TransportLinkSpec {
	t.Helper()
	plan, err := ipsec.PlanTransportLinks(context.Background(), verified.Network, verified.ManagedZone, []ipsec.LinkGroupSpec{group}, ipsec.LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks(%s): %v", verified.ManagedZone, err)
	}
	if len(plan.Desired) != 1 {
		t.Fatalf("desired for %s = %+v, skips=%+v, want one", verified.ManagedZone, plan.Desired, plan.Skipped)
	}
	return photonlinux.InjectIPsecKeyMaterial(verified.Network, key, plan.Desired)[0]
}

func freeDaemonTestUDPAddr(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("ListenUDP(free port): %v", err)
	}
	addr := conn.LocalAddr().String()
	if err := conn.Close(); err != nil {
		t.Fatalf("close free UDP port: %v", err)
	}
	return addr
}

func waitDaemonRunGossipStrongSwanUp(ctx context.Context, t *testing.T, serviceA, serviceB *Daemon, groupA, groupB ipsec.LinkGroupSpec) (corestate.View, map[string]ipsec.LinkInstance, *ipsecObservationSummary, corestate.View, map[string]ipsec.LinkInstance, *ipsecObservationSummary) {
	t.Helper()
	var commonA, commonB corestate.View
	var runtimeA, runtimeB *photonlinux.LinuxState
	var observationALinks, observationBLinks map[string]ipsec.LinkInstance
	var observationAReconcile, observationBReconcile *ipsecObservationSummary
	for {
		commonA = serviceA.State.Common.ReadView()
		runtimeA = serviceA.State.ReadLinux()
		commonB = serviceB.State.Common.ReadView()
		runtimeB = serviceB.State.ReadLinux()
		observationALinks, observationAReconcile = readTestIPsecObservation(serviceA)
		observationBLinks, observationBReconcile = readTestIPsecObservation(serviceB)
		if daemonRunGossipStrongSwanReady(commonA.State, runtimeA.IPsecTransportKey, observationALinks, observationAReconcile, groupA) && daemonRunGossipStrongSwanReady(commonB.State, runtimeB.IPsecTransportKey, observationBLinks, observationBReconcile, groupB) {
			return commonA, observationALinks, observationAReconcile, commonB, observationBLinks, observationBReconcile
		}
		select {
		case <-ctx.Done():
			t.Logf("last node-a reconcile = %+v instances=%+v", observationAReconcile, observationALinks)
			t.Logf("last node-b reconcile = %+v instances=%+v", observationBReconcile, observationBLinks)
			t.Fatalf("timeout waiting for daemon gossip StrongSwan up")
		default:
			time.Sleep(250 * time.Millisecond)
		}
	}
}

func newDaemonTestStrongSwanDriver(t *testing.T, viciSocket string, client ipsec.VICIClient) *ipsec.StrongSwanDriver {
	t.Helper()
	return &ipsec.StrongSwanDriver{
		VICI:          client,
		KeyDir:        t.TempDir(),
		InitiateAsync: true,
		InitiateClientFactory: func() (ipsec.VICIClient, func() error, error) {
			initiateClient, err := ipsec.NewGoviciClient(viciSocket)
			if err != nil {
				return nil, nil, err
			}
			return initiateClient, initiateClient.Close, nil
		},
	}
}

func daemonRunGossipStrongSwanReady(verified *corestate.VerifiedState, key *photonstate.IPsecTransportKeyState, links map[string]ipsec.LinkInstance, reconcile *ipsecObservationSummary, group ipsec.LinkGroupSpec) bool {
	if verified == nil || reconcile == nil || len(reconcile.ActualSAs) == 0 || len(links) == 0 {
		return false
	}
	if verified.ManagedZone == "node-a.catofes." {
		if zs := verified.Network.Zones["node-b.catofes."]; zs == nil || zs.Records[ipsec.RecordKeyTransportKey] == nil {
			return false
		}
	}
	if verified.ManagedZone == "node-b.catofes." {
		if zs := verified.Network.Zones["node-a.catofes."]; zs == nil || zs.Records[ipsec.RecordKeyTransportKey] == nil {
			return false
		}
	}
	plan, err := ipsec.PlanTransportLinks(context.Background(), verified.Network, verified.ManagedZone, []ipsec.LinkGroupSpec{group}, ipsec.LinkPlannerOptions{Now: time.Now()})
	if err != nil || len(plan.Desired) != 1 {
		return false
	}
	spec := photonlinux.InjectIPsecKeyMaterial(verified.Network, key, plan.Desired)[0]
	inst, ok := links[ipsec.LinkInstanceID(spec)]
	return ok && inst.ActualState == ipsec.LinkStateUp
}

func logDaemonTestFile(t *testing.T, label, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Logf("--- %s unavailable: %v ---", label, err)
		return
	}
	t.Logf("--- %s ---\n%s", label, string(data))
}

func dumpDaemonSystemState(t *testing.T, ctx context.Context, namespaces ...string) {
	t.Helper()
	for _, args := range [][]string{
		{"netns", "list"},
		{"link", "show", "type", "xfrm"},
		{"xfrm", "state"},
		{"xfrm", "policy"},
	} {
		if out, err := appExecCommand(ctx, "ip", args...); err == nil {
			t.Logf("ip %s\n%s", strings.Join(args, " "), string(out))
		} else {
			t.Logf("ip %s failed: %v\n%s", strings.Join(args, " "), err, string(out))
		}
	}
	for _, ns := range namespaces {
		for _, args := range [][]string{
			{"link"},
			{"addr"},
			{"route"},
			{"xfrm", "state"},
			{"xfrm", "policy"},
		} {
			full := append([]string{"netns", "exec", ns, "ip"}, args...)
			if out, err := appExecCommand(ctx, "ip", full...); err == nil {
				t.Logf("ip %s\n%s", strings.Join(full, " "), string(out))
			} else {
				t.Logf("ip %s failed: %v\n%s", strings.Join(full, " "), err, string(out))
			}
		}
	}
	if out, err := appExecCommand(ctx, "swanctl", "--list-sas"); err == nil {
		t.Logf("swanctl --list-sas\n%s", string(out))
	} else {
		t.Logf("swanctl --list-sas failed: %v\n%s", err, string(out))
	}
}

func dumpDaemonVICISAs(t *testing.T, ctx context.Context, viciSocket, label string) {
	t.Helper()
	client, err := ipsec.NewGoviciClient(viciSocket)
	if err != nil {
		t.Logf("vici connect %s: %v", label, err)
		return
	}
	defer client.Close()
	events, err := client.CallStreaming(ctx, "list-sas", "list-sa", nil)
	if err != nil {
		t.Logf("vici list-sas %s: %v", label, err)
		return
	}
	t.Logf("--- vici list-sas %s ---", label)
	for _, event := range events {
		t.Logf("%s", formatDaemonVICIEvent(event))
	}
}

func formatDaemonVICIEvent(event map[string]any) string {
	var parts []string
	for k, v := range event {
		parts = append(parts, fmt.Sprintf("%s=%v", k, v))
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}
