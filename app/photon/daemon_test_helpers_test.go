package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"github.com/HiggsNet/photon/pkg/core/gossip"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"
)

type observedIPsecDriver struct {
	ipsec.DryRunDriver
	sas        []ipsec.SAState
	linkState  *ipsec.XFRMLinkState
	linkStates map[string]ipsec.XFRMLinkState
	listCalls  int
}

func endpointRecordBytes(endpoints []gossip.LocalEndpoint, now time.Time) []byte {
	record := gossip.LocalEndpointsToRecordWithPolicy(endpoints, nil, now, gossip.DefaultEndpointTTL, gossip.DefaultEndpointGrace)
	value, err := json.Marshal(record)
	if err != nil {
		panic(err)
	}
	return value
}

func (d *observedIPsecDriver) ListSAs(context.Context) ([]ipsec.SAState, error) {
	d.listCalls++
	return d.sas, nil
}

func (d *observedIPsecDriver) InspectLink(_ context.Context, spec ipsec.TransportLinkSpec) (ipsec.XFRMLinkState, error) {
	if d.linkStates != nil {
		if state, ok := d.linkStates[spec.InterfaceName]; ok {
			return state, nil
		}
		return ipsec.XFRMLinkState{
			NetNS:           ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: spec.NetNS}.Normalized(),
			NamespaceExists: true,
			InterfaceExists: false,
		}, nil
	}
	if d.linkState != nil {
		return *d.linkState, nil
	}
	state := ipsec.XFRMLinkState{
		NetNS:           ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: spec.NetNS}.Normalized(),
		NamespaceExists: true,
		InterfaceExists: true,
	}
	if spec.LocalTunnelAddr.IsValid() {
		state.Addresses = []netip.Prefix{netip.PrefixFrom(spec.LocalTunnelAddr, 128)}
	}
	return state, nil
}

func (d *observedIPsecDriver) FilterSAsWithMissingLinks(ctx context.Context, desired []ipsec.TransportLinkSpec, sas []ipsec.SAState) ([]ipsec.SAState, map[string]ipsec.TransportLinkSpec, error) {
	missing := make(map[string]ipsec.TransportLinkSpec)
	for _, spec := range desired {
		state, err := d.InspectLink(ctx, spec)
		if err != nil {
			return nil, nil, err
		}
		if xfrmLinkStateMatchesCandidate(state, spec) {
			continue
		}
		missing[ipsec.LinkInstanceID(spec)] = spec
	}
	if len(missing) == 0 {
		return sas, missing, nil
	}
	filtered := sas[:0]
	for _, sa := range sas {
		drop := false
		for _, spec := range missing {
			if sa.Name == spec.TransportID || sa.ChildSA == ipsec.ChildSAName(spec) || sa.XFRMIfID == spec.XFRMIfID {
				drop = true
				break
			}
		}
		if !drop {
			filtered = append(filtered, sa)
		}
	}
	return filtered, missing, nil
}

type countingIPsecDriver struct {
	ipsec.DryRunDriver
	listCalls int
}

func (d *countingIPsecDriver) ListSAs(context.Context) ([]ipsec.SAState, error) {
	d.listCalls++
	return d.DryRunDriver.ListSAs(context.Background())
}

type staleCommitIPsecDriver struct {
	ipsec.DryRunDriver
	onLoadConnection func(ipsec.TransportLinkSpec)
	loadedOnce       bool
}

func (d *staleCommitIPsecDriver) LoadConnection(ctx context.Context, spec ipsec.TransportLinkSpec) error {
	if !d.loadedOnce {
		d.loadedOnce = true
		if d.onLoadConnection != nil {
			d.onLoadConnection(spec)
		}
	}
	return d.DryRunDriver.LoadConnection(ctx, spec)
}

func testIPsecLinkGroup() ipsec.LinkGroupSpec {
	return ipsec.LinkGroupSpec{
		ID:                 "main",
		Provider:           ipsec.ProviderStrongSwan,
		NetNS:              ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "photontesth2", Create: true},
		DefaultPathMode:    ipsec.PathModeFamilyRedundant,
		AddressSourceOrder: []string{ipsec.SourceManualAddress},
		TunnelAddressSpec: ipsec.TunnelAddressSpec{
			Mode:   ipsec.TunnelAddressSequentialPool,
			Family: ipsec.FamilyIPv4,
			Pool:   netip.MustParsePrefix("10.44.0.0/29"),
		},
		ConnectRules: []string{"strongswan://node-*.catofes.?role=in"},
	}
}

func singleDesiredSpec(t *testing.T, state *stateFile) ipsec.TransportLinkSpec {
	t.Helper()
	if state == nil || state.IPsecReconcile == nil || len(state.IPsecReconcile.Desired) != 1 {
		t.Fatalf("desired snapshot = %+v, want one desired link", state.IPsecReconcile)
	}
	desired := state.IPsecReconcile.Desired[0]
	localTunnel := netip.MustParseAddr("10.44.0.1")
	peerTunnel := netip.MustParseAddr("10.44.0.2")
	if desired.PeerZone < state.ManagedZone {
		localTunnel, peerTunnel = peerTunnel, localTunnel
	}
	return ipsec.TransportLinkSpec{
		LocalZone:       state.ManagedZone,
		PeerZone:        desired.PeerZone,
		OverlayID:       desired.GroupID,
		Provider:        ipsec.ProviderStrongSwan,
		LinkID:          desired.LinkID,
		PathKey:         desired.PathKey,
		TransportID:     desired.TransportID,
		InterfaceName:   desired.InterfaceName,
		XFRMIfID:        desired.XFRMIfID,
		LocalTunnelAddr: localTunnel,
		PeerTunnelAddr:  peerTunnel,
		NetNS:           "photontesth2",
		ContactPoints: []ipsec.ContactPoint{{
			Address:  desired.Endpoint,
			IKEPort:  ipsec.DefaultIKEPort,
			NATTPort: ipsec.DefaultNATTPort,
		}},
	}
}

func assertDryRunApply(t *testing.T, driver *observedIPsecDriver, spec ipsec.TransportLinkSpec, netns ipsec.NetNSSpec) {
	t.Helper()
	if len(driver.Namespaces) != 1 || driver.Namespaces[0] != netns.Normalized() {
		t.Fatalf("namespaces = %+v, want %s", driver.Namespaces, netns.Target())
	}
	if len(driver.Connections) != 1 || driver.Connections[0].TransportID != spec.TransportID {
		t.Fatalf("connections = %+v, want one %s", driver.Connections, spec.TransportID)
	}
	if len(driver.Interfaces) == 0 {
		t.Fatalf("interfaces = %+v, want %s/%d", driver.Interfaces, spec.InterfaceName, spec.XFRMIfID)
	}
	for _, iface := range driver.Interfaces {
		if iface.InterfaceName != spec.InterfaceName || iface.XFRMIfID != spec.XFRMIfID {
			t.Fatalf("interfaces = %+v, want only %s/%d", driver.Interfaces, spec.InterfaceName, spec.XFRMIfID)
		}
	}
	wantAddr := spec.InterfaceName + "=" + netip.PrefixFrom(spec.LocalTunnelAddr, 32).String()
	if len(driver.Addresses) == 0 {
		t.Fatalf("addresses = %+v, want %s", driver.Addresses, wantAddr)
	}
	for _, addr := range driver.Addresses {
		if addr != wantAddr {
			t.Fatalf("addresses = %+v, want only %s", driver.Addresses, wantAddr)
		}
	}
}

func assertStrongSwanLoadConnMatchesSpec(t *testing.T, spec ipsec.TransportLinkSpec) {
	t.Helper()
	msg, err := ipsec.BuildLoadConnMessage(spec)
	if err != nil {
		t.Fatalf("BuildLoadConnMessage: %v", err)
	}
	raw := msg[spec.TransportID]
	conn, ok := raw.(map[string]any)
	if !ok {
		t.Fatalf("load-conn message = %#v", msg)
	}
	if got := conn["remote_port"]; got != "4500" {
		t.Fatalf("remote_port = %#v, want 4500", got)
	}
	if got := conn["encap"]; got != "yes" {
		t.Fatalf("encap = %#v, want yes", got)
	}
	if got := conn["local_port"]; got != "4500" {
		t.Fatalf("local_port = %#v, want 4500", got)
	}
	children, _ := conn["children"].(map[string]any)
	child, _ := children[ipsec.ChildSAName(spec)].(map[string]any)
	if child["if_id_in"] != fmt.Sprintf("%d", spec.XFRMIfID) || child["if_id_out"] != fmt.Sprintf("%d", spec.XFRMIfID) {
		t.Fatalf("child if_id = %#v, want %d", child, spec.XFRMIfID)
	}
	local, _ := conn["local"].(map[string]any)
	remote, _ := conn["remote"].(map[string]any)
	if local["id"] != string(spec.LocalZone) || remote["id"] != string(spec.PeerZone) {
		t.Fatalf("conn identities local=%#v remote=%#v spec=%+v", local["id"], remote["id"], spec)
	}
}

func observedSAForSpec(spec ipsec.TransportLinkSpec, localEndpoint, remoteEndpoint string, reqID uint32) ipsec.SAState {
	return ipsec.SAState{
		Name:           spec.TransportID,
		Peer:           remoteEndpoint,
		ChildSA:        ipsec.ChildSAName(spec),
		XFRMIfID:       spec.XFRMIfID,
		ReqID:          reqID,
		LocalIdentity:  string(spec.LocalZone),
		RemoteIdentity: string(spec.PeerZone),
		LocalEndpoint:  localEndpoint,
		RemoteEndpoint: remoteEndpoint,
		Endpoint:       remoteEndpoint,
		Established:    true,
	}
}

func buildTestABDaemonStates(t *testing.T) (*stateFile, *syncConfigFile, *stateFile, *syncConfigFile) {
	t.Helper()
	rootPub, rootPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(root): %v", err)
	}
	catofesPub, catofesPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(catofes): %v", err)
	}
	nodeAPub, nodeAPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(node-a): %v", err)
	}
	nodeBPub, nodeBPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(node-b): %v", err)
	}

	rootAuthority := &zone.ZoneAuthority{
		Zone:      zone.RootZone,
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: rootPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermDelegate},
			}},
		}},
	}
	catofesAuthority := &zone.ZoneAuthority{
		Zone:      "catofes.",
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: catofesPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermDelegate},
			}},
		}},
	}
	nodeAAuthority := testWriteAuthority("node-a.catofes.", nodeAPub)
	nodeBAuthority := testWriteAuthority("node-b.catofes.", nodeBPub)
	catofesDelegation := testSignedDelegation(t, "catofes.", *catofesAuthority, zone.RootZone, rootPriv)
	nodeADelegation := testSignedDelegation(t, "node-a.catofes.", *nodeAAuthority, "catofes.", catofesPriv)
	nodeBDelegation := testSignedDelegation(t, "node-b.catofes.", *nodeBAuthority, "catofes.", catofesPriv)

	buildNetwork := func(managed zone.ZonePath) *zone.NetworkState {
		ns := zone.NewNetworkState()
		ns.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, rootAuthority)
		ns.Zones["catofes."] = zone.NewZoneState("catofes.", catofesAuthority)
		ns.Zones[zone.RootZone].Delegations["catofes."] = catofesDelegation
		ns.Zones["catofes."].Delegations["node-a.catofes."] = nodeADelegation
		ns.Zones["catofes."].Delegations["node-b.catofes."] = nodeBDelegation
		switch managed {
		case "node-a.catofes.":
			ns.Zones["node-a.catofes."] = zone.NewZoneState("node-a.catofes.", nodeAAuthority)
		case "node-b.catofes.":
			ns.Zones["node-b.catofes."] = zone.NewZoneState("node-b.catofes.", nodeBAuthority)
		default:
			t.Fatalf("unexpected managed zone %s", managed)
		}
		configureValidation(ns)
		for _, path := range []zone.ZonePath{"catofes.", managed} {
			if err := photoncrypto.VerifyChain(ns, path, time.Unix(123, 0)); err != nil {
				t.Fatalf("VerifyChain(%s): %v", path, err)
			}
		}
		return ns
	}

	stateA := &stateFile{
		ManagedZone:    "node-a.catofes.",
		Network:        buildNetwork("node-a.catofes."),
		ZonePrivateKey: nodeAPriv,
	}
	stateB := &stateFile{
		ManagedZone:    "node-b.catofes.",
		Network:        buildNetwork("node-b.catofes."),
		ZonePrivateKey: nodeBPriv,
	}
	configA := &syncConfigFile{PeerID: "node-a.catofes.", ListenAddr: "127.0.0.1:0"}
	configB := &syncConfigFile{PeerID: "node-b.catofes.", ListenAddr: "127.0.0.1:0"}
	return stateA, configA, stateB, configB
}

func testWriteAuthority(path zone.ZonePath, pub ed25519.PublicKey) *zone.ZoneAuthority {
	return &zone.ZoneAuthority{
		Zone:      path,
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: pub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermWrite},
			}},
		}},
	}
}

func testSignedDelegation(t *testing.T, path zone.ZonePath, authority zone.ZoneAuthority, parent zone.ZonePath, priv ed25519.PrivateKey) *zone.Delegation {
	t.Helper()
	delegation := &zone.Delegation{
		ZoneName:  path,
		Scope:     zone.DelegationScopeDirectChild,
		Authority: authority,
	}
	if err := photoncrypto.SignDelegation(delegation, parent, priv); err != nil {
		t.Fatalf("SignDelegation(%s): %v", path, err)
	}
	return delegation
}

func testDaemonIPsecAppConfig(dataDir, advertiseAddr string, group ipsec.LinkGroupSpec) *appConfig {
	config := defaultAppConfig()
	config.DataDir = dataDir
	config.StatePath = filepath.Join(dataDir, "photon.db")
	config.ListenAddr = advertiseAddr
	config.AdvertiseAddrs = []string{advertiseAddr}
	config.PublishEndpoints = false
	config.IPsec.LinkGroups = []ipsec.LinkGroupSpec{group}
	return config
}

func assertGossipedIPsecRecords(t *testing.T, state *stateFile, peer zone.ZonePath) {
	t.Helper()
	zs := state.Network.Zones[peer]
	if zs == nil {
		t.Fatalf("zone %s missing after gossip", peer)
	}
	for _, key := range []string{ipsec.RecordKeyProfile, ipsec.RecordKeyAddresses, ipsec.RecordKeyPorts, ipsec.RecordKeyTransportKey, ipsec.OverlayIntentRecordKey("main")} {
		if zs.Records[key] == nil {
			t.Fatalf("%s missing for %s after gossip", key, peer)
		}
	}
}

func assertSingleLinkUpFromSA(t *testing.T, state *stateFile, spec ipsec.TransportLinkSpec, sa ipsec.SAState) {
	t.Helper()
	if state.IPsecReconcile == nil || len(state.IPsecReconcile.Actions) != 1 || state.IPsecReconcile.Actions[0].Action != ipsec.ReconcileActionAdopt {
		t.Fatalf("reconcile = %+v, want adopt", state.IPsecReconcile)
	}
	inst := state.LinkInstances[ipsec.LinkInstanceID(spec)]
	if inst.ActualState != ipsec.LinkStateUp || inst.Endpoint != sa.Endpoint {
		t.Fatalf("instance = %+v, want up endpoint %s", inst, sa.Endpoint)
	}
	if len(state.IPsecReconcile.ActualSAs) != 1 || state.IPsecReconcile.ActualSAs[0].ReqID != sa.ReqID || state.IPsecReconcile.ActualSAs[0].RemoteIdentity != sa.RemoteIdentity {
		t.Fatalf("actual SAs = %+v, want reqid=%d remote_id=%s", state.IPsecReconcile.ActualSAs, sa.ReqID, sa.RemoteIdentity)
	}
}

func hasDebugSkip(skips []linkSkipState, peer zone.ZonePath, reason string) bool {
	for _, skip := range skips {
		if skip.Peer == peer && skip.Reason == reason {
			return true
		}
	}
	return false
}

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
	// The %iface scope suffix is only valid for link-local targets; global
	// addresses must be resolved without it.
	if target.IsLinkLocalUnicast() {
		runAppCommand(t, ctx, "ip", "netns", "exec", ns, "ping", "-6", "-c", "1", "-W", "3", target.String()+"%"+iface)
		return
	}
	runAppCommand(t, ctx, "ip", "netns", "exec", ns, "ping", "-6", "-c", "1", "-W", "3", target.String())
}

func pingTunnelAddrShouldFail(t *testing.T, ctx context.Context, ns string, target netip.Addr, iface string) []byte {
	t.Helper()
	var cmdArgs []string
	if target.Is4() {
		cmdArgs = []string{"netns", "exec", ns, "ping", "-c", "1", "-W", "1", target.String()}
	} else if target.IsLinkLocalUnicast() {
		cmdArgs = []string{"netns", "exec", ns, "ping", "-6", "-c", "1", "-W", "1", target.String() + "%" + iface}
	} else {
		cmdArgs = []string{"netns", "exec", ns, "ping", "-6", "-c", "1", "-W", "1", target.String()}
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
	charonPath := "/usr/lib/ipsec/charon"
	if resolved, err := exec.LookPath("charon"); err == nil {
		charonPath = resolved
	}
	script := fmt.Sprintf("mkdir -p /run && mount --bind %s /run && STRONGSWAN_CONF=%s exec %s --debug-cfg 2 --debug-ike 2 --debug-mgr 2", piddir, conf, charonPath)
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

func daemonTestTransportKey(t *testing.T, now time.Time) (*ipsecTransportKeyState, *ipsec.TransportKeyRecord) {
	t.Helper()
	key, record, err := ipsec.GenerateTransportKeyRecord(ipsec.AlgorithmECDSAP256, now, 0)
	if err != nil {
		t.Fatalf("GenerateTransportKeyRecord: %v", err)
	}
	return &ipsecTransportKeyState{
		Kind:        key.Kind,
		Algorithm:   key.Algorithm,
		PublicKey:   append([]byte(nil), key.PublicKey...),
		PrivateKey:  append([]byte(nil), key.PrivateKey...),
		Fingerprint: record.Fingerprint,
		NotBefore:   record.NotBefore,
		NotAfter:    record.NotAfter,
		UpdatedAt:   record.UpdatedAt,
	}, record
}

func addDaemonTestIPsecRecords(t *testing.T, zs *zone.ZoneState, peer zone.ZonePath, address string, key *ipsec.TransportKeyRecord, accept string, now time.Time) {
	t.Helper()
	if zs == nil {
		t.Fatalf("missing zone state for %s", peer)
	}
	// The advertised underlay family must match the literal address, or the
	// planner derives the wrong path key and SAs stop matching the link.
	family := ipsec.FamilyIPv4
	if ip := net.ParseIP(address); ip != nil && ip.To4() == nil {
		family = ipsec.FamilyIPv6
	}
	zs.Records[ipsec.RecordKeyProfile] = unsignedIPsecRecord(t, peer, ipsec.RecordKeyProfile, ipsec.RecordTypeProfile, ipsec.ProfileRecord{
		Version:                 1,
		Enabled:                 true,
		Provider:                ipsec.ProviderStrongSwan,
		IKEIdentity:             string(peer),
		TransportKeyFingerprint: key.Fingerprint,
		Role:                    accept,
		AddressFamilies:         []string{family},
		PathModes:               []string{ipsec.PathModeFamilyRedundant},
		UpdatedAt:               now.Unix(),
	})
	zs.Records[ipsec.RecordKeyAddresses] = unsignedIPsecRecord(t, peer, ipsec.RecordKeyAddresses, ipsec.RecordTypeAddresses, ipsec.AddressRecord{
		Version: 1,
		Addresses: []ipsec.AddressAdvertisement{{
			ID:           "underlay-" + family,
			Source:       ipsec.SourceManualAddress,
			Address:      address,
			Family:       family,
			Reachability: ipsec.ReachabilityPublic,
		}},
		UpdatedAt: now.Unix(),
	})
	zs.Records[ipsec.RecordKeyPorts] = unsignedIPsecRecord(t, peer, ipsec.RecordKeyPorts, ipsec.RecordTypePorts, ipsec.PortRecord{
		Version: 1,
		Mode:    ipsec.PortModeFixed,
		Current: &ipsec.PortSelection{
			Generation: 1,
			IKE:        ipsec.PortBinding{Advertised: ipsec.DefaultIKEPort},
			NATT:       ipsec.PortBinding{Advertised: ipsec.DefaultNATTPort},
			ValidUntil: now.Add(time.Hour).Unix(),
		},
		UpdatedAt: now.Unix(),
	})
	zs.Records[ipsec.RecordKeyTransportKey] = unsignedIPsecRecord(t, peer, ipsec.RecordKeyTransportKey, ipsec.RecordTypeTransportKey, *key)
	zs.Records[ipsec.OverlayIntentRecordKey("main")] = unsignedIPsecRecord(t, peer, ipsec.OverlayIntentRecordKey("main"), ipsec.RecordTypeOverlayIntent, ipsec.OverlayIntentRecord{
		Version:       1,
		OverlayID:     "main",
		Provider:      ipsec.ProviderStrongSwan,
		PathKeys:      []string{"family:ipv4"},
		TunnelAddress: ipsec.TunnelAddressSpec{Mode: ipsec.TunnelAddressDerivedLinkLocal, Family: ipsec.FamilyIPv6},
		UpdatedAt:     now.Unix(),
	})
}

func setTestIPsecOverlayIntent(t *testing.T, zs *zone.ZoneState, peer zone.ZonePath, group ipsec.LinkGroupSpec, now time.Time) {
	t.Helper()
	if zs == nil {
		t.Fatalf("missing zone state for %s", peer)
	}
	group = group.Normalized()
	// Path keys must cover the group's advertised tunnel address family; the
	// legacy helper was IPv4-only and broke IPv6 underlay scenarios.
	pathKeys := []string{"family:ipv4"}
	if group.TunnelAddressSpec.Family == ipsec.FamilyIPv6 {
		pathKeys = []string{"family:ipv6", "family:ipv4"}
	}
	zs.Records[ipsec.OverlayIntentRecordKey(group.ID)] = unsignedIPsecRecord(t, peer, ipsec.OverlayIntentRecordKey(group.ID), ipsec.RecordTypeOverlayIntent, ipsec.OverlayIntentRecord{
		Version:       1,
		OverlayID:     group.ID,
		Provider:      group.Provider,
		PathKeys:      pathKeys,
		TunnelAddress: group.TunnelAddressSpec,
		UpdatedAt:     now.Unix(),
	})
}

func updateDaemonTestPortRecord(t *testing.T, zs *zone.ZoneState, peer zone.ZonePath, generation uint64, ikePort uint16, now time.Time) {
	t.Helper()
	if zs == nil {
		t.Fatalf("missing zone state for %s", peer)
	}
	if ikePort == 0 {
		ikePort = ipsec.DefaultIKEPort
	}
	nattPort := ikePort
	previous := ipsec.PortSelection{
		Generation: 1,
		IKE:        ipsec.PortBinding{Advertised: ipsec.DefaultIKEPort},
		NATT:       ipsec.PortBinding{Advertised: ipsec.DefaultNATTPort},
		ValidUntil: now.Add(time.Hour).Unix(),
	}
	zs.Records[ipsec.RecordKeyPorts] = unsignedIPsecRecord(t, peer, ipsec.RecordKeyPorts, ipsec.RecordTypePorts, ipsec.PortRecord{
		Version: 1,
		Mode:    ipsec.PortModeFixed,
		Current: &ipsec.PortSelection{
			Generation: generation,
			IKE:        ipsec.PortBinding{Local: ikePort, Advertised: ikePort},
			NATT:       ipsec.PortBinding{Local: nattPort, Advertised: nattPort},
			ValidUntil: now.Add(time.Hour).Unix(),
		},
		Previous:  []ipsec.PortSelection{previous},
		UpdatedAt: now.Unix(),
	})
}

func assertDaemonSystemLinkUp(t *testing.T, state *stateFile, spec ipsec.TransportLinkSpec) {
	t.Helper()
	inst := state.LinkInstances[ipsec.LinkInstanceID(spec)]
	if inst.ActualState != ipsec.LinkStateUp {
		t.Fatalf("link instance = %+v, want up", inst)
	}
	if state.IPsecReconcile == nil || len(state.IPsecReconcile.ActualSAs) == 0 {
		t.Fatalf("ipsec reconcile = %+v, want observed SAs", state.IPsecReconcile)
	}
	ikeName := inst.IKEName
	if ikeName == "" {
		ikeName = spec.TransportID
	}
	childName := inst.ChildSAName
	if childName == "" {
		childName = ipsec.ChildSAName(spec)
	}
	for _, sa := range state.IPsecReconcile.ActualSAs {
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
	t.Fatalf("actual SAs = %+v, want established SA for %s", state.IPsecReconcile.ActualSAs, spec.TransportID)
}

func daemonSystemDesiredSpec(t *testing.T, state *stateFile, group ipsec.LinkGroupSpec, now time.Time) ipsec.TransportLinkSpec {
	t.Helper()
	plan, err := ipsec.PlanTransportLinks(context.Background(), state.Network, state.ManagedZone, []ipsec.LinkGroupSpec{group}, ipsec.LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks(%s): %v", state.ManagedZone, err)
	}
	if len(plan.Desired) != 1 {
		t.Fatalf("desired for %s = %+v, skips=%+v, want one", state.ManagedZone, plan.Desired, plan.Skipped)
	}
	return injectIPsecKeyMaterial(state, plan.Desired)[0]
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

func waitDaemonRunGossipStrongSwanUp(ctx context.Context, t *testing.T, rtA, rtB *Runtime, groupA, groupB ipsec.LinkGroupSpec) (*stateFile, *stateFile) {
	t.Helper()
	var lastA, lastB *stateFile
	var lastErr error
	for {
		if stateA, err := rtA.LoadState(); err == nil {
			lastA = stateA
		} else {
			lastErr = err
		}
		if stateB, err := rtB.LoadState(); err == nil {
			lastB = stateB
		} else {
			lastErr = err
		}
		if lastA != nil && lastB != nil && daemonRunGossipStrongSwanReady(lastA, groupA) && daemonRunGossipStrongSwanReady(lastB, groupB) {
			return lastA, lastB
		}
		select {
		case <-ctx.Done():
			if lastA != nil {
				t.Logf("last node-a reconcile = %+v instances=%+v", lastA.IPsecReconcile, lastA.LinkInstances)
			}
			if lastB != nil {
				t.Logf("last node-b reconcile = %+v instances=%+v", lastB.IPsecReconcile, lastB.LinkInstances)
			}
			if lastErr != nil {
				t.Fatalf("timeout waiting for daemon gossip StrongSwan up; last load error: %v", lastErr)
			}
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

func daemonRunGossipStrongSwanReady(state *stateFile, group ipsec.LinkGroupSpec) bool {
	if state == nil || state.IPsecReconcile == nil || len(state.IPsecReconcile.ActualSAs) == 0 || len(state.LinkInstances) == 0 {
		return false
	}
	if state.ManagedZone == "node-a.catofes." {
		if zs := state.Network.Zones["node-b.catofes."]; zs == nil || zs.Records[ipsec.RecordKeyTransportKey] == nil {
			return false
		}
	}
	if state.ManagedZone == "node-b.catofes." {
		if zs := state.Network.Zones["node-a.catofes."]; zs == nil || zs.Records[ipsec.RecordKeyTransportKey] == nil {
			return false
		}
	}
	plan, err := ipsec.PlanTransportLinks(context.Background(), state.Network, state.ManagedZone, []ipsec.LinkGroupSpec{group}, ipsec.LinkPlannerOptions{Now: time.Now()})
	if err != nil || len(plan.Desired) != 1 {
		return false
	}
	spec := injectIPsecKeyMaterial(state, plan.Desired)[0]
	inst, ok := state.LinkInstances[ipsec.LinkInstanceID(spec)]
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

func addTestIPsecRecords(t *testing.T, zs *zone.ZoneState, peer zone.ZonePath, now time.Time, accept string) {
	t.Helper()
	if zs == nil {
		t.Fatalf("missing zone state for %s", peer)
	}
	fingerprint := "fp-" + string(peer)
	zs.Records[ipsec.RecordKeyProfile] = unsignedIPsecRecord(t, peer, ipsec.RecordKeyProfile, ipsec.RecordTypeProfile, ipsec.ProfileRecord{
		Version:                 1,
		Enabled:                 true,
		Provider:                ipsec.ProviderStrongSwan,
		IKEIdentity:             string(peer),
		TransportKeyFingerprint: fingerprint,
		Role:                    accept,
		AddressFamilies:         []string{ipsec.FamilyIPv4},
		PathModes:               []string{ipsec.PathModeFamilyRedundant},
		UpdatedAt:               now.Unix(),
	})
	zs.Records[ipsec.RecordKeyAddresses] = unsignedIPsecRecord(t, peer, ipsec.RecordKeyAddresses, ipsec.RecordTypeAddresses, ipsec.AddressRecord{
		Version: 1,
		Addresses: []ipsec.AddressAdvertisement{{
			ID:           "public-v4",
			Source:       ipsec.SourceManualAddress,
			Address:      "203.0.113.10",
			Family:       ipsec.FamilyIPv4,
			Reachability: ipsec.ReachabilityPublic,
		}},
		UpdatedAt: now.Unix(),
	})
	zs.Records[ipsec.RecordKeyPorts] = unsignedIPsecRecord(t, peer, ipsec.RecordKeyPorts, ipsec.RecordTypePorts, ipsec.PortRecord{
		Version: 1,
		Mode:    ipsec.PortModeFixed,
		Current: &ipsec.PortSelection{
			Generation: 1,
			IKE:        ipsec.PortBinding{Advertised: ipsec.DefaultIKEPort},
			NATT:       ipsec.PortBinding{Advertised: ipsec.DefaultNATTPort},
			ValidUntil: now.Add(time.Hour).Unix(),
		},
		UpdatedAt: now.Unix(),
	})
	zs.Records[ipsec.RecordKeyTransportKey] = unsignedIPsecRecord(t, peer, ipsec.RecordKeyTransportKey, ipsec.RecordTypeTransportKey, ipsec.TransportKeyRecord{
		Version:     1,
		Kind:        ipsec.TransportKeyRawPublicKey,
		Algorithm:   ipsec.AlgorithmEd25519,
		PublicKey:   "base64",
		Fingerprint: fingerprint,
		UpdatedAt:   now.Unix(),
	})
	zs.Records[ipsec.OverlayIntentRecordKey("main")] = unsignedIPsecRecord(t, peer, ipsec.OverlayIntentRecordKey("main"), ipsec.RecordTypeOverlayIntent, ipsec.OverlayIntentRecord{
		Version:       1,
		OverlayID:     "main",
		Provider:      ipsec.ProviderStrongSwan,
		PathKeys:      []string{"family:ipv4"},
		TunnelAddress: ipsec.TunnelAddressSpec{Mode: ipsec.TunnelAddressDerivedLinkLocal, Family: ipsec.FamilyIPv6},
		UpdatedAt:     now.Unix(),
	})
}

func unsignedIPsecRecord(t *testing.T, peer zone.ZonePath, key, recordType string, value any) *zone.Record {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("Marshal(%s): %v", key, err)
	}
	return &zone.Record{
		Zone:      peer,
		Key:       key,
		Type:      recordType,
		Value:     data,
		Version:   1,
		Timestamp: time.Unix(4000, 0).Unix(),
	}
}

func pumpDaemonEvents(ctx context.Context, service *DaemonService) {
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			service.processEvents(ctx)
		}
	}
}

func controlRequestViaPipe(t *testing.T, service *DaemonService, request controlRequest) controlResponse {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	_ = server.SetDeadline(time.Now().Add(5 * time.Second))
	done := make(chan struct{})
	go func() {
		defer close(done)
		service.handleControlConn(context.Background(), server)
	}()
	if err := json.NewEncoder(client).Encode(request); err != nil {
		t.Fatalf("Encode(request): %v", err)
	}
	var response controlResponse
	if err := json.NewDecoder(client).Decode(&response); err != nil {
		t.Fatalf("Decode(response): %v", err)
	}
	<-done
	return response
}

func pumpEventLoopSync(ctx context.Context, services []*DaemonService, transports []*gossip.Transport) {
	for {
		processed := false
		for _, svc := range services {
			select {
			case ev := <-svc.syncEvents:
				svc.handleSyncEvent(ctx, ev)
				processed = true
			default:
			}
			select {
			case res := <-svc.objectPullResults:
				_ = svc.postSyncEvent(objectPullResultToEvent(res))
				processed = true
			default:
			}
		}
		for i, tr := range transports {
			packet, err := receiveWithContext(ctx, tr, time.Now().Add(10*time.Millisecond))
			if err == nil {
				services[i].handlePacketEvent(packet, ctx)
				processed = true
			}
		}
		if !processed {
			return
		}
	}
}
