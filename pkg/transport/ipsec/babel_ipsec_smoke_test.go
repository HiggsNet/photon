package ipsec

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/routing/bird"
)

type babelIPsecSmokePeer struct {
	ns, iface, underlay, tunnel string
	prefix4, prefix6            netip.Prefix
	address4, address6          netip.Addr
	spec                        TransportLinkSpec
	vici                        *GoviciClient
	birdSpec                    bird.BirdInstanceSpec
	birdConfig                  []byte
	birdClient                  bird.Client
	birdProcess                 *bird.ExecProcessManager
	charonLog, birdLog          string
}

// This intentionally uses the production traffic-selector and BIRD config
// generators unchanged. A handshake, learned route, or a static remote route
// must not stand in for real bidirectional IPv4 AND IPv6 encrypted traffic.
func TestBabelOverIPsecDualStackSmoke(t *testing.T) {
	if os.Getenv("PHOTON_IPSEC_BABEL_SMOKE") != "1" {
		t.Skip("set PHOTON_IPSEC_BABEL_SMOKE=1 to run the isolated real BIRD/charon dual-stack smoke")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	rootDir, err := os.MkdirTemp("", "photon-babel-ipsec-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(rootDir) })
	suffix := fmt.Sprint(time.Now().UnixNano())
	a := &babelIPsecSmokePeer{
		ns: "photon-babel-esp-a-" + suffix, iface: "phxjointa0", underlay: "192.0.2.17", tunnel: "fe80::4242:1",
		prefix4: netip.MustParsePrefix("10.243.1.0/24"), prefix6: netip.MustParsePrefix("fd43:4242:1::/64"),
		address4: netip.MustParseAddr("10.243.1.1"), address6: netip.MustParseAddr("fd43:4242:1::1"),
	}
	b := &babelIPsecSmokePeer{
		ns: "photon-babel-esp-b-" + suffix, iface: "phxjointb0", underlay: "192.0.2.18", tunnel: "fe80::4242:2",
		prefix4: netip.MustParsePrefix("10.243.2.0/24"), prefix6: netip.MustParsePrefix("fd43:4242:2::/64"),
		address4: netip.MustParseAddr("10.243.2.1"), address6: netip.MustParseAddr("fd43:4242:2::1"),
	}
	peers := []*babelIPsecSmokePeer{a, b}
	defer func() {
		if t.Failed() {
			for i, peer := range peers {
				dumpBabelIPsecSmoke(t, ctx, peer, peers[1-i])
			}
		}
	}()
	for _, peer := range peers {
		runIP(t, ctx, "netns", "add", peer.ns)
		t.Cleanup(func() { _ = exec.Command("ip", "netns", "delete", peer.ns).Run() })
		runIP(t, ctx, "netns", "exec", peer.ns, "ip", "link", "set", "lo", "up")
		// Only the newly-created namespaces are changed. Avoid waiting for DAD
		// before the first Babel Hello on the explicitly assigned link-local.
		for _, key := range []string{"all", "default"} {
			runIP(t, ctx, "netns", "exec", peer.ns, "sysctl", "-w", "net.ipv6.conf."+key+".accept_dad=0")
		}
		for _, address := range []netip.Addr{peer.address4, peer.address6} {
			runIP(t, ctx, "netns", "exec", peer.ns, "ip", "addr", "add", netip.PrefixFrom(address, address.BitLen()).String(), "dev", "lo")
		}
	}
	vethA, vethB := "phjta"+suffix[len(suffix)-5:], "phjtb"+suffix[len(suffix)-5:]
	runIP(t, ctx, "link", "add", vethA, "type", "veth", "peer", "name", vethB)
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", vethA).Run() })
	for i, peer := range peers {
		veth := []string{vethA, vethB}[i]
		runIP(t, ctx, "link", "set", veth, "netns", peer.ns)
		runIP(t, ctx, "netns", "exec", peer.ns, "ip", "addr", "add", peer.underlay+"/30", "dev", veth)
		runIP(t, ctx, "netns", "exec", peer.ns, "ip", "link", "set", veth, "up")
	}

	keyA, err := generateTransportPrivateKey(AlgorithmEd25519)
	if err != nil {
		t.Fatal(err)
	}
	keyB, err := generateTransportPrivateKey(AlgorithmEd25519)
	if err != nil {
		t.Fatal(err)
	}
	for i, peer := range peers {
		other := peers[1-i]
		dir := filepath.Join(rootDir, fmt.Sprint(i))
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		piddir := filepath.Join(dir, "run")
		if err := os.Mkdir(piddir, 0700); err != nil {
			t.Fatal(err)
		}
		socket := filepath.Join(dir, "charon.vici")
		conf, err := writeStrongSwanConf(socket)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Remove(conf) })
		peer.charonLog = filepath.Join(dir, "charon.log")
		logFile, err := os.Create(peer.charonLog)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = logFile.Close() })
		charon := startCharonInNetNS(ctx, t, peer.ns, piddir, conf, logFile)
		t.Cleanup(func() { _ = charon.Process.Kill(); _ = charon.Wait() })
		peer.vici, err = waitForVICI(ctx, socket)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = peer.vici.Close() })
		assertCharonPrivateRunMount(t, charon, piddir)
		localKey, peerKey := keyA, keyB
		if i == 1 {
			localKey, peerKey = keyB, keyA
		}
		peer.spec = TransportLinkSpec{
			LocalZone: "joint-a.invalid.", PeerZone: "joint-b.invalid.", IKEIdentity: "joint-a.invalid.",
			OverlayID: "joint-smoke", Provider: ProviderStrongSwan, TransportID: fmt.Sprintf("ipsec-joint-%d", i),
			InitiatorRole: InitiatorRolePrimary, PathMode: PathModeFamilyRedundant,
			LocalAddress: peer.underlay, ContactPoints: []ContactPoint{{Address: other.underlay, IKEPort: DefaultIKEPort, NATTPort: DefaultNATTPort}},
			XFRMIfID: uint32(424540 + i), InterfaceName: peer.iface, NetNS: peer.ns,
			LocalTunnelAddr: netip.MustParseAddr(peer.tunnel), PeerTunnelAddr: netip.MustParseAddr(other.tunnel),
			LocalPrivateKey: localKey.PrivateKey, LocalPrivateKeyAlgorithm: AlgorithmEd25519, PeerPublicKey: peerKey.PublicKey,
		}
		if i == 1 {
			peer.spec.LocalZone, peer.spec.PeerZone = "joint-b.invalid.", "joint-a.invalid."
			peer.spec.IKEIdentity = "joint-b.invalid."
			peer.spec.ContactPoints, peer.spec.InitiatorRole = nil, ""
		}
		xfrm := NewSystemXFRMDriver(NetNSSpec{Kind: NetNSName, Name: peer.ns})
		xfrm.StateNetNS = NetNSSpec{Kind: NetNSName, Name: peer.ns}
		if _, err := ApplyTransportLink(ctx, &StrongSwanDriver{VICI: peer.vici}, xfrm, peer.spec, NetNSSpec{Kind: NetNSName, Name: peer.ns}); err != nil {
			t.Fatalf("apply %s: %v", peer.ns, err)
		}
	}
	if err := InitiateTransportChild(ctx, &StrongSwanDriver{VICI: a.vici}, a.spec, nil); err != nil {
		t.Fatal(err)
	}
	for i, peer := range peers {
		if err := waitForSA(ctx, peer.vici, peer.spec.TransportID); err != nil {
			t.Fatal(err)
		}
		other := peers[1-i]
		dir := filepath.Join(rootDir, fmt.Sprint(i))
		peer.birdLog = filepath.Join(dir, "bird.log")
		peer.birdSpec = bird.BirdInstanceSpec{
			RouterID: uint32(0x0af30001 + i), NetNSName: peer.ns, Mode: bird.BirdModeManaged,
			NetNS: bird.NetNSSpec{Kind: "name", Name: peer.ns}, TableID: "main", InternalTableName: "joint",
			ControlSocketPath: filepath.Join(dir, "bird.ctl"), ConfigPath: filepath.Join(dir, "bird.conf"), PIDFilePath: filepath.Join(dir, "bird.pid"),
			InterfacePatterns: []string{peer.iface}, DeviceScanTime: time.Second,
			BabelHelloInterval: time.Second, BabelUpdateInterval: time.Second,
			LogTarget: fmt.Sprintf("log %q all", peer.birdLog),
			// These are local origins only. Remote business routes must come
			// from Babel and must disappear when the remote BIRD stops.
			StaticRoutes: []bird.StaticRouteSpec{{Prefix: peer.prefix4, Via: "lo"}, {Prefix: peer.prefix6, Via: "lo"}},
		}
		owner := bird.BirdResourceOwner{Manager: "photon", InstanceID: peer.ns, NetNSName: peer.ns}
		owner.Token = bird.OwnerToken(owner.InstanceID, owner.NetNSName)
		owner.ControlSocketToken = bird.ResourceToken(owner, "control_socket")
		owner.PIDFileToken = bird.ResourceToken(owner, "pid_file")
		owner.ConfigFileToken = bird.ResourceToken(owner, "config_file")
		peer.birdSpec.Owner = owner
		peer.birdConfig, err = (bird.DefaultConfigGenerator{}).Generate(peer.birdSpec,
			[]netip.Prefix{other.prefix4, other.prefix6}, []netip.Prefix{peer.prefix4, peer.prefix6})
		if err != nil {
			t.Fatal(err)
		}
		peer.birdProcess = bird.NewExecProcessManager("")
		peer.birdClient = bird.NewClientWithRouteTables(peer.birdSpec.ControlSocketPath, 2*time.Second, []string{"joint4", "joint6"})
		for _, prefix := range []netip.Prefix{other.prefix4, other.prefix6} {
			if combinedKernelRoute(t, ctx, peer, prefix) != "" {
				t.Fatalf("remote prefix %s already routed before BIRD startup", prefix)
			}
		}
		t.Cleanup(func() { _ = peer.birdProcess.Stop(context.Background(), peer.birdSpec) })
		startCombinedBird(t, ctx, peer)
	}

	for _, family := range []int{6, 4} {
		waitCombinedRoutes(t, ctx, peers, family, true)
		pingCombinedPrefixes(t, ctx, peers, family)
	}
	if err := b.birdProcess.Stop(ctx, b.birdSpec); err != nil {
		t.Fatalf("stop only test BIRD B: %v", err)
	}
	for _, family := range []int{6, 4} {
		waitCombinedRoutes(t, ctx, []*babelIPsecSmokePeer{a, b}, family, false)
	}
	t.Log("both business families withdrawn after remote BIRD stop; no static fallback")
	startCombinedBird(t, ctx, b)
	for _, family := range []int{6, 4} {
		waitCombinedRoutes(t, ctx, peers, family, true)
		pingCombinedPrefixes(t, ctx, peers, family)
	}
	t.Log("production BIRD generator + real IPsec: IPv4/IPv6 learned routes, encrypted bidirectional ping, withdrawal and recovery passed")
}

func startCombinedBird(t *testing.T, ctx context.Context, peer *babelIPsecSmokePeer) {
	t.Helper()
	if err := os.WriteFile(peer.birdSpec.ConfigPath, peer.birdConfig, 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := execCommand(ctx, "ip", "netns", "exec", peer.ns, "bird", "-p", "-c", peer.birdSpec.ConfigPath); err != nil {
		t.Fatalf("parse production BIRD config in %s: %v\n%s\n%s", peer.ns, err, out, peer.birdConfig)
	}
	if err := peer.birdProcess.Start(ctx, peer.birdSpec); err != nil {
		t.Fatalf("start generated BIRD in %s: %v\n%s", peer.ns, err, peer.birdConfig)
	}
}

func combinedKernelRoute(t *testing.T, ctx context.Context, peer *babelIPsecSmokePeer, prefix netip.Prefix) string {
	t.Helper()
	family := "-6"
	if prefix.Addr().Is4() {
		family = "-4"
	}
	out, err := execCommand(ctx, "ip", "netns", "exec", peer.ns, "ip", family, "route", "show", "exact", prefix.String())
	if err != nil {
		t.Fatalf("kernel route %s in %s: %v: %s", prefix, peer.ns, err, out)
	}
	return strings.TrimSpace(string(out))
}

func waitCombinedRoutes(t *testing.T, ctx context.Context, peers []*babelIPsecSmokePeer, family int, present bool) {
	t.Helper()
	deadline := time.Now().Add(25 * time.Second)
	var last string
	for time.Now().Before(deadline) && ctx.Err() == nil {
		ready := true
		for i, peer := range peers {
			if !present && i == 1 {
				continue // BIRD B is intentionally stopped; A must withdraw B's origins.
			}
			other := peers[1-i]
			prefix := other.prefix6
			if family == 4 {
				prefix = other.prefix4
			}
			observation, err := peer.birdClient.Status(ctx)
			if err != nil || observation.Stale {
				t.Fatalf("BIRD observation unavailable in %s: %v, %+v", peer.ns, err, observation)
			}
			learned := false
			for _, route := range observation.Routes {
				if route.Prefix == prefix && route.Selected && strings.HasPrefix(route.Protocol, "photon_babel_") && route.Iface == peer.iface {
					learned = true
				}
			}
			kernel := combinedKernelRoute(t, ctx, peer, prefix)
			installed := strings.Contains(kernel, "dev "+peer.iface) && strings.Contains(kernel, "proto bird")
			if present && (!learned || !installed) || !present && (learned || kernel != "") {
				ready = false
				last = fmt.Sprintf("%s prefix=%s learned=%v kernel=%q", peer.ns, prefix, learned, kernel)
			}
		}
		if ready {
			t.Logf("IPv%d Babel remote routes present=%v verified in BIRD and namespace kernel tables", family, present)
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("IPv%d Babel routes present=%v did not converge: %s", family, present, last)
}

type combinedPacketCounters struct {
	SAInbound, LinkRX, LinkTX uint64
}

func combinedCounters(t *testing.T, ctx context.Context, peer *babelIPsecSmokePeer) combinedPacketCounters {
	t.Helper()
	sas, err := (&StrongSwanDriver{VICI: peer.vici}).ListSAs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var result combinedPacketCounters
	found := false
	for _, sa := range sas {
		if sa.Name == peer.spec.TransportID && sa.Established && sa.XFRMIfID == peer.spec.XFRMIfID {
			found = true
			result.SAInbound += sa.InboundPackets
		}
	}
	if !found {
		t.Fatalf("no established SA for %s if_id=%d", peer.spec.TransportID, peer.spec.XFRMIfID)
	}
	out, err := execCommand(ctx, "ip", "netns", "exec", peer.ns, "ip", "-j", "-s", "link", "show", "dev", peer.iface)
	if err != nil {
		t.Fatal(err)
	}
	type stats struct {
		RX struct{ Packets uint64 } `json:"rx"`
		TX struct{ Packets uint64 } `json:"tx"`
	}
	var links []struct {
		Stats64 stats `json:"stats64"`
	}
	if err := json.Unmarshal(out, &links); err != nil || len(links) != 1 {
		t.Fatalf("invalid interface counters: %v: %s", err, out)
	}
	result.LinkRX, result.LinkTX = links[0].Stats64.RX.Packets, links[0].Stats64.TX.Packets
	return result
}

func pingCombinedPrefixes(t *testing.T, ctx context.Context, peers []*babelIPsecSmokePeer, family int) {
	t.Helper()
	before := []combinedPacketCounters{combinedCounters(t, ctx, peers[0]), combinedCounters(t, ctx, peers[1])}
	for i, peer := range peers {
		other := peers[1-i]
		source, destination := peer.address6, other.address6
		if family == 4 {
			source, destination = peer.address4, other.address4
		}
		out, err := execCommand(ctx, "ip", "netns", "exec", peer.ns, "ip", fmt.Sprintf("-%d", family), "route", "get", destination.String(), "from", source.String())
		if err != nil || !strings.Contains(string(out), "dev "+peer.iface) {
			t.Fatalf("business route did not use XFRM: %v: %s", err, out)
		}
		t.Logf("IPv%d route get in %s: %s", family, peer.ns, strings.TrimSpace(string(out)))
		if out, err := execCommand(ctx, "ip", "netns", "exec", peer.ns, "ping", fmt.Sprintf("-%d", family), "-I", source.String(), "-c", "3", "-W", "2", destination.String()); err != nil {
			t.Fatalf("IPv%d learned-route encrypted business ping %s -> %s: %v\n%s", family, source, destination, err, out)
		}
	}
	for i, peer := range peers {
		after := combinedCounters(t, ctx, peer)
		if after.SAInbound <= before[i].SAInbound || after.LinkRX <= before[i].LinkRX || after.LinkTX <= before[i].LinkTX {
			t.Fatalf("IPv%d no encrypted/interface packet progress in %s: before=%+v after=%+v", family, peer.ns, before[i], after)
		}
		t.Logf("IPv%d encrypted/interface counter progress in %s before=%+v after=%+v", family, peer.ns, before[i], after)
	}
}

func dumpBabelIPsecSmoke(t *testing.T, ctx context.Context, peer, other *babelIPsecSmokePeer) {
	t.Helper()
	for _, path := range []string{peer.charonLog, peer.birdLog} {
		if data, err := os.ReadFile(path); err == nil {
			t.Logf("%s:\n%s", path, data)
		}
	}
	for _, args := range [][]string{
		{"-s", "xfrm", "state", "list", "nokeys"}, {"xfrm", "policy"},
		{"-4", "route", "show", "table", "all"}, {"-6", "route", "show", "table", "all"},
		{"-4", "route", "get", other.address4.String(), "from", peer.address4.String()},
		{"-6", "route", "get", other.address6.String(), "from", peer.address6.String()},
		{"-s", "link", "show", "dev", peer.iface},
	} {
		full := append([]string{"netns", "exec", peer.ns, "ip"}, args...)
		out, err := execCommand(ctx, "ip", full...)
		t.Logf("%s ip %v (%v):\n%s", peer.ns, args, err, out)
	}
	if peer.vici != nil {
		sas, err := (&StrongSwanDriver{VICI: peer.vici}).ListSAs(ctx)
		t.Logf("%s VICI SAs/counters (%v): %+v", peer.ns, err, sas)
	}
	if peer.birdClient != nil {
		for _, command := range []string{"show protocols all", "show babel neighbors", "show route table all all"} {
			out, err := peer.birdClient.Raw(ctx, command)
			t.Logf("%s bird %s (%v):\n%s", peer.ns, command, err, out)
		}
	}
}
