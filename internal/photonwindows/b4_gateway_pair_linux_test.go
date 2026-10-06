package photonwindows

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
	"github.com/HiggsNet/photon/pkg/routing"
	"github.com/HiggsNet/photon/pkg/routing/bird"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

// Only public backend facts leave a backend container. Its independent private
// transport key stays in that process. The coordinator issues one shared root
// and Windows identity after observing BOTH actual randomized BIRD identities.
type b4GatewayManifest struct {
	Zone         zone.ZonePath
	Address      netip.Addr
	IKE, NATT    uint16
	Host4, Host6 string
	RouterID     string
	Transport    ipsec.TransportKeyRecord
}

type b4SwitchTraffic struct {
	ObservedAt   time.Time
	Echo4, Echo6 uint64
	SAs          []ipsec.SAState
}

func b4SwitchWriteJSON(t *testing.T, path string, value any) {
	t.Helper()
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".tmp", b, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".tmp", path); err != nil {
		t.Fatal(err)
	}
}

func TestServeWindowsB4SwitchBackend(t *testing.T) {
	dir := os.Getenv("PHOTON_B4_SWITCH_BACKEND")
	if dir == "" {
		t.Skip("run windows-b4-gateway-switch-smoke.sh")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("backend requires disposable container")
	}
	index := os.Getenv("PHOTON_B4_SWITCH_INDEX")
	if index != "a" && index != "b" {
		t.Fatal("backend index must be a or b")
	}
	manifest := b4GatewayManifest{Zone: zone.ZonePath("gateway-" + index + ".catofes."), Host4: "198.18.252.1", Host6: "fd00:7068:b5::1"}
	if index == "b" {
		manifest.Host4, manifest.Host6 = "198.18.252.3", "fd00:7068:b5::3"
	}
	var err error
	manifest.Address, err = netip.ParseAddr(os.Getenv("PHOTON_LINUX_IP"))
	if err != nil || !manifest.Address.Is4() {
		t.Fatal("invalid backend LAN address")
	}
	for key, target := range map[string]*uint16{"PHOTON_BACKEND_IKE": &manifest.IKE, "PHOTON_BACKEND_NATT": &manifest.NATT} {
		port, err := strconv.ParseUint(os.Getenv(key), 10, 16)
		if err != nil || port <= 1024 {
			t.Fatal("invalid backend published port")
		}
		*target = uint16(port)
	}
	ctx := t.Context()
	command := func(name string, args ...string) string {
		t.Helper()
		out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("backend %s: %v %s", name, err, out)
		}
		return string(out)
	}
	const localZone zone.ZonePath = "node-a.catofes."
	group := ipsec.LinkGroupSpec{ID: "main", TunnelAddressSpec: ipsec.TunnelAddressSpec{Mode: ipsec.TunnelAddressDerivedLinkLocal, Family: ipsec.FamilyIPv6}}
	linkID := ipsec.StableLinkID(localZone, manifest.Zone, "main", ipsec.DefaultPathKey)
	localLL, remoteLL, err := group.DeriveTunnelAddressesForLink(localZone, manifest.Zone, linkID, ipsec.DefaultPathKey, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	const iface = "phb4switch"
	ifID := uint32(524260)
	if index == "b" {
		ifID++
	}
	for _, args := range [][]string{
		{"link", "add", iface, "type", "xfrm", "if_id", fmt.Sprint(ifID)},
		{"link", "set", iface, "multicast", "on"}, {"link", "set", iface, "up"},
		{"-6", "addr", "flush", "dev", iface, "scope", "link"},
		{"-6", "addr", "add", remoteLL.String() + "/64", "dev", iface, "nodad"},
		{"addr", "add", manifest.Host4 + "/32", "dev", "lo"},
		{"-6", "addr", "add", manifest.Host6 + "/128", "dev", "lo", "nodad"},
	} {
		command("ip", args...)
	}
	const protocol = "photon_babel_switch"
	config := fmt.Sprintf(`log stderr all;
router id %s;
protocol device { scan time 1; }
protocol static local4 { ipv4; route %s/32 blackhole; }
protocol static local6 { ipv6; route %s/128 blackhole; }
protocol kernel kernel4 { ipv4 { import none; export where source = RTS_BABEL; }; }
protocol kernel kernel6 { ipv6 { import none; export where source = RTS_BABEL; }; }
protocol babel %s {
 randomize router id yes;
 ipv4 { import all; export all; };
 ipv6 { import all; export all; };
 interface "%s" { type wired; hello interval 1 s; update interval 4 s; rtt cost 0; };
}
`, manifest.Host4, manifest.Host4, manifest.Host6, protocol, iface)
	if err := os.WriteFile(filepath.Join(dir, "bird.conf"), []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	log, err := os.Create(filepath.Join(dir, "bird.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	process := exec.CommandContext(ctx, os.Getenv("BIRD_BIN"), "-f", "-c", filepath.Join(dir, "bird.conf"), "-s", filepath.Join(dir, "bird.ctl"))
	process.Stdout, process.Stderr = log, log
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	birdDone := make(chan struct{})
	var birdErr error
	go func() { birdErr = process.Wait(); close(birdDone) }()
	defer func() { _ = process.Process.Kill(); <-birdDone }()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		out, err := exec.CommandContext(ctx, os.Getenv("BIRDC_BIN"), "-s", filepath.Join(dir, "bird.ctl"), "show", "babel", "entries", protocol).CombinedOutput()
		if err == nil {
			manifest.RouterID, err = bird.LocalBabelIdentity(string(out), protocol, []netip.Prefix{netip.MustParsePrefix(manifest.Host4 + "/32")})
			if err == nil && manifest.RouterID != "" {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if decoded, err := hex.DecodeString(manifest.RouterID); err != nil || len(decoded) != 8 {
		t.Fatal("no actual BIRD router identity")
	}
	key, record, err := ipsec.GenerateTransportKeyRecord(ipsec.AlgorithmEd25519, time.Now().Add(-15*time.Second), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key.PrivateKey)
	manifest.Transport = *record
	b4SwitchWriteJSON(t, filepath.Join(dir, "manifest.json"), manifest)
	var clientPublic []byte
	for deadline := time.Now().Add(90 * time.Second); time.Now().Before(deadline); {
		clientPublic, err = os.ReadFile("/smoke/client-public.der")
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if _, err := x509.ParsePKIXPublicKey(clientPublic); err != nil {
		t.Fatal("missing coordinated Windows public key")
	}
	vici, err := ipsec.NewGoviciClient("/tmp/ike-auth.vici")
	if err != nil {
		t.Fatal(err)
	}
	defer vici.Close()
	driver := &ipsec.StrongSwanDriver{VICI: vici}
	if err := driver.LoadPrivateKey(ctx, "windows-b4-switch", key.PrivateKey, ipsec.AlgorithmEd25519); err != nil {
		t.Fatal(err)
	}
	if err := driver.LoadConnection(ctx, ipsec.TransportLinkSpec{TransportID: "windows-b4-switch", LocalZone: manifest.Zone, PeerZone: localZone, LocalAddress: "0.0.0.0", XFRMIfID: ifID, LocalTunnelAddr: remoteLL, PeerTunnelAddr: localLL, LocalPrivateKey: key.PrivateKey, LocalPrivateKeyAlgorithm: ipsec.AlgorithmEd25519, PeerPublicKey: clientPublic}); err != nil {
		t.Fatal(err)
	}
	var echoes [2]atomic.Uint64
	serviceErrors := make(chan error, 2)
	for n, host := range []string{manifest.Host4, manifest.Host6} {
		conn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr(host), 19096)))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		go func() {
			packet := make([]byte, 2048)
			for {
				size, peer, err := conn.ReadFromUDPAddrPort(packet)
				if err != nil {
					serviceErrors <- err
					return
				}
				if _, err = conn.WriteToUDPAddrPort(packet[:size], peer); err == nil {
					echoes[n].Add(1)
				}
			}
		}()
	}
	if err := os.WriteFile(filepath.Join(dir, "ready"), []byte("ready"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Logf("independent backend %s ready; transport fingerprint=%s BIRD ID=%s", manifest.Zone, manifest.Transport.Fingerprint, manifest.RouterID)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-birdDone:
			t.Fatalf("backend BIRD stopped: %v", birdErr)
		case err := <-serviceErrors:
			t.Fatalf("backend UDP service stopped: %v", err)
		case <-ticker.C:
			sas, err := driver.ListSAs(ctx)
			if err != nil {
				t.Fatalf("backend StrongSwan unavailable: %v", err)
			}
			b4SwitchWriteJSON(t, filepath.Join(dir, "traffic.json"), b4SwitchTraffic{time.Now(), echoes[0].Load(), echoes[1].Load(), sas})
		}
	}
}

// Pure preparation: run locally after docker cp has collected public manifests.
// This performs no host network mutation and never reads backend private keys.
func TestPrepareWindowsB4GatewaySwitch(t *testing.T) {
	dir := os.Getenv("PHOTON_B4_SWITCH_PREPARE")
	if dir == "" {
		t.Skip("requires two backend public manifests")
	}
	var manifests [2]b4GatewayManifest
	for n, index := range []string{"a", "b"} {
		data, err := os.ReadFile(filepath.Join(dir, index+"-manifest.json"))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(data, &manifests[n]); err != nil {
			t.Fatal(err)
		}
		if manifests[n].Zone != zone.ZonePath("gateway-"+index+".catofes.") {
			t.Fatal("wrong backend zone")
		}
	}
	if manifests[0].RouterID == manifests[1].RouterID || manifests[0].Transport.Fingerprint == manifests[1].Transport.Fingerprint {
		t.Fatal("backends must have independent identities")
	}
	network, _, identity := signedNetwork(t)
	defer clear(identity)
	root := identity.Public().(ed25519.PublicKey)
	network.Zones[zone.RootZone].Authority = photoncrypto.ConfiguredRootAuthority(root)
	if err := photoncrypto.SignDelegation(network.Zones[zone.RootZone].Delegations["catofes."], zone.RootZone, identity); err != nil {
		t.Fatal(err)
	}
	const localZone zone.ZonePath = "node-a.catofes."
	now := time.Now().Add(-15 * time.Second).Truncate(time.Second)
	put := func(path zone.ZonePath, key, kind string, value any) {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		record := &zone.Record{Zone: path, Key: key, Type: kind, Value: data, Version: 1, Timestamp: now.Unix()}
		if err := photoncrypto.SignRecord(record, identity); err != nil {
			t.Fatal(err)
		}
		network.Zones[path].Records[key] = record
	}
	for _, m := range manifests {
		authority := *network.Zones[localZone].Authority
		authority.Zone = m.Zone
		delegation := &zone.Delegation{ZoneName: m.Zone, Authority: authority}
		if err := photoncrypto.SignDelegation(delegation, "catofes.", identity); err != nil {
			t.Fatal(err)
		}
		network.Zones["catofes."].Delegations[m.Zone] = delegation
		network.Zones[m.Zone] = zone.NewZoneState(m.Zone, &authority)
		put(m.Zone, ipsec.RecordKeyTransportKey, ipsec.RecordTypeTransportKey, m.Transport)
		put(m.Zone, ipsec.RecordKeyProfile, ipsec.RecordTypeProfile, ipsec.ProfileRecord{Version: 1, Enabled: true, Provider: ipsec.ProviderStrongSwan, IKEIdentity: string(m.Zone), TransportKeyFingerprint: m.Transport.Fingerprint, Role: ipsec.RoleIn, AddressFamilies: []string{ipsec.FamilyIPv4}, PathModes: []string{ipsec.PathModeFamilyRedundant}})
		put(m.Zone, ipsec.RecordKeyAddresses, ipsec.RecordTypeAddresses, ipsec.AddressRecord{Version: 1, Addresses: []ipsec.AddressAdvertisement{{ID: "fixture", Source: ipsec.SourceManualAddress, Address: m.Address.String(), Family: ipsec.FamilyIPv4}}})
		put(m.Zone, ipsec.RecordKeyPorts, ipsec.RecordTypePorts, ipsec.PortRecord{Version: 1, Mode: ipsec.PortModeFixed, Current: &ipsec.PortSelection{Generation: 1, IKE: ipsec.PortBinding{Advertised: m.IKE}, NATT: ipsec.PortBinding{Advertised: m.NATT}}})
		put(m.Zone, ipsec.OverlayIntentRecordKey("main"), ipsec.RecordTypeOverlayIntent, ipsec.OverlayIntentRecord{Version: 1, OverlayID: "main", Provider: ipsec.ProviderStrongSwan, PathKeys: []string{ipsec.DefaultPathKey}, TunnelAddress: ipsec.TunnelAddressSpec{Mode: ipsec.TunnelAddressDerivedLinkLocal, Family: ipsec.FamilyIPv6}})
		put(m.Zone, routing.RecordKeyBabelIdentity, routing.RecordTypeBabelIdentity, routing.BabelIdentityRecord{Version: 1, RouterIDs: []string{m.RouterID}, ExpiresAt: now.Add(time.Hour).Unix()})
	}
	for _, prefix := range []string{"198.18.252.0/24", "fd00:7068:b5::/64"} {
		key, _ := routing.NormalizeIPAMPoolKey(prefix)
		put(zone.RootZone, key, routing.RecordTypeIPAMPool, routing.IPAMPoolRecord{Version: 1, Prefix: prefix, DelegatedTo: zone.RootZone, Active: true})
	}
	for path, prefixes := range map[zone.ZonePath][]string{localZone: {"198.18.252.2/32", "fd00:7068:b5::2/128"}, manifests[0].Zone: {manifests[0].Host4 + "/32", manifests[0].Host6 + "/128"}, manifests[1].Zone: {manifests[1].Host4 + "/32", manifests[1].Host6 + "/128"}} {
		for _, prefix := range prefixes {
			key, _ := routing.NormalizeIPAMAssignmentKey(prefix)
			put(zone.RootZone, key, routing.RecordTypeIPAMAssignment, routing.IPAMAssignmentRecord{Version: 1, Prefix: prefix, AssignedTo: path, Active: true})
			key, _ = routing.NormalizeRouteAnnouncementKey(prefix)
			put(path, key, routing.RecordTypeRouteAnnouncement, routing.RouteAnnouncementRecord{Version: 1, Prefix: prefix, Active: true})
		}
	}
	config := &Config{SchemaVersion: 1, ManagedZone: localZone, TrustedRootPublicKey: root, State: StateConfig{Path: filepath.Join(dir, "windows.db")}, GossipListen: "0.0.0.0:0", Wintun: WintunConfig{AdapterName: "PhotonB4Switch", MTU: 1280}, Overlay: OverlayConfig{ID: "main", SplitRoutes: []netip.Prefix{netip.MustParsePrefix("198.18.252.0/24"), netip.MustParsePrefix("fd00:7068:b5::/64")}}, Gateway: GatewayConfig{AllowedZones: []zone.ZonePath{manifests[0].Zone, manifests[1].Zone}}, Reconnect: ReconnectConfig{InitialBackoff: time.Second, MaxBackoff: 3 * time.Second}}
	disk, err := corestate.OpenBoltStore(config.State.Path, 0600, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	err = disk.CommitCommon(t.Context(), &corestate.CommitCandidate{Verified: &corestate.VerifiedState{ManagedZone: localZone, Network: network, TrustedRootPublicKey: root, IdentityPrivateKey: identity}, Gossip: &corestate.GossipCheckpoint{}}, corestate.ChangeSet{VerifiedRevision: 1, NetworkChanged: true})
	if closeErr := disk.Close(); err != nil || closeErr != nil {
		t.Fatal(err, closeErr)
	}
	state, err := OpenState(config.State.Path, localZone, root, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	plan := PlanGateway(t.Context(), config, state.Store().ReadView(), now)
	if plan.Selected == nil || plan.Selected.Zone != manifests[0].Zone {
		t.Fatalf("primary not selected: %s", plan.Rejected)
	}
	client, err := state.EnsureLocalTransport(t.Context(), config, now, plan, netip.MustParseAddrPort("0.0.0.0:16500"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(client.PrivateKey)
	if _, err := state.EnsureLocalBabelIdentity(t.Context(), config, now); err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(client.PrivateKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	b4SwitchWriteJSON(t, filepath.Join(dir, "config.json"), config)
	// Publish last: this releases both backend connection loaders.
	if err := os.WriteFile(filepath.Join(dir, "client-public.der.tmp"), public, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, "client-public.der.tmp"), filepath.Join(dir, "client-public.der")); err != nil {
		t.Fatal(err)
	}
	t.Log("one signed root/client DB prepared from two independent backend manifests")
}

func TestCheckWindowsB4GatewaySwitchEvidence(t *testing.T) {
	dir := os.Getenv("PHOTON_B4_SWITCH_EVIDENCE")
	if dir == "" {
		t.Skip("requires backend public traffic reports")
	}
	for _, index := range []string{"a", "b"} {
		data, err := os.ReadFile(filepath.Join(dir, index+"-traffic.json"))
		if err != nil {
			t.Fatal(err)
		}
		var report b4SwitchTraffic
		if err := json.Unmarshal(data, &report); err != nil {
			t.Fatal(err)
		}
		if report.ObservedAt.IsZero() || time.Since(report.ObservedAt) > 5*time.Second || report.Echo4 == 0 || report.Echo6 == 0 {
			t.Fatalf("backend %s lacks fresh live dual-stack evidence: %+v", index, report)
		}
		t.Logf("backend %s remained alive: echo4=%d echo6=%d SA count=%d at=%s", index, report.Echo4, report.Echo6, len(report.SAs), report.ObservedAt)
	}
}

func TestPrepareWindowsB4GatewaySwitchManifestPair(t *testing.T) {
	dir := t.TempDir()
	for n, index := range []string{"a", "b"} {
		key, record, err := ipsec.GenerateTransportKeyRecord(ipsec.AlgorithmEd25519, time.Now().Add(-30*time.Second), time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		clear(key.PrivateKey)
		m := b4GatewayManifest{Zone: zone.ZonePath("gateway-" + index + ".catofes."), Address: netip.MustParseAddr("192.0.2.1"), IKE: uint16(15000 + n), NATT: uint16(14500 + n), Host4: fmt.Sprintf("198.18.252.%d", 1+2*n), Host6: fmt.Sprintf("fd00:7068:b5::%d", 1+2*n), RouterID: fmt.Sprintf("%016x", n+1), Transport: *record}
		b4SwitchWriteJSON(t, filepath.Join(dir, index+"-manifest.json"), m)
	}
	t.Setenv("PHOTON_B4_SWITCH_PREPARE", dir)
	TestPrepareWindowsB4GatewaySwitch(t)
	data, err := os.ReadFile(filepath.Join(dir, "client-public.der"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x509.ParsePKIXPublicKey(data); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "windows.db")); err != nil {
		t.Fatal(err)
	}
}
