//go:build linux

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
	"testing"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
	"github.com/HiggsNet/photon/pkg/routing"
	"github.com/HiggsNet/photon/pkg/routing/bird"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

// The enclosing script owns this disposable container and its child processes.
// All keys and the database are per-run fixtures, never production identities.
func TestServeWindowsB4Gateway(t *testing.T) {
	dir := os.Getenv("PHOTON_WINDOWS_B4_FIXTURE")
	if dir == "" {
		t.Skip("run windows-b4-cross-host-smoke.sh")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("B4 gateway fixture requires a disposable container")
	}
	ctx := t.Context()
	command := func(name string, args ...string) string {
		t.Helper()
		output, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("fixture command %s failed: %v %s", name, err, output)
		}
		return string(output)
	}
	port := func(key string) uint16 {
		n, err := strconv.ParseUint(os.Getenv(key), 10, 16)
		if err != nil || n <= 1024 {
			t.Fatal("invalid isolated fixture port", key)
		}
		return uint16(n)
	}
	address, err := netip.ParseAddr(os.Getenv("PHOTON_WINDOWS_TUNNEL_GATEWAY"))
	if err != nil || !address.Is4() {
		t.Fatal("invalid isolated fixture host address")
	}
	ikePort, nattPort := port("PHOTON_WINDOWS_TUNNEL_IKE_PORT"), port("PHOTON_WINDOWS_TUNNEL_NATT_PORT")
	const localZone zone.ZonePath = "node-a.catofes."
	const gatewayZone zone.ZonePath = "gateway.catofes."
	const gateway4 = "198.18.253.1"
	const local4 = "198.18.253.2"
	const gateway6 = "fd00:7068:b4::1"
	const local6 = "fd00:7068:b4::2"
	const iface = "phb4cross"
	const protocol = "photon_babel_b4"
	tunnelAddress := ipsec.TunnelAddressSpec{Mode: ipsec.TunnelAddressDerivedLinkLocal, Family: ipsec.FamilyIPv6}
	group := ipsec.LinkGroupSpec{ID: "main", TunnelAddressSpec: tunnelAddress}
	linkID := ipsec.StableLinkID(localZone, gatewayZone, "main", ipsec.DefaultPathKey)
	localLL, gatewayLL, err := group.DeriveTunnelAddressesForLink(localZone, gatewayZone, linkID, ipsec.DefaultPathKey, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"link", "add", iface, "type", "xfrm", "if_id", "524250"},
		{"link", "set", iface, "up"},
		{"-6", "addr", "flush", "dev", iface, "scope", "link"},
		{"-6", "addr", "add", gatewayLL.String() + "/64", "dev", iface, "nodad"},
		{"addr", "add", gateway4 + "/32", "dev", "lo"},
		{"-6", "addr", "add", gateway6 + "/128", "dev", "lo", "nodad"},
	} {
		command("ip", args...)
	}
	birdConfig := fmt.Sprintf(`log stderr all;
router id 198.18.253.1;
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
`, gateway4, gateway6, protocol, iface)
	if err := os.WriteFile(filepath.Join(dir, "bird.conf"), []byte(birdConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	birdLog, err := os.Create(filepath.Join(dir, "bird.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer birdLog.Close()
	birdProcess := exec.CommandContext(ctx, os.Getenv("BIRD_BIN"), "-f", "-c", filepath.Join(dir, "bird.conf"), "-s", filepath.Join(dir, "bird.ctl"))
	birdProcess.Stdout, birdProcess.Stderr = birdLog, birdLog
	if err := birdProcess.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = birdProcess.Process.Kill(); _ = birdProcess.Wait() }()
	var fullID string
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		output, err := exec.CommandContext(ctx, os.Getenv("BIRDC_BIN"), "-s", filepath.Join(dir, "bird.ctl"), "show", "babel", "entries", protocol).CombinedOutput()
		if err == nil {
			fullID, err = bird.LocalBabelIdentity(string(output), protocol, []netip.Prefix{netip.MustParsePrefix(gateway4 + "/32"), netip.MustParsePrefix(gateway6 + "/128")})
			if err == nil && fullID != "" {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if raw, err := hex.DecodeString(fullID); err != nil || len(raw) != 8 {
		t.Fatal("no proven local full BIRD identity")
	}

	network, _, identity := signedNetwork(t)
	root := identity.Public().(ed25519.PublicKey)
	network.Zones[zone.RootZone].Authority = photoncrypto.ConfiguredRootAuthority(root)
	if err := photoncrypto.SignDelegation(network.Zones[zone.RootZone].Delegations["catofes."], zone.RootZone, identity); err != nil {
		t.Fatal(err)
	}
	authority := *network.Zones[localZone].Authority
	authority.Zone = gatewayZone
	delegation := &zone.Delegation{ZoneName: gatewayZone, Authority: authority}
	if err := photoncrypto.SignDelegation(delegation, "catofes.", identity); err != nil {
		t.Fatal(err)
	}
	network.Zones["catofes."].Delegations[gatewayZone] = delegation
	network.Zones[gatewayZone] = zone.NewZoneState(gatewayZone, &authority)
	now := time.Now().Truncate(time.Second)
	put := func(path zone.ZonePath, key, kind string, value any) {
		t.Helper()
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		record := &zone.Record{Zone: path, Key: key, Type: kind, Value: encoded, Version: 1, Timestamp: now.Unix()}
		if err := photoncrypto.SignRecord(record, identity); err != nil {
			t.Fatal(err)
		}
		network.Zones[path].Records[key] = record
	}
	serverKey, serverRecord, err := ipsec.GenerateTransportKeyRecord(ipsec.AlgorithmEd25519, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(serverKey.PrivateKey)
	put(gatewayZone, ipsec.RecordKeyTransportKey, ipsec.RecordTypeTransportKey, serverRecord)
	put(gatewayZone, ipsec.RecordKeyProfile, ipsec.RecordTypeProfile, ipsec.ProfileRecord{Version: 1, Enabled: true, Provider: ipsec.ProviderStrongSwan, IKEIdentity: string(gatewayZone), TransportKeyFingerprint: serverRecord.Fingerprint, Role: ipsec.RoleIn, AddressFamilies: []string{ipsec.FamilyIPv4}, PathModes: []string{ipsec.PathModeFamilyRedundant}})
	put(gatewayZone, ipsec.RecordKeyAddresses, ipsec.RecordTypeAddresses, ipsec.AddressRecord{Version: 1, Addresses: []ipsec.AddressAdvertisement{{ID: "fixture", Source: ipsec.SourceManualAddress, Address: address.String(), Family: ipsec.FamilyIPv4}}})
	put(gatewayZone, ipsec.RecordKeyPorts, ipsec.RecordTypePorts, ipsec.PortRecord{Version: 1, Mode: ipsec.PortModeFixed, Current: &ipsec.PortSelection{Generation: 1, IKE: ipsec.PortBinding{Advertised: ikePort}, NATT: ipsec.PortBinding{Advertised: nattPort}}})
	put(gatewayZone, ipsec.OverlayIntentRecordKey("main"), ipsec.RecordTypeOverlayIntent, ipsec.OverlayIntentRecord{Version: 1, OverlayID: "main", Provider: ipsec.ProviderStrongSwan, PathKeys: []string{ipsec.DefaultPathKey}, TunnelAddress: tunnelAddress})
	put(gatewayZone, routing.RecordKeyBabelIdentity, routing.RecordTypeBabelIdentity, routing.BabelIdentityRecord{Version: 1, RouterIDs: []string{fullID}, ExpiresAt: now.Add(time.Hour).Unix()})
	for _, prefix := range []string{"198.18.253.0/24", "fd00:7068:b4::/64"} {
		key, _ := routing.NormalizeIPAMPoolKey(prefix)
		put(zone.RootZone, key, routing.RecordTypeIPAMPool, routing.IPAMPoolRecord{Version: 1, Prefix: prefix, DelegatedTo: zone.RootZone, Active: true})
	}
	for path, prefixes := range map[zone.ZonePath][]string{localZone: {local4 + "/32", local6 + "/128"}, gatewayZone: {gateway4 + "/32", gateway6 + "/128"}} {
		for _, prefix := range prefixes {
			key, _ := routing.NormalizeIPAMAssignmentKey(prefix)
			put(zone.RootZone, key, routing.RecordTypeIPAMAssignment, routing.IPAMAssignmentRecord{Version: 1, Prefix: prefix, AssignedTo: path, Active: true})
			key, _ = routing.NormalizeRouteAnnouncementKey(prefix)
			put(path, key, routing.RecordTypeRouteAnnouncement, routing.RouteAnnouncementRecord{Version: 1, Prefix: prefix, Active: true})
		}
	}
	config := &Config{SchemaVersion: ConfigSchemaVersion, ManagedZone: localZone, TrustedRootPublicKey: root, State: StateConfig{Path: filepath.Join(dir, "windows.db")}, GossipListen: "0.0.0.0:0", Wintun: WintunConfig{AdapterName: "PhotonB4Cross", MTU: 1280}, Overlay: OverlayConfig{ID: "main", SplitRoutes: []netip.Prefix{netip.MustParsePrefix("198.18.253.0/24"), netip.MustParsePrefix("fd00:7068:b4::/64")}}, Gateway: GatewayConfig{AllowedZones: []zone.ZonePath{gatewayZone}}, Reconnect: ReconnectConfig{InitialBackoff: time.Second, MaxBackoff: 3 * time.Second}}
	disk, err := corestate.OpenBoltStore(config.State.Path, 0o600, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	err = disk.CommitCommon(ctx, &corestate.CommitCandidate{Verified: &corestate.VerifiedState{ManagedZone: localZone, Network: network, TrustedRootPublicKey: root, IdentityPrivateKey: identity}, Gossip: &corestate.GossipCheckpoint{}}, corestate.ChangeSet{VerifiedRevision: 1, NetworkChanged: true})
	if closeErr := disk.Close(); err != nil || closeErr != nil {
		t.Fatal("fixture common state persistence failed", err, closeErr)
	}
	state, err := OpenState(config.State.Path, localZone, root, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	plan := PlanGateway(ctx, config, state.Store().ReadView(), now)
	client, err := state.EnsureLocalTransport(ctx, config, now, plan, netip.MustParseAddrPort("0.0.0.0:16500"))
	if err != nil {
		state.Close()
		t.Fatal(err)
	}
	defer clear(client.PrivateKey)
	if _, err := state.EnsureLocalBabelIdentity(ctx, config, now); err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	serverDER := serverKey.PrivateKey // GenerateTransportKeyRecord returns PKCS#8.
	clientDER, err := x509.MarshalPKIXPublicKey(client.PrivateKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	vici, err := ipsec.NewGoviciClient("/tmp/ike-auth.vici")
	if err != nil {
		t.Fatal(err)
	}
	defer vici.Close()
	driver := &ipsec.StrongSwanDriver{VICI: vici}
	if err := driver.LoadPrivateKey(ctx, "windows-b4", serverDER, ipsec.AlgorithmEd25519); err != nil {
		t.Fatal(err)
	}
	if err := driver.LoadConnection(ctx, ipsec.TransportLinkSpec{TransportID: "windows-b4", LocalZone: gatewayZone, PeerZone: localZone, LocalAddress: "0.0.0.0", XFRMIfID: 524250, LocalTunnelAddr: gatewayLL, PeerTunnelAddr: localLL, LocalPrivateKey: serverDER, LocalPrivateKeyAlgorithm: ipsec.AlgorithmEd25519, PeerPublicKey: clientDER}); err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{gateway4, gateway6} {
		conn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr(host), 19096)))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		go func() {
			packet := make([]byte, 2048)
			for {
				n, peer, err := conn.ReadFromUDPAddrPort(packet)
				if err != nil {
					return
				}
				_, _ = conn.WriteToUDPAddrPort(packet[:n], peer)
			}
		}()
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ready"), []byte("ready"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Log("isolated BIRD full identity, signed common DB, production StrongSwan and dual-stack UDP services ready")
	<-ctx.Done()
}
