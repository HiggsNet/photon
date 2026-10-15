//go:build linux

package photonwindows

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/photonlinux"
	photonstate "github.com/HiggsNet/photon/internal/state"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
	"github.com/HiggsNet/photon/pkg/routing"
	"github.com/HiggsNet/photon/pkg/routing/bird"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

// Preparation only: no driver, routing process or live state writer runs here.
func TestPrepareWindowsFullDaemonGateway(t *testing.T) {
	dir := os.Getenv("PHOTON_WINDOWS_FULL_DAEMON_FIXTURE")
	if dir == "" {
		t.Skip("run windows-full-daemon-smoke.sh")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("requires disposable container")
	}
	ctx := t.Context()
	port := func(key string) uint16 {
		n, err := strconv.ParseUint(os.Getenv(key), 10, 16)
		if err != nil || n <= 1024 {
			t.Fatal("invalid fixture port", key)
		}
		return uint16(n)
	}
	address, err := netip.ParseAddr(os.Getenv("PHOTON_WINDOWS_TUNNEL_GATEWAY"))
	if err != nil || !address.Is4() {
		t.Fatal("invalid gateway")
	}
	ikePort, nattPort := port("PHOTON_WINDOWS_TUNNEL_IKE_PORT"), port("PHOTON_WINDOWS_TUNNEL_NATT_PORT")
	gossipContact := netip.AddrPortFrom(address, port("PHOTON_WINDOWS_GOSSIP_PORT")).String()
	const localZone zone.ZonePath = "node-a.catofes."
	const gatewayZone zone.ZonePath = "gateway.catofes."
	const local4, gateway4 = "198.18.253.2", "198.18.253.1"
	const local6, gateway6 = "fd00:7068:b4::2", "fd00:7068:b4::1"
	tunnelAddress := ipsec.TunnelAddressSpec{Mode: ipsec.TunnelAddressDerivedLinkLocal, Family: ipsec.FamilyIPv6}
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
	// VM clocks may differ by a few seconds. Issue the disposable fixture just
	// before now so strict production NotBefore checks do not delay startup.
	now := time.Now().Add(-15 * time.Second).Truncate(time.Second)
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
	put(gatewayZone, ipsec.RecordKeyPorts, ipsec.RecordTypePorts, ipsec.PortRecord{Version: 1, Mode: ipsec.PortModeFixed, Current: &ipsec.PortSelection{Generation: 1, IKE: ipsec.PortBinding{Local: 500, Advertised: ikePort}, NATT: ipsec.PortBinding{Local: 4500, Advertised: nattPort}}})
	put(gatewayZone, ipsec.OverlayIntentRecordKey("main"), ipsec.RecordTypeOverlayIntent, ipsec.OverlayIntentRecord{Version: 1, OverlayID: "main", Provider: ipsec.ProviderStrongSwan, PathKeys: []string{"family:ipv4"}, TunnelAddress: tunnelAddress})
	for _, prefix := range []string{"198.18.253.0/24", "fd00:7068:b4::/64"} {
		key, _ := routing.NormalizeIPAMPoolKey(prefix)
		put(zone.RootZone, key, routing.RecordTypeIPAMPool, routing.IPAMPoolRecord{Version: 1, Prefix: prefix, DelegatedTo: zone.RootZone, Active: true})
	}
	for path, prefixes := range map[zone.ZonePath][]string{localZone: {local4 + "/32", local6 + "/128"}, gatewayZone: {gateway4 + "/32", gateway6 + "/128"}} {
		for _, prefix := range prefixes {
			key, _ := routing.NormalizeIPAMAssignmentKey(prefix)
			put(zone.RootZone, key, routing.RecordTypeIPAMAssignment, routing.IPAMAssignmentRecord{Version: 1, Prefix: prefix, AssignedTo: path, Active: true})
			if path == localZone {
				continue
			}
			key, _ = routing.NormalizeRouteAnnouncementKey(prefix)
			put(path, key, routing.RecordTypeRouteAnnouncement, routing.RouteAnnouncementRecord{Version: 1, Prefix: prefix, Active: true})
		}
	}
	config := &Config{SchemaVersion: ConfigSchemaVersion, ManagedZone: localZone, TrustedRootPublicKey: root, State: StateConfig{Path: filepath.Join(dir, "windows.db")}, GossipListen: "0.0.0.0:0", Wintun: WintunConfig{AdapterName: "PhotonB4Cross", MTU: 1280}, Overlay: OverlayConfig{ID: "main", SplitRoutes: []netip.Prefix{netip.MustParsePrefix("198.18.253.0/24"), netip.MustParsePrefix("fd00:7068:b4::/64")}}, Gateway: GatewayConfig{AllowedZones: []zone.ZonePath{gatewayZone}}, Reconnect: ReconnectConfig{InitialBackoff: time.Second, MaxBackoff: 3 * time.Second}}
	var candidate *corestate.CommitCandidate
	var revision corestate.VerifiedRevision
	if os.Getenv("PHOTON_WINDOWS_AUTOJOIN_SMOKE") == "1" {
		// No Windows database or private key is prepared for this mode. The
		// production Windows initializer must generate its own stable identity.
		delete(network.Zones[localZone.Parent()].Delegations, localZone)
		delete(network.Zones, localZone)
		candidate = &corestate.CommitCandidate{Verified: &corestate.VerifiedState{ManagedZone: gatewayZone, Network: network, TrustedRootPublicKey: root, IdentityPrivateKey: identity}, Gossip: &corestate.GossipCheckpoint{}}
		revision = 1
	} else {
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

		disk, err = corestate.OpenBoltStore(config.State.Path, 0600, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		var found bool
		candidate, revision, _, found, err = disk.LoadCommon()
		closeErr := disk.Close()
		if err != nil || closeErr != nil || !found {
			t.Fatal("read prepared Windows snapshot", err, closeErr)
		}
	}
	config.Gateway.BootstrapHints = []BootstrapHint{{Peer: gatewayZone, Address: gossipContact}}
	write := func(name string, value any) {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("config.json", config)
	initialRevision := revision
	if os.Getenv("PHOTON_WINDOWS_AUTOJOIN_SMOKE") == "1" {
		initialRevision = 0
	}
	write("gossip-evidence.json", map[string]any{"gateway": gatewayZone, "missing_record": routing.RecordKeyBabelIdentity, "initial_revision": initialRevision})
	candidate.Verified.ManagedZone = gatewayZone
	candidate.Gossip = &corestate.GossipCheckpoint{}
	linuxDisk, err := corestate.OpenBoltStore(filepath.Join(dir, "linux.db"), 0600, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer linuxDisk.Close()
	if err = linuxDisk.CommitCommon(ctx, candidate, corestate.ChangeSet{VerifiedRevision: revision, NetworkChanged: true}); err != nil {
		t.Fatal(err)
	}
	key := &photonstate.IPsecTransportKeyState{Kind: serverKey.Kind, Algorithm: serverKey.Algorithm, PublicKey: serverKey.PublicKey, PrivateKey: serverKey.PrivateKey, Fingerprint: serverRecord.Fingerprint, NotBefore: serverRecord.NotBefore, NotAfter: serverRecord.NotAfter, UpdatedAt: serverRecord.UpdatedAt}
	if err = photonlinux.CommitLinuxState(linuxDisk, revision, &photonlinux.LinuxState{IPsecTransportKey: key}); err != nil {
		t.Fatal(err)
	}
	yaml := fmt.Sprintf(`data_dir: %s
state_path: %s/linux.db
trusted_root_public_key: %s
gossip:
  peer_id: gateway.catofes.
  listen_addr: "0.0.0.0:5201"
  advertise_addrs: ["%s"]
  endpoint_discovery: advertise_only
  filter_private_ipv4: false
netns:
  default:
    kind: host
ipsec:
  role: in
  driver: strongswan
  vici_socket: /tmp/ike-auth.vici
  port_mode: fixed
  announce_addrs: ["%s"]
  announce_gossip_endpoints: false
overlays:
  - id: main
    provider: strongswan
    netns: default
    default_path_mode: family-redundant
    tunnel_address: {mode: derived-link-local, family: ipv6}
    connect: ["strongswan://node-a.catofes.?role=out&family=ipv4&mode=family-redundant"]
    reconcile: {interval: 1s}
ipam:
  announce: [non-shared]
routing:
  instances:
    - id: main
      netns: default
      provider: bird
      mode: managed
      shutdown_policy: stop
      table: main
      control_socket: %s/bird.ctl
      config_file: %s/bird.conf
      pid_file: %s/bird.pid
`, dir, dir, base64.StdEncoding.EncodeToString(root), gossipContact, address, dir, dir, dir)
	if err = os.WriteFile(filepath.Join(dir, "gateway.yaml"), []byte(yaml), 0600); err != nil {
		t.Fatal(err)
	}
}

// Business endpoint only. Production daemon owns all control-plane work.
func TestServeFullDaemonEcho(t *testing.T) {
	dir := os.Getenv("PHOTON_WINDOWS_FULL_DAEMON_FIXTURE")
	if dir == "" {
		t.Skip("run windows-full-daemon-smoke.sh")
	}
	for _, host := range []string{"198.18.253.1", "fd00:7068:b4::1"} {
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
	if err := os.WriteFile(filepath.Join(dir, "ready"), []byte("echo ready"), 0600); err != nil {
		t.Fatal(err)
	}
	<-t.Context().Done()
}

// Read only production CLI/BIRD/kernel observations. No live Bolt opens.
func TestObserveFullDaemonGateway(t *testing.T) {
	dir := os.Getenv("PHOTON_WINDOWS_FULL_DAEMON_FIXTURE")
	if dir == "" {
		t.Skip("run windows-full-daemon-smoke.sh")
	}
	t.Setenv("PHOTON_CONTROL_SOCKET", filepath.Join(dir, "photon.sock"))
	run := func(name string, args ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		defer cancel()
		return exec.CommandContext(ctx, name, args...).CombinedOutput()
	}
	save := func(name string, b []byte) {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(90 * time.Second)
	var last string
	for time.Now().Before(deadline) {
		if _, err := os.Stat(filepath.Join(dir, "bird.conf")); err == nil {
			parsed, err := run(os.Getenv("BIRD_BIN"), "-p", "-c", filepath.Join(dir, "bird.conf"))
			if err != nil {
				save("bird-parse.txt", parsed)
				t.Fatalf("production BIRD configuration rejected: %v %s", err, parsed)
			}
		}
		status, err := run("/smoke/photon", "status")
		if err != nil || !strings.Contains(string(status), "daemon: online") {
			last = string(status)
			time.Sleep(time.Second)
			continue
		}
		raw, err := run("/smoke/photon", "debug", "record", "gateway.catofes.", routing.RecordKeyBabelIdentity)
		var record struct {
			Value string `json:"value"`
		}
		var binding routing.BabelIdentityRecord
		if err != nil || json.Unmarshal(raw, &record) != nil || json.Unmarshal([]byte(record.Value), &binding) != nil || len(binding.RouterIDs) != 1 || binding.ExpiresAt <= time.Now().Unix() {
			last = string(raw)
			time.Sleep(time.Second)
			continue
		}
		entries, err := run(os.Getenv("BIRDC_BIN"), "-s", filepath.Join(dir, "bird.ctl"), "show", "babel", "entries")
		if err != nil {
			last = string(entries)
			time.Sleep(time.Second)
			continue
		}
		protocol := ""
		for line := range strings.SplitSeq(string(entries), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 1 && strings.HasPrefix(fields[0], "photon_babel_") {
				protocol = strings.TrimSuffix(fields[0], ":")
			}
		}
		id, err := bird.LocalBabelIdentity(string(entries), protocol, []netip.Prefix{netip.MustParsePrefix("198.18.253.1/32")})
		if err != nil || id == "" || id != binding.RouterIDs[0] {
			last = fmt.Sprintf("BIRD identity mismatch: %s %v %s", id, err, entries)
			time.Sleep(time.Second)
			continue
		}
		portsRaw, err := run("/smoke/photon", "debug", "record", "gateway.catofes.", ipsec.RecordKeyPorts)
		var ports ipsec.PortRecord
		if err != nil || json.Unmarshal(portsRaw, &record) != nil || json.Unmarshal([]byte(record.Value), &ports) != nil || ports.Current == nil {
			last = string(portsRaw)
			time.Sleep(time.Second)
			continue
		}
		ike, _ := strconv.Atoi(os.Getenv("PHOTON_WINDOWS_TUNNEL_IKE_PORT"))
		natt, _ := strconv.Atoi(os.Getenv("PHOTON_WINDOWS_TUNNEL_NATT_PORT"))
		if ports.Current.IKE.Local != 500 || ports.Current.NATT.Local != 4500 || int(ports.Current.IKE.Advertised) != ike || int(ports.Current.NATT.Advertised) != natt {
			t.Fatalf("production daemon changed published mapped ports: %+v", ports)
		}
		save("linux-status.txt", status)
		save("linux-identity.json", raw)
		save("linux-ports.json", portsRaw)
		save("bird-entries.txt", entries)
		save("control-ready", []byte(id))
		break
	}
	if _, err := os.Stat(filepath.Join(dir, "control-ready")); err != nil {
		t.Fatalf("production control/identity timeout: %s", last)
	}
	// Keep polling during Windows service lifetime, before its final Stop removes
	// routes. Both exact host routes must be dynamically installed on an XFRM link.
	deadline = time.Now().Add(180 * time.Second)
	if os.Getenv("PHOTON_WINDOWS_AUTOJOIN_SMOKE") == "1" {
		deadline = time.Now().Add(420 * time.Second)
	}
	for time.Now().Before(deadline) {
		v4, e4 := run("ip", "-4", "route", "show", "exact", "198.18.253.2/32")
		v6, e6 := run("ip", "-6", "route", "show", "exact", "fd00:7068:b4::2/128")
		links, el := run("ip", "-d", "link", "show", "type", "xfrm")
		routes, eb := run(os.Getenv("BIRDC_BIN"), "-s", filepath.Join(dir, "bird.ctl"), "show", "route", "table", "all", "all")
		valid := func(raw []byte) bool {
			f := strings.Fields(string(raw))
			for i := 0; i+1 < len(f); i++ {
				if f[i] != "dev" || !strings.Contains(string(raw), "proto bird") {
					continue
				}
				for line := range strings.SplitSeq(string(links), "\n") {
					fields := strings.Fields(line)
					if len(fields) < 2 || !strings.HasSuffix(fields[0], ":") {
						continue
					}
					name, _, _ := strings.Cut(strings.TrimSuffix(fields[1], ":"), "@")
					if name == f[i+1] {
						return true
					}
				}
			}
			return false
		}
		if e4 == nil && e6 == nil && el == nil && eb == nil && valid(v4) && valid(v6) && strings.Contains(string(routes), "198.18.253.2") && strings.Contains(string(routes), "fd00:7068:b4::2") {
			save("linux-routes.txt", append(v4, v6...))
			save("linux-xfrm.txt", links)
			save("bird-routes.txt", routes)
			save("return-routes-ready", []byte("BIRD installed both Windows host routes on XFRM"))
			return
		}
		last = fmt.Sprintf("v4=%s v6=%s links=%s BIRD=%s", v4, v6, links, routes)
		time.Sleep(time.Second)
	}
	t.Fatalf("dynamic dual-stack return routes timeout: %s", last)
}
