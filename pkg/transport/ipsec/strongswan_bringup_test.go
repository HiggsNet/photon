package ipsec

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestStrongSwanDriverIKEBringupSmoke brings up a real IKEv2/IPsec SA between
// two charon instances running in separate network namespaces, creates XFRM
// interfaces, assigns tunnel addresses, and verifies bidirectional ping.
func TestStrongSwanDriverIKEBringupSmoke(t *testing.T) {
	runStrongSwanBringup(t, strongSwanInteropCase{algorithm: AlgorithmECDSAP256})
}

func runStrongSwanBringup(t *testing.T, variant strongSwanInteropCase) {
	if os.Getenv("PHOTON_IPSEC_XFRM_SMOKE") != "1" {
		t.Skip("set PHOTON_IPSEC_XFRM_SMOKE=1 to run the root/system StrongSwan smoke")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	suffix := time.Now().UTC().Format("20060102150405")
	nsA := "photon-ike-a-" + suffix
	nsB := "photon-ike-b-" + suffix
	viciA := "/tmp/charon-" + nsA + ".vici"
	viciB := "/tmp/charon-" + nsB + ".vici"

	t.Cleanup(func() {
		_ = exec.Command("ip", "netns", "delete", nsA).Run()
		_ = exec.Command("ip", "netns", "delete", nsB).Run()
		_ = os.Remove(viciA)
		_ = os.Remove(viciB)
	})

	// Create network namespaces and a veth pair connecting them.
	runIP(t, ctx, "netns", "add", nsA)
	runIP(t, ctx, "netns", "add", nsB)
	runIP(t, ctx, "link", "add", "phvetha", "type", "veth", "peer", "name", "phvethb")
	runIP(t, ctx, "link", "set", "phvetha", "netns", nsA)
	runIP(t, ctx, "link", "set", "phvethb", "netns", nsB)
	for _, args := range [][]string{
		{"netns", "exec", nsA, "ip", "link", "set", "lo", "up"},
		{"netns", "exec", nsB, "ip", "link", "set", "lo", "up"},
		{"netns", "exec", nsA, "ip", "addr", "add", "192.0.2.1/30", "dev", "phvetha"},
		{"netns", "exec", nsB, "ip", "addr", "add", "192.0.2.2/30", "dev", "phvethb"},
		{"netns", "exec", nsA, "ip", "link", "set", "phvetha", "up"},
		{"netns", "exec", nsB, "ip", "link", "set", "phvethb", "up"},
	} {
		runIP(t, ctx, args...)
	}

	// Start charon in each namespace with a dedicated VICI socket and a
	// private piddir bind-mounted over /run so multiple instances do not
	// conflict on /run/charon.pid.
	confA, err := writeStrongSwanConf(viciA)
	if err != nil {
		t.Fatalf("write strongswan.conf A: %v", err)
	}
	confB, err := writeStrongSwanConf(viciB)
	if err != nil {
		t.Fatalf("write strongswan.conf B: %v", err)
	}
	piddirA, err := os.MkdirTemp("", "photon-piddir-a-*")
	if err != nil {
		t.Fatalf("create piddir A: %v", err)
	}
	piddirB, err := os.MkdirTemp("", "photon-piddir-b-*")
	if err != nil {
		t.Fatalf("create piddir B: %v", err)
	}

	logA, err := os.CreateTemp("", "photon-charon-a-*.log")
	if err != nil {
		t.Fatalf("create log A: %v", err)
	}
	logB, err := os.CreateTemp("", "photon-charon-b-*.log")
	if err != nil {
		t.Fatalf("create log B: %v", err)
	}

	charonA := startCharonInNetNS(ctx, t, nsA, piddirA, confA, logA)
	charonB := startCharonInNetNS(ctx, t, nsB, piddirB, confB, logB)
	defer func() {
		_ = charonA.Process.Kill()
		_ = charonB.Process.Kill()
		_ = charonA.Wait()
		_ = charonB.Wait()
		_ = os.Remove(confA)
		_ = os.Remove(confB)
		_ = os.RemoveAll(piddirA)
		_ = os.RemoveAll(piddirB)
		_ = logA.Close()
		_ = logB.Close()
		_ = os.Remove(logA.Name())
		_ = os.Remove(logB.Name())
	}()
	dumpLogsOnFail := func() {
		_ = logA.Sync()
		_ = logB.Sync()
		t.Logf("--- charon A log ---")
		if data, err := os.ReadFile(logA.Name()); err == nil {
			t.Logf("%s", string(data))
		}
		t.Logf("--- charon B log ---")
		if data, err := os.ReadFile(logB.Name()); err == nil {
			t.Logf("%s", string(data))
		}
		dumpStrongSwanSmokeDiagnostics(t, ctx, nsA, viciA, "A")
		dumpStrongSwanSmokeDiagnostics(t, ctx, nsB, viciB, "B")
	}
	defer func() {
		if t.Failed() {
			dumpLogsOnFail()
		}
	}()

	clientA, err := waitForVICI(ctx, viciA)
	if err != nil {
		t.Fatalf("connect to charon A VICI: %v", err)
	}
	defer clientA.Close()
	clientB, err := waitForVICI(ctx, viciB)
	if err != nil {
		t.Fatalf("connect to charon B VICI: %v", err)
	}
	defer clientB.Close()

	// Generate transport keys for both peers.
	keyA, err := generateTransportPrivateKey(variant.algorithm)
	if err != nil {
		t.Fatalf("generate key A: %v", err)
	}
	keyB, err := generateTransportPrivateKey(variant.algorithm)
	if err != nil {
		t.Fatalf("generate key B: %v", err)
	}

	const ifIDA = uint32(424244)
	const ifIDB = uint32(424344)
	ifaceA := "phxikea0"
	ifaceB := "phxikeb0"
	transportAtoB := "ipsec-ike-a-b"
	transportBtoA := "ipsec-ike-b-a"

	group := LinkGroupSpec{
		ID:                "main",
		Provider:          ProviderStrongSwan,
		TunnelAddressSpec: TunnelAddressSpec{Mode: TunnelAddressDerivedPool, Family: FamilyIPv6, Pool: netip.MustParsePrefix("fd00:4242::/64")},
	}
	if variant.ipv4 {
		group.TunnelAddressSpec.Family = FamilyIPv4
		group.TunnelAddressSpec.Pool = netip.MustParsePrefix("10.242.0.0/24")
	}
	addrA, addrB, err := group.DeriveTunnelAddresses("node-a.", "node-b.", 0)
	if err != nil {
		t.Fatalf("derive tunnel addresses: %v", err)
	}

	specA := TransportLinkSpec{
		LocalZone:                "node-a.",
		PeerZone:                 "node-b.",
		OverlayID:                "main",
		Provider:                 ProviderStrongSwan,
		TransportID:              transportAtoB,
		InitiatorRole:            InitiatorRolePrimary,
		PathMode:                 PathModeFamilyRedundant,
		IKEIdentity:              "node-a.",
		LocalAddress:             "192.0.2.1",
		ContactPoints:            []ContactPoint{{Address: "192.0.2.2", IKEPort: DefaultIKEPort, NATTPort: DefaultNATTPort}},
		XFRMIfID:                 ifIDA,
		InterfaceName:            ifaceA,
		LocalTunnelAddr:          addrA,
		PeerTunnelAddr:           addrB,
		NetNS:                    nsA,
		LocalPrivateKey:          keyA.PrivateKey,
		LocalPrivateKeyAlgorithm: variant.algorithm,
		PeerPublicKey:            keyB.PublicKey,
	}
	specB := TransportLinkSpec{
		LocalZone:                "node-b.",
		PeerZone:                 "node-a.",
		OverlayID:                "main",
		Provider:                 ProviderStrongSwan,
		TransportID:              transportBtoA,
		InitiatorRole:            InitiatorRolePrimary,
		PathMode:                 PathModeFamilyRedundant,
		IKEIdentity:              "node-b.",
		LocalAddress:             "192.0.2.2",
		ContactPoints:            []ContactPoint{{Address: "192.0.2.1", IKEPort: DefaultIKEPort, NATTPort: DefaultNATTPort}},
		XFRMIfID:                 ifIDB,
		InterfaceName:            ifaceB,
		LocalTunnelAddr:          addrB,
		PeerTunnelAddr:           addrA,
		NetNS:                    nsB,
		LocalPrivateKey:          keyB.PrivateKey,
		LocalPrivateKeyAlgorithm: variant.algorithm,
		PeerPublicKey:            keyA.PublicKey,
	}
	specB.ContactPoints = nil
	specB.InitiatorRole = ""

	keyDirA := t.TempDir()
	keyDirB := t.TempDir()
	ipsecA := &StrongSwanDriver{VICI: clientA, KeyDir: keyDirA}
	ipsecB := &StrongSwanDriver{VICI: clientB, KeyDir: keyDirB}
	xfrmA := NewSystemXFRMDriver(NetNSSpec{Kind: NetNSName, Name: nsA, Create: false})
	xfrmB := NewSystemXFRMDriver(NetNSSpec{Kind: NetNSName, Name: nsB, Create: false})
	xfrmA.StateNetNS = NetNSSpec{Kind: NetNSName, Name: nsA, Create: false}
	xfrmB.StateNetNS = NetNSSpec{Kind: NetNSName, Name: nsB, Create: false}

	if _, err := ApplyTransportLink(ctx, ipsecA, xfrmA, specA, NetNSSpec{Kind: NetNSName, Name: nsA}); err != nil {
		t.Fatalf("apply transport link A: %v", err)
	}
	if _, err := ApplyTransportLink(ctx, ipsecB, xfrmB, specB, NetNSSpec{Kind: NetNSName, Name: nsB}); err != nil {
		t.Fatalf("apply transport link B: %v", err)
	}

	if variant.candidate {
		loadInteropCandidate(t, ctx, ipsecA, specA)
	}

	if err := InitiateTransportChild(ctx, ipsecA, specA, nil); err != nil {
		t.Fatalf("initiate child A: %v", err)
	}

	// Wait until both sides report an established SA. The loaded children use
	// trap policies; Photon triggers establishment explicitly through VICI.
	if err := waitForSA(ctx, clientA, transportAtoB); err != nil {
		t.Fatalf("wait for SA on A: %v", err)
	}
	if err := waitForSA(ctx, clientB, transportBtoA); err != nil {
		t.Fatalf("wait for SA on B: %v", err)
	}

	prefix, family := "/128", "-6"
	if variant.ipv4 {
		prefix, family = "/32", "-4"
	}
	runIP(t, ctx, "netns", "exec", nsA, "ip", "route", "replace", addrB.String()+prefix, "dev", ifaceA)
	runIP(t, ctx, "netns", "exec", nsB, "ip", "route", "replace", addrA.String()+prefix, "dev", ifaceB)
	ping := func() {
		t.Helper()
		for _, target := range []struct{ ns, addr string }{{nsA, addrB.String()}, {nsB, addrA.String()}} {
			if out, err := execCommand(ctx, "ip", "netns", "exec", target.ns, "ping", family, "-c", "1", "-W", "3", target.addr); err != nil {
				t.Fatalf("tunnel ping from %s failed: %v\n%s", target.ns, err, out)
			}
		}
	}
	ping()
	if variant.rekey {
		verifyInteropRekeys(t, ctx, clientA, clientB, specA, specB, variant.candidate, ping)
	}
	t.Logf("IKE bring-up succeeded; bidirectional tunnel ping passed")
}

// TestStrongSwanUnloadConnectionKeepsEstablishedSASmoke verifies the rotation
// assumption that unloading an old responder config does not terminate the
// already established IKE/CHILD SA. It then loads a staged config with a new
// if_id and logs whether StrongSwan establishes the staged SA while the old SA
// is still alive.
func TestStrongSwanUnloadConnectionKeepsEstablishedSASmoke(t *testing.T) {
	if os.Getenv("PHOTON_IPSEC_XFRM_SMOKE") != "1" {
		t.Skip("set PHOTON_IPSEC_XFRM_SMOKE=1 to run the root/system StrongSwan smoke")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
	defer cancel()

	suffix := time.Now().UTC().Format("20060102150405")
	nsA := "photon-unload-a-" + suffix
	nsB := "photon-unload-b-" + suffix
	viciA := "/tmp/charon-" + nsA + ".vici"
	viciB := "/tmp/charon-" + nsB + ".vici"

	t.Cleanup(func() {
		_ = exec.Command("ip", "netns", "delete", nsA).Run()
		_ = exec.Command("ip", "netns", "delete", nsB).Run()
		_ = os.Remove(viciA)
		_ = os.Remove(viciB)
	})

	runIP(t, ctx, "netns", "add", nsA)
	runIP(t, ctx, "netns", "add", nsB)
	runIP(t, ctx, "link", "add", "hgunloada", "type", "veth", "peer", "name", "hgunloadb")
	runIP(t, ctx, "link", "set", "hgunloada", "netns", nsA)
	runIP(t, ctx, "link", "set", "hgunloadb", "netns", nsB)
	for _, args := range [][]string{
		{"netns", "exec", nsA, "ip", "link", "set", "lo", "up"},
		{"netns", "exec", nsB, "ip", "link", "set", "lo", "up"},
		{"netns", "exec", nsA, "ip", "addr", "add", "192.0.2.9/30", "dev", "hgunloada"},
		{"netns", "exec", nsB, "ip", "addr", "add", "192.0.2.10/30", "dev", "hgunloadb"},
		{"netns", "exec", nsA, "ip", "link", "set", "hgunloada", "up"},
		{"netns", "exec", nsB, "ip", "link", "set", "hgunloadb", "up"},
	} {
		runIP(t, ctx, args...)
	}

	confA, err := writeStrongSwanConf(viciA)
	if err != nil {
		t.Fatalf("write strongswan.conf A: %v", err)
	}
	confB, err := writeStrongSwanConf(viciB)
	if err != nil {
		t.Fatalf("write strongswan.conf B: %v", err)
	}
	piddirA, err := os.MkdirTemp("", "photon-unload-piddir-a-*")
	if err != nil {
		t.Fatalf("create piddir A: %v", err)
	}
	piddirB, err := os.MkdirTemp("", "photon-unload-piddir-b-*")
	if err != nil {
		t.Fatalf("create piddir B: %v", err)
	}
	logA, err := os.CreateTemp("", "photon-unload-charon-a-*.log")
	if err != nil {
		t.Fatalf("create log A: %v", err)
	}
	logB, err := os.CreateTemp("", "photon-unload-charon-b-*.log")
	if err != nil {
		t.Fatalf("create log B: %v", err)
	}

	charonA := startCharonInNetNS(ctx, t, nsA, piddirA, confA, logA)
	charonB := startCharonInNetNS(ctx, t, nsB, piddirB, confB, logB)
	defer func() {
		_ = charonA.Process.Kill()
		_ = charonB.Process.Kill()
		_ = charonA.Wait()
		_ = charonB.Wait()
		_ = os.Remove(confA)
		_ = os.Remove(confB)
		_ = os.RemoveAll(piddirA)
		_ = os.RemoveAll(piddirB)
		_ = logA.Close()
		_ = logB.Close()
		_ = os.Remove(logA.Name())
		_ = os.Remove(logB.Name())
	}()
	defer func() {
		if !t.Failed() {
			return
		}
		_ = logA.Sync()
		_ = logB.Sync()
		if data, err := os.ReadFile(logA.Name()); err == nil {
			t.Logf("--- unload charon A log ---\n%s", string(data))
		}
		if data, err := os.ReadFile(logB.Name()); err == nil {
			t.Logf("--- unload charon B log ---\n%s", string(data))
		}
	}()

	clientA, err := waitForVICI(ctx, viciA)
	if err != nil {
		t.Fatalf("connect to charon A VICI: %v", err)
	}
	defer clientA.Close()
	clientB, err := waitForVICI(ctx, viciB)
	if err != nil {
		t.Fatalf("connect to charon B VICI: %v", err)
	}
	defer clientB.Close()

	localPrivA, localPubA, err := generateECDSAKeyPair()
	if err != nil {
		t.Fatalf("generate key A: %v", err)
	}
	localPrivB, localPubB, err := generateECDSAKeyPair()
	if err != nil {
		t.Fatalf("generate key B: %v", err)
	}

	group := LinkGroupSpec{
		ID:                "main",
		Provider:          ProviderStrongSwan,
		TunnelAddressSpec: TunnelAddressSpec{Mode: TunnelAddressDerivedPool, Family: FamilyIPv6, Pool: netip.MustParsePrefix("fd00:4646::/64")},
	}
	linkID := StableLinkID("node-a.", "node-b.", group.ID, DefaultPathKey)
	addrA, addrB, err := group.DeriveTunnelAddressesForLink("node-a.", "node-b.", linkID, DefaultPathKey, 0, 0)
	if err != nil {
		t.Fatalf("derive base tunnel addresses: %v", err)
	}
	stagedAddrA, stagedAddrB, err := group.DeriveTunnelAddressesForLink("node-a.", "node-b.", linkID, DefaultPathKey, 2, 0)
	if err != nil {
		t.Fatalf("derive staged tunnel addresses: %v", err)
	}

	specA := TransportLinkSpec{
		LocalZone:                "node-a.",
		PeerZone:                 "node-b.",
		OverlayID:                group.ID,
		Provider:                 ProviderStrongSwan,
		TransportID:              "ipsec-unload-a-b",
		IKEIdentity:              "node-a.",
		LocalAddress:             "192.0.2.9",
		ContactPoints:            []ContactPoint{{Address: "192.0.2.10", IKEPort: DefaultIKEPort, NATTPort: DefaultNATTPort}},
		XFRMIfID:                 424446,
		InterfaceName:            "phxunloada0",
		LocalTunnelAddr:          addrA,
		PeerTunnelAddr:           addrB,
		NetNS:                    nsA,
		LocalPrivateKey:          localPrivA,
		LocalPrivateKeyAlgorithm: AlgorithmECDSAP256,
		PeerPublicKey:            localPubB,
		InitiatorRole:            InitiatorRolePrimary,
	}
	specB := TransportLinkSpec{
		LocalZone:                "node-b.",
		PeerZone:                 "node-a.",
		OverlayID:                group.ID,
		Provider:                 ProviderStrongSwan,
		TransportID:              "ipsec-unload-b-a",
		IKEIdentity:              "node-b.",
		LocalAddress:             "192.0.2.10",
		XFRMIfID:                 424546,
		InterfaceName:            "phxunloadb0",
		LocalTunnelAddr:          addrB,
		PeerTunnelAddr:           addrA,
		NetNS:                    nsB,
		LocalPrivateKey:          localPrivB,
		LocalPrivateKeyAlgorithm: AlgorithmECDSAP256,
		PeerPublicKey:            localPubA,
	}

	ipsecA := &StrongSwanDriver{VICI: clientA, KeyDir: t.TempDir()}
	ipsecB := &StrongSwanDriver{VICI: clientB, KeyDir: t.TempDir()}
	xfrmA := NewSystemXFRMDriver(NetNSSpec{Kind: NetNSName, Name: nsA, Create: false})
	xfrmB := NewSystemXFRMDriver(NetNSSpec{Kind: NetNSName, Name: nsB, Create: false})
	xfrmA.StateNetNS = NetNSSpec{Kind: NetNSName, Name: nsA, Create: false}
	xfrmB.StateNetNS = NetNSSpec{Kind: NetNSName, Name: nsB, Create: false}

	if _, err := ApplyTransportLink(ctx, ipsecB, xfrmB, specB, NetNSSpec{Kind: NetNSName, Name: nsB}); err != nil {
		t.Fatalf("apply responder link B: %v", err)
	}
	if _, err := ApplyTransportLink(ctx, ipsecA, xfrmA, specA, NetNSSpec{Kind: NetNSName, Name: nsA}); err != nil {
		t.Fatalf("apply initiator link A: %v", err)
	}
	if err := waitForSA(ctx, clientA, specA.TransportID); err != nil {
		t.Fatalf("wait for base SA on A: %v", err)
	}
	if err := waitForSA(ctx, clientB, specB.TransportID); err != nil {
		t.Fatalf("wait for base SA on B: %v", err)
	}

	runIP(t, ctx, "netns", "exec", nsA, "ip", "route", "replace", addrB.String()+"/128", "dev", specA.InterfaceName)
	runIP(t, ctx, "netns", "exec", nsB, "ip", "route", "replace", addrA.String()+"/128", "dev", specB.InterfaceName)
	if out, err := execCommand(ctx, "ip", "netns", "exec", nsA, "ping", "-6", "-c", "1", "-W", "3", addrB.String()); err != nil {
		t.Fatalf("base tunnel ping A->B failed: %v\n%s", err, string(out))
	}

	if err := ipsecB.UnloadConnection(ctx, specB.TransportID); err != nil {
		t.Fatalf("unload responder base config: %v", err)
	}
	if err := waitForSA(ctx, clientB, specB.TransportID); err != nil {
		t.Fatalf("base SA disappeared after unload-conn on responder: %v", err)
	}
	if out, err := execCommand(ctx, "ip", "netns", "exec", nsA, "ping", "-6", "-c", "1", "-W", "3", addrB.String()); err != nil {
		t.Fatalf("base tunnel ping after responder unload-conn failed: %v\n%s", err, string(out))
	}
	t.Logf("unload-conn on responder kept the established base SA and data plane alive")

	stagedA := specA
	stagedA.TransportID = RotateConnectionName(specA.TransportID, 2)
	stagedA.XFRMIfID = 424447
	stagedA.InterfaceName = "phxunloada2"
	stagedA.LocalTunnelAddr = stagedAddrA
	stagedA.PeerTunnelAddr = stagedAddrB
	stagedB := specB
	stagedB.TransportID = RotateConnectionName(specB.TransportID, 2)
	stagedB.XFRMIfID = 424547
	stagedB.InterfaceName = "phxunloadb2"
	stagedB.LocalTunnelAddr = stagedAddrB
	stagedB.PeerTunnelAddr = stagedAddrA

	if _, err := ApplyStagedConnection(ctx, ipsecB, xfrmB, stagedB, NetNSSpec{Kind: NetNSName, Name: nsB}); err != nil {
		t.Fatalf("apply staged responder link B: %v", err)
	}
	if _, err := ApplyStagedConnection(ctx, ipsecA, xfrmA, stagedA, NetNSSpec{Kind: NetNSName, Name: nsA}); err != nil {
		t.Fatalf("apply staged initiator link A: %v", err)
	}

	stagedCtx, stagedCancel := context.WithTimeout(ctx, 8*time.Second)
	defer stagedCancel()
	errA := waitForSA(stagedCtx, clientA, stagedA.TransportID)
	errB := waitForSA(stagedCtx, clientB, stagedB.TransportID)
	if errA != nil || errB != nil {
		t.Logf("staged SA not observed while base SA remained alive: A=%v B=%v", errA, errB)
		return
	}
	sasB, err := ipsecB.ListSAs(ctx)
	if err != nil {
		t.Fatalf("list staged SAs on B: %v", err)
	}
	if !hasEstablishedSAWithIfID(sasB, stagedB.TransportID, stagedB.XFRMIfID) {
		t.Logf("staged SA name appeared on B, but not with staged if_id %d: %+v", stagedB.XFRMIfID, sasB)
		return
	}
	t.Logf("staged SA established with staged if_id while base SA stayed alive")
}

// TestStrongSwanBidirectionalTakeoverSmoke exercises the Phase 4.5 takeover
// path with real StrongSwan/VICI/XFRM. The primary side is loaded as a
// responder-only trap to model "primary outbound cannot initiate, but inbound
// IKE is still reachable"; the secondary starts in standby, then reconcile
// promotes it to takeover and establishes the SA.
func TestStrongSwanBidirectionalTakeoverSmoke(t *testing.T) {
	if os.Getenv("PHOTON_IPSEC_XFRM_SMOKE") != "1" {
		t.Skip("set PHOTON_IPSEC_XFRM_SMOKE=1 to run the root/system StrongSwan smoke")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	suffix := time.Now().UTC().Format("20060102150405")
	nsA := "photon-take-a-" + suffix
	nsB := "photon-take-b-" + suffix
	viciA := "/tmp/charon-" + nsA + ".vici"
	viciB := "/tmp/charon-" + nsB + ".vici"

	t.Cleanup(func() {
		_ = exec.Command("ip", "netns", "delete", nsA).Run()
		_ = exec.Command("ip", "netns", "delete", nsB).Run()
		_ = os.Remove(viciA)
		_ = os.Remove(viciB)
	})

	runIP(t, ctx, "netns", "add", nsA)
	runIP(t, ctx, "netns", "add", nsB)
	runIP(t, ctx, "link", "add", "hgtakea", "type", "veth", "peer", "name", "hgtakeb")
	runIP(t, ctx, "link", "set", "hgtakea", "netns", nsA)
	runIP(t, ctx, "link", "set", "hgtakeb", "netns", nsB)
	for _, args := range [][]string{
		{"netns", "exec", nsA, "ip", "link", "set", "lo", "up"},
		{"netns", "exec", nsB, "ip", "link", "set", "lo", "up"},
		{"netns", "exec", nsA, "ip", "addr", "add", "192.0.2.5/30", "dev", "hgtakea"},
		{"netns", "exec", nsB, "ip", "addr", "add", "192.0.2.6/30", "dev", "hgtakeb"},
		{"netns", "exec", nsA, "ip", "link", "set", "hgtakea", "up"},
		{"netns", "exec", nsB, "ip", "link", "set", "hgtakeb", "up"},
	} {
		runIP(t, ctx, args...)
	}

	confA, err := writeStrongSwanConf(viciA)
	if err != nil {
		t.Fatalf("write strongswan.conf A: %v", err)
	}
	confB, err := writeStrongSwanConf(viciB)
	if err != nil {
		t.Fatalf("write strongswan.conf B: %v", err)
	}
	piddirA, err := os.MkdirTemp("", "photon-take-piddir-a-*")
	if err != nil {
		t.Fatalf("create piddir A: %v", err)
	}
	piddirB, err := os.MkdirTemp("", "photon-take-piddir-b-*")
	if err != nil {
		t.Fatalf("create piddir B: %v", err)
	}
	logA, err := os.CreateTemp("", "photon-take-charon-a-*.log")
	if err != nil {
		t.Fatalf("create log A: %v", err)
	}
	logB, err := os.CreateTemp("", "photon-take-charon-b-*.log")
	if err != nil {
		t.Fatalf("create log B: %v", err)
	}

	charonA := startCharonInNetNS(ctx, t, nsA, piddirA, confA, logA)
	charonB := startCharonInNetNS(ctx, t, nsB, piddirB, confB, logB)
	defer func() {
		_ = charonA.Process.Kill()
		_ = charonB.Process.Kill()
		_ = charonA.Wait()
		_ = charonB.Wait()
		_ = os.Remove(confA)
		_ = os.Remove(confB)
		_ = os.RemoveAll(piddirA)
		_ = os.RemoveAll(piddirB)
		_ = logA.Close()
		_ = logB.Close()
		_ = os.Remove(logA.Name())
		_ = os.Remove(logB.Name())
	}()
	defer func() {
		if !t.Failed() {
			return
		}
		_ = logA.Sync()
		_ = logB.Sync()
		if data, err := os.ReadFile(logA.Name()); err == nil {
			t.Logf("--- takeover charon A log ---\n%s", string(data))
		}
		if data, err := os.ReadFile(logB.Name()); err == nil {
			t.Logf("--- takeover charon B log ---\n%s", string(data))
		}
	}()

	clientA, err := waitForVICI(ctx, viciA)
	if err != nil {
		t.Fatalf("connect to charon A VICI: %v", err)
	}
	defer clientA.Close()
	clientB, err := waitForVICI(ctx, viciB)
	if err != nil {
		t.Fatalf("connect to charon B VICI: %v", err)
	}
	defer clientB.Close()

	localPrivA, localPubA, err := generateECDSAKeyPair()
	if err != nil {
		t.Fatalf("generate key A: %v", err)
	}
	localPrivB, localPubB, err := generateECDSAKeyPair()
	if err != nil {
		t.Fatalf("generate key B: %v", err)
	}

	const ifIDA = uint32(424245)
	const ifIDB = uint32(424345)
	ifaceA := "phxtakea0"
	ifaceB := "phxtakeb0"
	transportA := "ipsec-takeover-a"
	transportB := "ipsec-takeover-b"
	group := LinkGroupSpec{
		ID:                "main",
		Provider:          ProviderStrongSwan,
		TunnelAddressSpec: TunnelAddressSpec{Mode: TunnelAddressDerivedPool, Family: FamilyIPv6, Pool: netip.MustParsePrefix("fd00:4545::/64")},
	}
	addrA, addrB, err := group.DeriveTunnelAddresses("node-a.", "node-b.", 0)
	if err != nil {
		t.Fatalf("derive tunnel addresses: %v", err)
	}

	specA := TransportLinkSpec{
		LocalZone:                "node-a.",
		PeerZone:                 "node-b.",
		OverlayID:                group.ID,
		Provider:                 ProviderStrongSwan,
		TransportID:              transportA,
		IKEIdentity:              "node-a.",
		LocalAddress:             "192.0.2.5",
		ContactPoints:            []ContactPoint{{Address: "192.0.2.6", IKEPort: DefaultIKEPort, NATTPort: DefaultNATTPort}},
		XFRMIfID:                 ifIDA,
		InterfaceName:            ifaceA,
		LocalTunnelAddr:          addrA,
		PeerTunnelAddr:           addrB,
		NetNS:                    nsA,
		LocalPrivateKey:          localPrivA,
		LocalPrivateKeyAlgorithm: AlgorithmECDSAP256,
		PeerPublicKey:            localPubB,
		InitiatorRole:            InitiatorRolePrimary,
	}
	specAInbound := specA
	specAInbound.InitiatorRole = ""
	specAInbound.ContactPoints = nil
	specB := TransportLinkSpec{
		LocalZone:                "node-b.",
		PeerZone:                 "node-a.",
		OverlayID:                group.ID,
		Provider:                 ProviderStrongSwan,
		TransportID:              transportB,
		IKEIdentity:              "node-b.",
		LocalAddress:             "192.0.2.6",
		ContactPoints:            []ContactPoint{{Address: "192.0.2.5", IKEPort: DefaultIKEPort, NATTPort: DefaultNATTPort}},
		XFRMIfID:                 ifIDB,
		InterfaceName:            ifaceB,
		LocalTunnelAddr:          addrB,
		PeerTunnelAddr:           addrA,
		NetNS:                    nsB,
		LocalPrivateKey:          localPrivB,
		LocalPrivateKeyAlgorithm: AlgorithmECDSAP256,
		PeerPublicKey:            localPubA,
		InitiatorRole:            InitiatorRoleSecondaryStandby,
	}

	ipsecA := &StrongSwanDriver{
		VICI:                  clientA,
		KeyDir:                t.TempDir(),
		InitiateAsync:         true,
		InitiateClientFactory: testVICIClientFactory(viciA),
	}
	ipsecB := &StrongSwanDriver{
		VICI:                  clientB,
		KeyDir:                t.TempDir(),
		InitiateAsync:         true,
		InitiateClientFactory: testVICIClientFactory(viciB),
	}
	xfrmA := NewSystemXFRMDriver(NetNSSpec{Kind: NetNSName, Name: nsA, Create: false})
	xfrmB := NewSystemXFRMDriver(NetNSSpec{Kind: NetNSName, Name: nsB, Create: false})
	xfrmA.StateNetNS = NetNSSpec{Kind: NetNSName, Name: nsA, Create: false}
	xfrmB.StateNetNS = NetNSSpec{Kind: NetNSName, Name: nsB, Create: false}

	if _, err := ApplyTransportLink(ctx, ipsecA, xfrmA, specAInbound, NetNSSpec{Kind: NetNSName, Name: nsA}); err != nil {
		t.Fatalf("apply primary responder config: %v", err)
	}

	base := time.Now()
	result := ReconcileLinkInstances(ReconcileInputs{
		Desired:      []TransportLinkSpec{specB},
		Instances:    map[string]LinkInstance{},
		Now:          base,
		Roles:        map[string]string{transportB: InitiatorRoleSecondaryStandby},
		GroupBackoff: map[string]BackoffPolicy{group.ID: group.Reconcile.Backoff},
	})
	if len(result.Actions) != 1 || result.Actions[0].Action != ReconcileActionPrepareStandby || result.Actions[0].Reason != "standby_responder_prepare" {
		t.Fatalf("expected secondary standby, got %+v", result.Actions)
	}
	instB := result.Instances[transportB]

	result = ReconcileLinkInstances(ReconcileInputs{
		Desired:      []TransportLinkSpec{specB},
		Instances:    map[string]LinkInstance{instB.ID: instB},
		Now:          base.Add(2 * time.Minute),
		Roles:        map[string]string{transportB: InitiatorRoleSecondaryStandby},
		GroupBackoff: map[string]BackoffPolicy{group.ID: group.Reconcile.Backoff},
	})
	if len(result.Actions) != 1 || result.Actions[0].Action != ReconcileActionCreate || result.Actions[0].Reason != "secondary_takeover" {
		t.Fatalf("expected secondary takeover create, got %+v", result.Actions)
	}
	if _, err := ApplyReconcileAction(ctx, ipsecB, xfrmB, result.Actions[0], NetNSSpec{Kind: NetNSName, Name: nsB}); err != nil {
		t.Fatalf("apply secondary takeover: %v", err)
	}

	if err := waitForSA(ctx, clientA, transportA); err != nil {
		t.Fatalf("wait for takeover SA on primary responder: %v", err)
	}
	if err := waitForSA(ctx, clientB, transportB); err != nil {
		t.Fatalf("wait for takeover SA on secondary: %v", err)
	}

	runIP(t, ctx, "netns", "exec", nsA, "ip", "route", "replace", addrB.String()+"/128", "dev", specA.InterfaceName)
	runIP(t, ctx, "netns", "exec", nsB, "ip", "route", "replace", addrA.String()+"/128", "dev", specB.InterfaceName)
	if out, err := execCommand(ctx, "ip", "netns", "exec", nsB, "ping", "-6", "-c", "1", "-W", "3", addrA.String()); err != nil {
		t.Fatalf("takeover tunnel ping B->A failed: %v\n%s", err, string(out))
	}

	sasA, err := ipsecA.ListSAs(ctx)
	if err != nil {
		t.Fatalf("list SAs on primary: %v", err)
	}
	recovered := ReconcileLinkInstances(ReconcileInputs{
		Desired:   []TransportLinkSpec{specA},
		Instances: map[string]LinkInstance{},
		SAs:       sasA,
		Now:       time.Now(),
		Roles:     map[string]string{transportA: InitiatorRolePrimary},
	})
	if len(recovered.Actions) != 1 || recovered.Actions[0].Action != ReconcileActionAdopt {
		t.Fatalf("primary recovery should adopt existing SA, got %+v", recovered.Actions)
	}
	if inst := recovered.Instances[transportA]; inst.ActualState != LinkStateUp {
		t.Fatalf("primary recovered instance = %+v", inst)
	}

	t.Logf("bidirectional takeover smoke succeeded; secondary established SA and primary recovered by adopt")
}

func generateECDSAKeyPair() (privDER, pubDER []byte, err error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	privDER, err = x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	pubDER, err = x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	return privDER, pubDER, nil
}

func writeStrongSwanConf(viciSocket string) (string, error) {
	f, err := os.CreateTemp("", "strongswan-*.conf")
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

func startCharonInNetNS(ctx context.Context, t *testing.T, ns, piddir, conf string, logFile *os.File) *exec.Cmd {
	t.Helper()
	script := fmt.Sprintf("mkdir -p /run && mount --bind %s /run && STRONGSWAN_CONF=%s exec charon", piddir, conf)
	cmd := exec.CommandContext(ctx, "unshare", "-m", "ip", "netns", "exec", ns, "bash", "-c", script)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		t.Fatalf("start charon in %s: %v", ns, err)
	}
	return cmd
}

func waitForVICI(ctx context.Context, socket string) (*GoviciClient, error) {
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
		client, err := NewGoviciClient(socket)
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

func testVICIClientFactory(socket string) func() (VICIClient, func() error, error) {
	return func() (VICIClient, func() error, error) {
		client, err := NewGoviciClient(socket)
		if err != nil {
			return nil, nil, err
		}
		return client, client.Close, nil
	}
}

func waitForSA(ctx context.Context, client *GoviciClient, name string) error {
	for {
		events, err := client.CallStreaming(ctx, "list-sas", "list-sa", map[string]any{"ike": name})
		if err != nil {
			return err
		}
		established := slices.ContainsFunc(events, saEstablished)
		if established {
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

func dumpStrongSwanSmokeDiagnostics(t *testing.T, ctx context.Context, ns, viciSocket, label string) {
	t.Helper()
	commands := []struct {
		name string
		args []string
	}{
		{name: "swanctl list conns", args: []string{"netns", "exec", ns, "swanctl", "--uri", "unix://" + viciSocket, "--list-conns"}},
		{name: "swanctl list sas", args: []string{"netns", "exec", ns, "swanctl", "--uri", "unix://" + viciSocket, "--list-sas"}},
		{name: "xfrm state", args: []string{"netns", "exec", ns, "ip", "xfrm", "state"}},
		{name: "xfrm policy", args: []string{"netns", "exec", ns, "ip", "xfrm", "policy"}},
		{name: "links", args: []string{"netns", "exec", ns, "ip", "link", "show"}},
		{name: "addresses", args: []string{"netns", "exec", ns, "ip", "addr", "show"}},
		{name: "routes", args: []string{"netns", "exec", ns, "ip", "route", "show", "table", "all"}},
	}
	for _, cmd := range commands {
		out, err := execCommand(ctx, "ip", cmd.args...)
		if err != nil {
			t.Logf("--- strongSwan smoke %s %s failed: %v ---\n%s", label, cmd.name, err, string(out))
			continue
		}
		t.Logf("--- strongSwan smoke %s %s ---\n%s", label, cmd.name, string(out))
	}
}

func saEstablished(raw map[string]any) bool {
	for _, v := range raw {
		sa, ok := v.(map[string]any)
		if !ok {
			continue
		}
		state := stringValue(sa["state"])
		if strings.EqualFold(state, "ESTABLISHED") {
			return true
		}
		children, _ := sa["child-sas"].(map[string]any)
		for _, cv := range children {
			child, ok := cv.(map[string]any)
			if !ok {
				continue
			}
			if stringValue(child["state"]) == "INSTALLED" {
				return true
			}
		}
	}
	return false
}

func hasEstablishedSAWithIfID(sas []SAState, name string, ifID uint32) bool {
	for _, sa := range sas {
		if sa.Name == name && sa.XFRMIfID == ifID && sa.Established {
			return true
		}
	}
	return false
}
