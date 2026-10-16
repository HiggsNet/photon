package photonwindows

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/HiggsNet/photon/internal/photonclient/ike"
)

// gatewayTunnel is owned exclusively by Daemon's event loop. It has no socket,
// goroutine, persisted observation or independent copy of verified state.
type gatewayTunnel struct {
	diagnostic                               tunnelDiagnostic
	childOverlapUntil                        time.Time
	localAuthorization                       [32]byte
	pendingChildSPI                          uint32
	ikeRekeyAt, ikeExpiresAt                 time.Time
	oldIKE                                   []*ikeOverlap
	rekeyAt, deleteAt                        time.Time
	rekeyGroup                               uint16
	deleteSPI                                uint32
	failed                                   error
	socket                                   *packetSockets
	data                                     *gatewayDataplane
	session                                  *ike.Initiator
	plan                                     GatewayPlan
	generation                               uint64
	peer                                     netip.AddrPort
	natt                                     bool
	phase                                    uint8 // 0 stopped, 1 INIT, 2 AUTH, 3 established
	localID                                  string
	private                                  ed25519.PrivateKey
	pending                                  [][]byte
	attempts                                 int
	retryAt, probeAt, keepaliveAt, expiresAt time.Time
	child                                    ike.ChildResult
}

func (t *gatewayTunnel) stop() {
	if t.phase != 0 {
		t.observeEvent("stopped", time.Now(), nil)
		t.observeProgress()
	}
	// Deny data first. An idle established SA gets one best-effort encrypted
	// Delete, without awaiting the peer or delaying local teardown/reconnect.
	t.data.reset(t.generation + 1)
	if t.phase == 3 && t.session != nil && len(t.session.PendingRequest()) == 0 && t.failed == nil {
		if request, err := t.session.IKEDeleteRequest(); err == nil {
			if wire, err := ike.EncapsulateIKE(request); err == nil {
				_ = t.socket.WriteTunnel(t.generation, wire, t.peer)
			}
		}
	}
	t.generation = t.socket.SelectTunnel(netip.AddrPort{}, netip.AddrPort{})
	t.data.reset(t.generation)
	clear(t.private)
	t.session, t.pending, t.private = nil, nil, nil
	t.phase = 0
	t.plan = GatewayPlan{}
	t.child = ike.ChildResult{}
	t.failed, t.deleteSPI = nil, 0
	t.pendingChildSPI = 0
	t.localAuthorization = [32]byte{}
	t.oldIKE = nil
	t.childOverlapUntil = time.Time{}
}

func (t *gatewayTunnel) start(plan GatewayPlan, localID string, private ed25519.PrivateKey, now time.Time) (err error) {
	t.stop()
	t.observeProgress()
	t.diagnostic.gateway, t.diagnostic.remote, t.diagnostic.generation = "", "", 0
	t.diagnostic.retryAt = time.Time{}
	if plan.Selected != nil {
		t.diagnostic.gateway = boundedObservationText(string(plan.Selected.Zone))
	}
	t.observeEvent("starting", now, nil)
	defer func() {
		if err != nil {
			t.observeEvent("start_failed", now, err)
		}
	}()
	if plan.Selected == nil || plan.Rejected != "" || len(private) != ed25519.PrivateKeySize {
		return errors.New("tunnel: no current gateway or local transport key")
	}
	contact := plan.Selected.Contact
	addr, err := netip.ParseAddr(contact.Address)
	if err != nil || contact.IKEPort == 0 || contact.NATTPort == 0 {
		return errors.New("tunnel: invalid gateway endpoints")
	}
	peer := netip.AddrPortFrom(addr.Unmap(), contact.IKEPort)
	t.diagnostic.remote = peer.String()
	nattPeer := netip.AddrPortFrom(addr.Unmap(), contact.NATTPort)
	local := t.socket.LocalAddr().AddrPort()
	if local.Addr().IsUnspecified() {
		// Route lookup only: this temporary socket never sends or receives IKE.
		// The single shared bound socket remains the packet transport owner.
		probe, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(peer))
		if err != nil {
			return err
		}
		local = netip.AddrPortFrom(probe.LocalAddr().(*net.UDPAddr).AddrPort().Addr().Unmap(), local.Port())
		probe.Close()
	}
	session, err := ike.NewInitiatorWithEndpoints(local, peer)
	if err != nil {
		return err
	}
	t.generation = t.socket.SelectTunnel(peer, nattPeer)
	t.data.reset(t.generation)
	t.session, t.plan, t.peer = session, plan, peer
	t.localID, t.private, t.phase = localID, append(ed25519.PrivateKey(nil), private...), 1
	t.rekeyGroup = ike.GroupP256
	t.natt = peer == nattPeer || peer.Port() == 4500
	return t.sendNew([][]byte{session.Request()}, now)
}

func (t *gatewayTunnel) sendNew(packets [][]byte, now time.Time) error {
	if t.phase == 3 {
		var err error
		packets, err = t.session.PendingRequestPackets(1196)
		if err != nil {
			return err
		}
	}
	t.pending, t.attempts = packets, 0
	return t.sendPending(now)
}

func (t *gatewayTunnel) sendPending(now time.Time) error {
	if t.attempts >= 5 {
		return errors.New("tunnel: IKE retransmission budget exhausted")
	}
	deadline := time.Now().Add(time.Second)
	for _, packet := range t.pending {
		if time.Now().After(deadline) {
			return context.DeadlineExceeded
		}
		wire := packet
		if t.natt {
			var err error
			wire, err = ike.EncapsulateIKE(packet)
			if err != nil {
				return err
			}
		}
		if err := t.socket.WriteTunnel(t.generation, wire, t.peer); err != nil {
			return err
		}
	}
	t.retryAt = now.Add(time.Second << t.attempts)
	t.attempts++
	t.observeEvent("exchange_sent", now, nil)
	return nil
}

func (t *gatewayTunnel) current(plan GatewayPlan) bool {
	return t.phase != 0 && plan.Rejected == "" && plan.Selected != nil && t.plan.Selected != nil && dataplaneGatewayEqual(*plan.Selected, *t.plan.Selected)
}

// tick returns fatal lifecycle errors. Invalid network packets are separately
// ignored without resetting retransmission deadlines or extending liveness.
func (t *gatewayTunnel) tick(plan GatewayPlan, now time.Time) (err error) {
	defer func() {
		if err != nil {
			t.observeEvent("lifecycle_failed", now, err)
		}
	}()
	if t.phase == 0 {
		return nil
	}
	if t.failed != nil {
		return t.failed
	}
	if !t.current(plan) {
		return errors.New("tunnel: current gateway authorization withdrawn")
	}
	if t.phase == 3 {
		if !now.Before(t.ikeExpiresAt) {
			return errors.New("tunnel: IKE hard lifetime reached")
		}
		t.tickOldIKE(now)
	}
	if t.phase == 3 && !now.Before(t.expiresAt) {
		return errors.New("tunnel: CHILD hard lifetime reached")
	}
	if t.phase == 3 && len(t.data.sas) > 1 && !t.childOverlapUntil.IsZero() && !now.Before(t.childOverlapUntil) {
		return errors.New("tunnel: CHILD overlap cleanup deadline reached")
	}
	if len(t.pending) != 0 && !now.Before(t.retryAt) {
		return t.sendPending(now)
	}
	if t.phase == 3 && t.data.active == nil {
		return errors.New("tunnel: active CHILD withdrawn")
	}
	if t.phase == 3 && len(t.pending) == 0 {
		if t.deleteSPI != 0 && !now.Before(t.deleteAt) {
			request, err := t.session.ChildDeleteRequest([]uint32{t.deleteSPI})
			if err != nil {
				return err
			}
			t.deleteSPI = 0
			return t.sendNew([][]byte{request}, now)
		}
		if !now.Before(t.ikeRekeyAt) {
			request, err := t.session.IKERekeyRequest()
			if err != nil {
				return err
			}
			return t.sendNew([][]byte{request}, now)
		}
		if !now.Before(t.rekeyAt) {
			spi, err := freshChildSPI()
			if err != nil {
				return err
			}
			request, err := t.session.ChildRequest(ike.ChildExchangeConfig{Child: ike.ChildConfig{InitiatorSPI: spi, LocalSelectors: t.child.LocalSelectors, RemoteSelectors: t.child.RemoteSelectors}, RekeySPI: t.child.InitiatorSPI, DHGroup: t.rekeyGroup})
			if err != nil {
				return err
			}
			return t.sendNew([][]byte{request}, now)
		}
	}
	if t.phase == 3 && len(t.pending) == 0 && !now.Before(t.probeAt) {
		packet, err := t.session.InformationalRequest()
		if err != nil {
			return err
		}
		return t.sendNew([][]byte{packet}, now)
	}
	if t.natt && t.phase == 3 && !now.Before(t.keepaliveAt) {
		if err := t.socket.WriteTunnel(t.generation, []byte{0xff}, t.peer); err != nil {
			return err
		}
		t.keepaliveAt = now.Add(15 * time.Second)
	}
	return nil
}

func (t *gatewayTunnel) handle(packet tunnelDatagram, plan GatewayPlan, now time.Time) (err error) {
	t.observeEvent("packet_received", now, nil)
	defer func() {
		if err != nil {
			t.observeEvent("packet_rejected", now, err)
		} else if t.phase == 3 && len(t.pending) == 0 {
			t.observeProgress()
		}
	}()
	if t.failed != nil {
		return t.failed
	}
	if packet.generation != t.generation || packet.peer != t.peer || !t.current(plan) {
		return errors.New("tunnel: stale or unauthorized ingress")
	}
	switch t.phase {
	case 1:
		if retry, err := t.session.HandleInitCookie(packet.packet); err == nil {
			t.pending = [][]byte{retry}
			return t.sendPending(now) // challenge never resets the attempt budget
		}
		result, err := t.session.HandleInitResponse(packet.packet)
		if err != nil {
			return err
		}
		if !result.NAT.Required() && !t.natt {
			return errors.New("tunnel: gateway did not negotiate UDP encapsulation")
		}
		t.peer = netip.AddrPortFrom(t.peer.Addr(), plan.Selected.Contact.NATTPort)
		t.natt = true
		var spi [4]byte
		for binary.BigEndian.Uint32(spi[:]) < 256 {
			if _, err := rand.Read(spi[:]); err != nil {
				return err
			}
		}
		selectors := []ike.TrafficSelector{
			{StartAddr: netip.MustParseAddr("0.0.0.0"), EndAddr: netip.MustParseAddr("255.255.255.255"), EndPort: 65535},
			{StartAddr: netip.MustParseAddr("::"), EndAddr: netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), EndPort: 65535},
		}
		request, err := t.session.AuthRequest(ike.AuthConfig{LocalID: t.localID, RemoteID: plan.Selected.Identity, PrivateKey: t.private, RemotePublicKey: plan.Selected.PublicKey, Child: ike.ChildConfig{InitiatorSPI: binary.BigEndian.Uint32(spi[:]), LocalSelectors: selectors, RemoteSelectors: selectors}})
		if err != nil {
			return err
		}
		clear(t.private)
		t.private = nil
		t.phase = 2
		t.observeProgress()
		requests := [][]byte{request}
		if len(request) > 1196 {
			requests, err = t.session.AuthRequestFragments(1196)
			if err != nil {
				return err
			}
		}
		return t.sendNew(requests, now)
	case 2:
		_, payload, err := ike.DecodeHeader(packet.packet)
		if err != nil {
			return err
		}
		var result *ike.AuthResult
		if payload == ike.PayloadSKF {
			result, err = t.session.HandleAuthFragment(packet.packet, now)
		} else {
			result, err = t.session.HandleAuthResponse(packet.packet)
		}
		if err != nil {
			return err
		}
		if result == nil {
			return nil
		}
		if err := t.data.install(t.generation, plan, t.peer, result.Child); err != nil {
			t.failed = err
			return err
		}
		t.child, t.phase, t.pending = result.Child, 3, nil
		t.probeAt, t.keepaliveAt = now.Add(20*time.Second), now.Add(15*time.Second)
		// This finite bound is replaced only by successful rekey, never traffic.
		t.expiresAt = now.Add(10 * time.Minute)
		t.rekeyAt = now.Add(5 * time.Minute)
		t.ikeRekeyAt, t.ikeExpiresAt = now.Add(30*time.Minute), now.Add(time.Hour)
		t.child.Keys = ike.ChildKeys{}
		t.observeProgress()
		t.observeEvent("authenticated", now, nil)
		return nil
	case 3:
		return t.handleEstablished(packet.packet, plan, now)
	}
	return fmt.Errorf("tunnel: inactive session")
}
