package photonwindows

import (
	"context"
	"crypto/ed25519"
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
	queueIKE                                 func(uint64, []byte, netip.AddrPort, bool) error
	data                                     *gatewayDataplane
	session                                  *ike.Initiator
	ikeLeased                                bool
	plan                                     GatewayPlan
	generation                               uint64
	peer                                     netip.AddrPort
	natt                                     bool
	offerMOBIKE, mobike                      bool
	mobikeEpoch, mobikeSent                  uint64
	mobikeDeadline                           time.Time
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
	retireQueued := false
	if t.phase == 3 && !t.ikeLeased && t.session != nil && len(t.session.PendingRequest()) == 0 && t.failed == nil {
		if request, err := t.session.IKEDeleteRequest(); err == nil {
			if wire, err := ike.EncapsulateIKE(request); err == nil {
				if t.queueIKE == nil {
					_ = t.writeIKE(wire)
				} else {
					retireQueued = t.queueIKE(t.generation, wire, t.peer, true) == nil
				}
			}
		}
	}
	if !retireQueued {
		t.socket.releaseTunnel(t.generation)
	}
	t.generation = 0
	t.data.reset(t.generation)
	clear(t.private)
	t.session, t.pending, t.private = nil, nil, nil
	t.ikeLeased = false
	t.mobike, t.mobikeEpoch, t.mobikeSent, t.mobikeDeadline = false, 0, 0, time.Time{}
	t.phase = 0
	t.plan = GatewayPlan{}
	t.child = ike.ChildResult{}
	t.failed, t.deleteSPI = nil, 0
	t.pendingChildSPI = 0
	t.localAuthorization = [32]byte{}
	t.oldIKE = nil
	t.childOverlapUntil = time.Time{}
}

type preparedIKEStart struct {
	session        *ike.Initiator
	peer, nattPeer netip.AddrPort
}

func prepareIKEStart(plan GatewayPlan, local netip.AddrPort) (preparedIKEStart, error) {
	var start preparedIKEStart
	if plan.Selected == nil || plan.Rejected != "" {
		return start, errors.New("tunnel: no current gateway")
	}
	contact := plan.Selected.Contact
	addr, err := netip.ParseAddr(contact.Address)
	if err != nil || contact.IKEPort == 0 || contact.NATTPort == 0 {
		return start, errors.New("tunnel: invalid gateway endpoints")
	}
	start.peer = netip.AddrPortFrom(addr.Unmap(), contact.IKEPort)
	start.nattPeer = netip.AddrPortFrom(addr.Unmap(), contact.NATTPort)
	local, err = outboundUDPLocal(local, start.peer)
	if err != nil {
		return start, err
	}
	start.session, err = ike.NewInitiatorWithEndpoints(local, start.peer)
	return start, err
}

func outboundUDPLocal(local, remote netip.AddrPort) (netip.AddrPort, error) {
	if !local.Addr().Unmap().IsUnspecified() {
		return local, nil
	}
	probe, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(remote))
	if err != nil {
		return netip.AddrPort{}, err
	}
	defer probe.Close()
	source := probe.LocalAddr().(*net.UDPAddr).AddrPort().Addr().Unmap()
	return netip.AddrPortFrom(source, local.Port()), nil
}

func (t *gatewayTunnel) start(plan GatewayPlan, localID string, private ed25519.PrivateKey, now time.Time) error {
	start, err := prepareIKEStart(plan, t.socket.LocalAddr().AddrPort())
	return t.installIKEStart(plan, localID, private, start, now, err)
}

func (t *gatewayTunnel) installIKEStart(plan GatewayPlan, localID string, private ed25519.PrivateKey, start preparedIKEStart, now time.Time, prepareErr error) (err error) {
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
	if prepareErr != nil {
		return prepareErr
	}
	if len(private) != ed25519.PrivateKeySize {
		return errors.New("tunnel: no current local transport key")
	}
	t.diagnostic.remote = start.peer.String()
	t.generation = t.socket.reserveTunnel(start.peer, start.nattPeer)
	t.data.reset(t.generation)
	t.session, t.plan, t.peer = start.session, plan, start.peer
	t.localID, t.private, t.phase = localID, append(ed25519.PrivateKey(nil), private...), 1
	t.rekeyGroup = ike.GroupP256
	t.natt = start.peer == start.nattPeer || start.peer.Port() == 4500
	return t.sendNew([][]byte{start.session.Request()}, now)
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
		if err := t.writeIKE(wire); err != nil {
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
func (t *gatewayTunnel) tick(plan GatewayPlan, now time.Time) error {
	return t.tickWithScheduler(plan, now, nil)
}

func (t *gatewayTunnel) tickWithScheduler(plan GatewayPlan, now time.Time, schedule func(ikeTimerRequest)) (err error) {
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
	if !t.mobikeDeadline.IsZero() && !now.Before(t.mobikeDeadline) {
		return errors.New("tunnel: MOBIKE update timed out")
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
		if request := t.dueIKERequest(now); request.kind != 0 {
			if schedule != nil {
				schedule(request)
				return nil
			}
			packets, err := prepareIKETimer(request)
			if errors.Is(err, errMOBIKEPathUnavailable) {
				t.waitForMOBIKEPath(now)
				return nil
			}
			if err != nil {
				return err
			}
			return t.applyIKETimer(request, packets, now)
		}
	}
	if t.natt && t.phase == 3 && !now.Before(t.keepaliveAt) {
		if err := t.writeIKE([]byte{0xff}); err != nil {
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
	if err := t.validateIKEIngress(packet, plan); err != nil {
		return err
	}
	switch t.phase {
	case 1, 2:
		input := t.ikeHandshakeInput(plan)
		action, err := prepareIKEHandshakeResponse(t.phase, packet.packet, now, input)
		return t.applyIKEHandshakeResponse(action, plan, now, err)
	case 3:
		return t.handleEstablished(packet.packet, plan, now)
	}
	return fmt.Errorf("tunnel: inactive session")
}

func (t *gatewayTunnel) validateIKEIngress(packet tunnelDatagram, plan GatewayPlan) error {
	if t.failed != nil {
		return t.failed
	}
	if packet.generation != t.generation || packet.peer != t.peer || !t.current(plan) {
		return errors.New("tunnel: stale or unauthorized ingress")
	}
	return nil
}

type ikeHandshakeInput struct {
	session   *ike.Initiator
	private   ed25519.PrivateKey
	localID   string
	selection GatewaySelection
	natt      bool
	mobike    bool
}

type ikeHandshakeAction struct {
	cookie       []byte
	floatNATT    bool
	authPrepared bool
	requests     [][]byte
	auth         *ike.AuthResult
}

func (t *gatewayTunnel) ikeHandshakeInput(plan GatewayPlan) ikeHandshakeInput {
	return ikeHandshakeInput{session: t.session, private: t.private, localID: t.localID, selection: *plan.Selected, natt: t.natt, mobike: t.offerMOBIKE}
}

// prepareIKEHandshakeResponse owns only the negotiating session. Socket writes
// and installation remain serialized with packet authorization by the caller.
func prepareIKEHandshakeResponse(phase uint8, packet []byte, now time.Time, input ikeHandshakeInput) (action ikeHandshakeAction, err error) {
	session := input.session
	if phase == 2 {
		_, payload, err := ike.DecodeHeader(packet)
		if err != nil {
			return action, err
		}
		if payload == ike.PayloadSKF {
			action.auth, err = session.HandleAuthFragment(packet, now)
		} else {
			action.auth, err = session.HandleAuthResponse(packet)
		}
		return action, err
	}
	if retry, err := session.HandleInitCookie(packet); err == nil {
		action.cookie = retry
		return action, nil
	}
	result, err := session.HandleInitResponse(packet)
	if err != nil {
		return action, err
	}
	if !result.NAT.Required() && !input.natt {
		return action, errors.New("tunnel: gateway did not negotiate UDP encapsulation")
	}
	action.floatNATT = true
	spi, err := freshChildSPI()
	if err != nil {
		return action, err
	}
	selectors := []ike.TrafficSelector{
		{StartAddr: netip.MustParseAddr("0.0.0.0"), EndAddr: netip.MustParseAddr("255.255.255.255"), EndPort: 65535},
		{StartAddr: netip.MustParseAddr("::"), EndAddr: netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), EndPort: 65535},
	}
	request, err := session.AuthRequest(ike.AuthConfig{LocalID: input.localID, RemoteID: input.selection.Identity, PrivateKey: input.private, RemotePublicKey: input.selection.PublicKey, MOBIKE: input.mobike, Child: ike.ChildConfig{InitiatorSPI: spi, LocalSelectors: selectors, RemoteSelectors: selectors}})
	if err != nil {
		return action, err
	}
	action.authPrepared = true
	action.requests = [][]byte{request}
	if len(request) > 1196 {
		action.requests, err = session.AuthRequestFragments(1196)
	}
	return action, err
}

func (t *gatewayTunnel) applyIKEHandshakeResponse(action ikeHandshakeAction, plan GatewayPlan, now time.Time, err error) error {
	if action.floatNATT {
		t.peer = netip.AddrPortFrom(t.peer.Addr(), plan.Selected.Contact.NATTPort)
		t.natt = true
	}
	if action.authPrepared {
		clear(t.private)
		t.private = nil
		t.phase = 2
		t.observeProgress()
	}
	if err != nil {
		return err
	}
	switch {
	case action.cookie != nil:
		t.pending = [][]byte{action.cookie}
		return t.sendPending(now) // challenge never resets the attempt budget
	case action.authPrepared:
		return t.sendNew(action.requests, now)
	case action.auth != nil:
		if err := t.data.install(t.generation, plan, t.peer, action.auth.Child); err != nil {
			t.failed = err
			return err
		}
		t.child, t.phase, t.pending = action.auth.Child, 3, nil
		t.probeAt, t.keepaliveAt = now.Add(20*time.Second), now.Add(15*time.Second)
		t.mobike = action.auth.MOBIKE
		if t.mobike {
			t.probeAt = now // Establish a NAT baseline while the path is known to work.
		}
		// This finite bound is replaced only by successful rekey, never traffic.
		t.expiresAt = now.Add(10 * time.Minute)
		t.rekeyAt = now.Add(5 * time.Minute)
		t.ikeRekeyAt, t.ikeExpiresAt = now.Add(30*time.Minute), now.Add(time.Hour)
		t.child.Keys = ike.ChildKeys{}
		t.observeProgress()
		t.observeEvent("authenticated", now, nil)
	}
	return nil
}
