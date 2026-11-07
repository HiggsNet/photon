package photonwindows

import (
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/HiggsNet/photon/internal/photonclient/ike"
)

var errMOBIKEPathUnavailable = errors.New("tunnel: MOBIKE path unavailable")

type ikeTimerKind uint8

const (
	ikeTimerDelete ikeTimerKind = iota + 1
	ikeTimerRekey
	ikeTimerChild
	ikeTimerProbe
	ikeTimerMOBIKEProbe
	ikeTimerMOBIKEUpdate
)

type ikeTimerRequest struct {
	kind          ikeTimerKind
	session       *ike.Initiator
	spi           uint32
	child         ike.ChildExchangeConfig
	local, remote netip.AddrPort
	socket        *packetSockets
	mobikeEpoch   uint64
}

func (t *gatewayTunnel) requestMOBIKE(now time.Time) {
	t.mobikeEpoch++
	if t.mobikeDeadline.IsZero() {
		t.mobikeDeadline = now.Add(5 * time.Second)
	}
}

func (t *gatewayTunnel) dueIKERequest(now time.Time) ikeTimerRequest {
	request := ikeTimerRequest{session: t.session}
	switch {
	case t.mobikeEpoch != t.mobikeSent:
		request.kind, request.mobikeEpoch = ikeTimerMOBIKEUpdate, t.mobikeEpoch
	case t.deleteSPI != 0 && !now.Before(t.deleteAt):
		request.kind, request.spi = ikeTimerDelete, t.deleteSPI
	case !now.Before(t.ikeRekeyAt):
		request.kind = ikeTimerRekey
	case !now.Before(t.rekeyAt):
		request.kind = ikeTimerChild
		request.child = ike.ChildExchangeConfig{
			Child:    ike.ChildConfig{LocalSelectors: t.child.LocalSelectors, RemoteSelectors: t.child.RemoteSelectors},
			RekeySPI: t.child.InitiatorSPI, DHGroup: t.rekeyGroup,
		}
	case !now.Before(t.probeAt):
		request.kind = ikeTimerProbe
		if t.mobike {
			request.kind = ikeTimerMOBIKEProbe
		}
	}
	if request.kind == ikeTimerMOBIKEProbe || request.kind == ikeTimerMOBIKEUpdate {
		request.local, request.remote = t.socket.LocalAddr().AddrPort(), t.peer
		request.socket = t.socket
	}
	return request
}

func prepareIKETimer(request ikeTimerRequest) ([][]byte, error) {
	session := request.session
	var err error
	switch request.kind {
	case ikeTimerDelete:
		_, err = session.ChildDeleteRequest([]uint32{request.spi})
	case ikeTimerRekey:
		_, err = session.IKERekeyRequest()
	case ikeTimerChild:
		request.child.Child.InitiatorSPI, err = freshChildSPI()
		if err == nil {
			_, err = session.ChildRequest(request.child)
		}
	case ikeTimerProbe:
		_, err = session.InformationalRequest()
	case ikeTimerMOBIKEProbe, ikeTimerMOBIKEUpdate:
		var local netip.AddrPort
		local, err = request.socket.outerLocal(request.local, request.remote)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", errMOBIKEPathUnavailable, err)
		}
		_, err = session.MOBIKERequest(local, request.remote, request.kind == ikeTimerMOBIKEUpdate)
	}
	if err != nil {
		return nil, err
	}
	return session.PendingRequestPackets(1196)
}

func (t *gatewayTunnel) waitForMOBIKEPath(now time.Time) {
	if t.mobikeDeadline.IsZero() {
		t.requestMOBIKE(now)
	}
}

func (t *gatewayTunnel) applyIKETimer(request ikeTimerRequest, packets [][]byte, now time.Time) error {
	if request.kind == ikeTimerDelete {
		t.deleteSPI = 0
	}
	if request.kind == ikeTimerMOBIKEUpdate {
		t.mobikeSent = request.mobikeEpoch
	}
	t.pending, t.attempts = packets, 0
	return t.sendPending(now)
}
