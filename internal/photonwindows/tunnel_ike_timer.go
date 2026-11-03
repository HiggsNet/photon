package photonwindows

import (
	"time"

	"github.com/HiggsNet/photon/internal/photonclient/ike"
)

type ikeTimerKind uint8

const (
	ikeTimerDelete ikeTimerKind = iota + 1
	ikeTimerRekey
	ikeTimerChild
	ikeTimerProbe
)

type ikeTimerRequest struct {
	kind    ikeTimerKind
	session *ike.Initiator
	spi     uint32
	child   ike.ChildExchangeConfig
}

func (t *gatewayTunnel) dueIKERequest(now time.Time) ikeTimerRequest {
	request := ikeTimerRequest{session: t.session}
	switch {
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
	}
	if err != nil {
		return nil, err
	}
	return session.PendingRequestPackets(1196)
}

func (t *gatewayTunnel) applyIKETimer(request ikeTimerRequest, packets [][]byte, now time.Time) error {
	if request.kind == ikeTimerDelete {
		t.deleteSPI = 0
	}
	t.pending, t.attempts = packets, 0
	return t.sendPending(now)
}
