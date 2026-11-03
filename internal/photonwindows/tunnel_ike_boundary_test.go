package photonwindows

import (
	"net/netip"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/photonclient/ike"
)

func TestPendingChildActivationRespectsHardLifetime(t *testing.T) {
	for _, lifetime := range []string{"IKE", "CHILD"} {
		t.Run(lifetime, func(t *testing.T) {
			for _, atDeadline := range []bool{false, true} {
				data, plan, endpoint, active := dataplaneFixture(t)
				pending := dataplaneChild(513)
				if err := data.install(data.generation, plan, endpoint, pending); err != nil {
					t.Fatal(err)
				}
				deadline := time.Now()
				tunnel := gatewayTunnel{
					phase: 3, data: data, child: active, pendingChildSPI: pending.InitiatorSPI,
					ikeExpiresAt: deadline.Add(time.Minute), expiresAt: deadline.Add(time.Minute),
				}
				if lifetime == "IKE" {
					tunnel.ikeExpiresAt = deadline
				} else {
					tunnel.expiresAt = deadline
				}
				expires := tunnel.expiresAt
				at := deadline
				if !atDeadline {
					at = at.Add(-time.Nanosecond)
				}
				tunnel.observeData(dataplaneCompletion{
					job:    dataplaneJob{ctx: data.generationCtx, generation: data.generation, sa: data.sas[pending.InitiatorSPI]},
					packet: dataplanePacket(false),
				}, plan, at)
				if atDeadline {
					if data.active.spi != active.InitiatorSPI || tunnel.pendingChildSPI != pending.InitiatorSPI || tunnel.expiresAt != expires {
						t.Fatal("authenticated packet changed CHILD state at hard expiry")
					}
				} else if data.active.spi != pending.InitiatorSPI || tunnel.pendingChildSPI != 0 || !tunnel.expiresAt.After(expires) {
					t.Fatal("valid authenticated packet did not activate the pending CHILD")
				}
			}
		})
	}
}

func TestEstablishedPeerChildRechecksSelectorsBeforeInstall(t *testing.T) {
	for _, side := range []string{"local", "remote"} {
		t.Run(side, func(t *testing.T) {
			data, plan, endpoint, active := dataplaneFixture(t)
			tunnel := gatewayTunnel{phase: 3, generation: data.generation, peer: endpoint, data: data, child: active}
			// Assume the worker accepted this request using an earlier, wider
			// active CHILD. The current sender permits only its exact hosts.
			offered := dataplaneChild(513)
			if side == "local" {
				offered.LocalSelectors[0].EndAddr = netip.MustParseAddr("10.0.0.10")
			} else {
				offered.RemoteSelectors[0].EndAddr = netip.MustParseAddr("10.0.0.10")
			}
			prepared := establishedExchangeResult{
				header:   ike.Header{ExchangeType: ike.ExchangeCreateChild},
				exchange: &ike.ExchangeResult{Child: &ike.ChildExchangeResult{Child: offered}},
			}
			err := tunnel.applyEstablishedExchange(establishedExchangeInput{}, prepared, plan, time.Now())
			if err == nil || tunnel.failed != err {
				t.Fatal("late wider selectors did not fail closed")
			}
			if len(data.sas) != 1 || data.active.spi != active.InitiatorSPI {
				t.Fatal("late wider selectors changed the installed CHILDs")
			}
		})
	}
}
