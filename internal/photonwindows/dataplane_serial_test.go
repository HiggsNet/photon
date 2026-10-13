package photonwindows

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"runtime"
	"testing"

	"github.com/HiggsNet/photon/internal/photonclient/babel"
	"github.com/HiggsNet/photon/internal/photonclient/esp"
	"github.com/HiggsNet/photon/internal/photonclient/ike"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func serialDataplaneFixture(t *testing.T) (*gatewayDataplane, GatewayPlan, ike.ChildResult, []byte) {
	t.Helper()
	d := newSerialGatewayDataplane(t.Context())
	t.Cleanup(d.close)
	d.reset(10)
	plan := GatewayPlan{Selected: &GatewaySelection{Zone: "gateway.test.", Identity: "gateway.test.", PublicKey: bytes.Repeat([]byte{1}, 32), Fingerprint: "pin", Contact: ipsec.ContactPoint{Address: "192.0.2.1", IKEPort: 500, NATTPort: 4500}}}
	child := dataplaneChild(768)
	controlSelectors := []ike.TrafficSelector{{StartAddr: netip.MustParseAddr("::"), EndAddr: netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), EndPort: 65535}}
	child.LocalSelectors = append(child.LocalSelectors, controlSelectors...)
	child.RemoteSelectors = append(child.RemoteSelectors, controlSelectors...)
	if err := d.install(10, plan, netip.MustParseAddrPort("192.0.2.1:4500"), child); err != nil {
		t.Fatal(err)
	}
	payload, err := babel.Encode([]babel.Message{{Type: babel.TLVHello, Seqno: 1, Interval: 400}})
	if err != nil {
		t.Fatal(err)
	}
	control, err := babel.BuildPacket(netip.MustParseAddr("fe80::1"), netip.MustParseAddr("fe80::2"), payload)
	if err != nil {
		t.Fatal(err)
	}
	return d, plan, child, control
}

// A queued Babel job must hold plaintext until the serial owner chooses it.
// Allocating its ESP sequence before a business burst would make this genuine
// Hello fall outside the peer's 64-packet replay window before it was delivered.
func TestDataplaneSerialDeferredControlSurvivesBusinessBurst(t *testing.T) {
	d, plan, child, control := serialDataplaneFixture(t)
	original := bytes.Clone(control)
	if !d.submitOutbound(10, plan, control, dataplaneAllow) {
		t.Fatal("Babel control was not queued")
	}
	control[len(control)-1] ^= 1 // producer may reuse the input after submission
	peer, err := esp.NewReceiver(child.ResponderSPI, child.Keys.InitiatorToResponder)
	if err != nil {
		t.Fatal(err)
	}
	for n := uint32(1); n <= 128; n++ {
		result, ok := d.processOutbound(10, plan, dataplanePacket(true), dataplaneAllow)
		if !ok || result.err != nil {
			t.Fatal("direct business encryption failed", result.err)
		}
		wire, _, outbound, accepted := d.accept(result, plan, dataplaneAllow)
		if !accepted || !outbound || binary.BigEndian.Uint32(wire[4:8]) != n {
			t.Fatal("queued control allocated a sequence before its owner turn")
		}
		plain, err := peer.Open(wire)
		if err != nil || !bytes.Equal(plain, dataplanePacket(true)) {
			t.Fatal("business burst did not reach the real ESP receiver", err)
		}
		runtime.Gosched() // background workers must not steal a serial owner's job
	}
	if len(d.jobs) != 1 || len(d.completed) != 0 {
		t.Fatal("serial control work escaped into a background worker")
	}
	result := executeDataplaneJob(<-d.jobs)
	wire, _, outbound, accepted := d.accept(result, plan, dataplaneAllow)
	if !accepted || !outbound || binary.BigEndian.Uint32(wire[4:8]) != 129 {
		t.Fatal("owner did not seal deferred control after the business burst", result.err)
	}
	plain, err := peer.Open(wire)
	if err != nil || !bytes.Equal(plain, original) {
		t.Fatal("deferred genuine Babel control was stale or lost its owned input", err)
	}
}

func TestDataplaneSerialControlQueueRemainsBounded(t *testing.T) {
	d, plan, _, control := serialDataplaneFixture(t)
	for range dataplaneQueueSize {
		if !d.submitOutbound(10, plan, control, dataplaneAllow) {
			t.Fatal("serial queue rejected a packet within its bound")
		}
		runtime.Gosched()
	}
	if d.submitOutbound(10, plan, control, dataplaneAllow) || len(d.jobs) != dataplaneQueueSize || len(d.completed) != 0 {
		t.Fatal("serial control queue lost owner isolation or bounded backpressure")
	}
}

func TestDataplaneSerialCancelledControlDoesNotAllocateSequence(t *testing.T) {
	d, plan, _, control := serialDataplaneFixture(t)
	if !d.submitOutbound(10, plan, control, dataplaneAllow) {
		t.Fatal("control submission failed")
	}
	job := <-d.jobs
	d.cancelGeneration()
	result := executeDataplaneJob(job)
	if !errors.Is(result.err, context.Canceled) || result.packet != nil {
		t.Fatal("cancelled owner work performed crypto or lost its error", result.err)
	}
	if wire, _, _, accepted := d.accept(result, plan, dataplaneAllow); accepted || wire != nil {
		t.Fatal("cancelled queued control escaped the completion gate")
	}
	// Inspect the original sender, without reconstructing an SA or resetting its
	// nonce state: cancelled plaintext must not consume its first sequence.
	wire, err := job.sa.sender.Seal(control)
	if err != nil || binary.BigEndian.Uint32(wire[4:8]) != 1 {
		t.Fatal("cancelled job consumed an ESP nonce", err)
	}
}

func TestDataplaneSerialControlUsesCurrentDeliveryGate(t *testing.T) {
	for _, change := range []string{"revocation", "generation", "active CHILD", "route"} {
		t.Run(change, func(t *testing.T) {
			d, plan, child, control := serialDataplaneFixture(t)
			if !d.submitOutbound(10, plan, control, dataplaneAllow) {
				t.Fatal("control submission failed")
			}
			result := executeDataplaneJob(<-d.jobs)
			if result.err != nil {
				t.Fatal(result.err)
			}
			authorize := dataplaneAllow
			switch change {
			case "revocation":
				plan.Rejected = "revoked"
			case "generation":
				d.reset(11)
			case "active CHILD":
				next := dataplaneChild(child.InitiatorSPI + 1)
				next.LocalSelectors, next.RemoteSelectors = child.LocalSelectors, child.RemoteSelectors
				if err := d.install(10, plan, netip.MustParseAddrPort("192.0.2.1:4500"), next); err != nil {
					t.Fatal(err)
				}
				if err := d.activate(next.InitiatorSPI); err != nil {
					t.Fatal(err)
				}
			case "route":
				authorize = func([]byte, bool) bool { return false }
			}
			if wire, _, _, accepted := d.accept(result, plan, authorize); accepted || wire != nil {
				t.Fatal("sealed control bypassed the current owner delivery gate")
			}
		})
	}
}
