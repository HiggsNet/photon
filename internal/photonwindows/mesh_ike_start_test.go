package photonwindows

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

func TestMeshIKEStartAcrossPlannerRefresh(t *testing.T) {
	for _, scenario := range []string{"metadata", "contact changed", "revision changed", "original hint expired", "canceled"} {
		t.Run(scenario, func(t *testing.T) {
			m, f := meshRouteFixture(t)
			store := corestate.NewStore(f.view.State, nil, nil)
			t.Cleanup(store.Close)
			m.state = &State{common: store}
			p := m.ordered()[0]
			m.stopPeer(p, "prepare a new attempt")
			m.ikeWrites = make(chan meshIKEWrite, meshIKEWriteQueueSize)
			p.tunnel.queueIKE = m.queueIKEWrite
			now := time.Now()
			hint := clonePacketGatewayHint(p.plan)
			hint.Revision, hint.EvaluatedAt = store.VerifiedRevision(), now.Add(-time.Second)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			request := &meshIKEStart{ctx: ctx, cancel: cancel, peer: p, config: p.config, hint: hint}
			p.starting = request
			start, err := prepareIKEStart(hint, m.socket.LocalAddr().AddrPort(), m.socket)
			if err != nil {
				t.Fatal(err)
			}
			_, private, err := ed25519.GenerateKey(nil)
			if err != nil {
				t.Fatal(err)
			}
			result := meshIKEStartResult{request: request, revision: hint.Revision, at: now.Round(0), deadline: now.Add(time.Minute),
				local: LocalTransportIdentity{ID: string(p.config.ManagedZone), PrivateKey: private}, plan: hint, start: start}
			next := clonePacketGatewayHint(hint)
			next.EvaluatedAt = now
			switch scenario {
			case "contact changed":
				next.Selected.Contact.Address = "192.0.2.200"
			case "revision changed":
				result.revision++
			case "original hint expired":
				request.hint.EvaluatedAt = now.Add(-11 * time.Second)
			case "canceled":
				p.starting = nil // The owner canceled/superseded this attempt.
			}
			p.setPlan(next)
			m.finishIKEStart(result)
			if scenario == "metadata" {
				if p.tunnel.phase != 1 || p.tunnel.session != start.session || len(m.ikeWrites) != 1 {
					t.Fatal("metadata-only refresh discarded the prepared IKE start")
				}
			} else if p.tunnel.phase != 0 || len(m.ikeWrites) != 0 {
				t.Fatal("obsolete IKE start was installed")
			}
			if !bytes.Equal(private, make([]byte, ed25519.PrivateKeySize)) {
				t.Fatal("completion retained the borrowed private key")
			}
		})
	}
}
