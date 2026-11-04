package photonwindows

import (
	"bytes"
	"testing"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

func TestMeshHostBatchPinsShapeAndCopiesBorrowedCiphertext(t *testing.T) {
	batch := meshHostBatch{wire: make([]byte, 0, 8)}
	packet := []byte{1, 2, 3, 4}
	completion := meshHostCompletion{dataplaneCompletion: dataplaneCompletion{
		job: dataplaneJob{owner: &gatewayDataplane{}, generation: 1, sa: &dataplaneSA{}}, packet: packet,
	}}
	batch.append(completion)
	packet[0] = 9
	if !bytes.Equal(batch.wire, []byte{1, 2, 3, 4}) || !batch.canAppend(completion) {
		t.Fatal("borrowed ESP workspace changed first segment or same SA cannot join")
	}

	otherSA := completion
	otherSA.job.sa = &dataplaneSA{}
	otherOwner := completion
	otherOwner.job.owner = &gatewayDataplane{}
	staleGeneration := completion
	staleGeneration.job.generation--
	differentLength := completion
	differentLength.packet = packet[:3]
	for _, rejected := range []meshHostCompletion{otherSA, otherOwner, staleGeneration, differentLength} {
		if batch.canAppend(rejected) {
			t.Fatal("a different SA, owner, generation or length joined the batch")
		}
	}
	batch.append(completion)
	if batch.canAppend(completion) {
		t.Fatal("batch accepted more bytes than its bounded workspace")
	}
}

func TestMeshHostBatchRechecksCanceledSA(t *testing.T) {
	m, f := meshRouteFixture(t)
	f.view.State.ManagedZone = f.config.ManagedZone
	f.view.State.TrustedRootPublicKey = f.config.TrustedRootPublicKey
	store, err := corestate.RestoreStore(&corestate.CommitCandidate{Verified: f.view.State}, f.view.Revision, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	m.state = &State{common: store}
	m.policy = newMeshPolicyWorker(store)
	var inputs meshPolicyInputs
	p := m.peers["node-a.catofes."]
	if _, pending := m.policy.project(p, f.view.Revision, f.now); !pending {
		t.Fatal("initial policy was not queued")
	}
	request := <-m.policy.requests
	m.policy.finish(meshPolicyResult{request: request, projection: inputs.project(request, f.view, f.now)}, f.view.Revision, f.now)
	m.device.activeGeneration.Store(1)
	batch := meshHostBatch{wire: make([]byte, 0, 4096)}
	for range 2 {
		packet := dataplanePacket(true)
		copy(packet[12:16], []byte{10, 9, 0, 1})
		copy(packet[16:20], []byte{10, 1, 2, 3})
		completion, ok := m.sealHost(leafDevicePacket{generation: 1, packet: packet})
		if !ok || completion.err != nil {
			t.Fatalf("fixture packet rejected before cancellation: %v", completion.err)
		}
		batch.append(completion)
	}
	p.tunnel.data.cancelGeneration()
	// A stale completion reaching transport would dereference the nil
	// socket. The canceled batch must stop at the fresh gate.
	socket := m.socket
	m.socket = nil
	defer func() { m.socket = socket }()
	batch.flush(m, nil)
	if batch.count != 0 || len(batch.wire) != 0 {
		t.Fatal("discarded packets retained batch scratch")
	}
}
