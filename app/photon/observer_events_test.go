package main

import (
	"testing"

	"github.com/HiggsNet/photon/internal/observer"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

func TestObserverIDsPayloadSortsAndOmitsEmpty(t *testing.T) {
	if got := observerIDsPayload("link_ids", nil); got != nil {
		t.Errorf("empty ids payload = %v, want nil", got)
	}
	got := observerIDsPayload("link_ids", []string{"link-b", "link-a"})
	ids, ok := got["link_ids"].([]string)
	if !ok {
		t.Fatalf("link_ids type = %T, want []string", got["link_ids"])
	}
	if len(ids) != 2 || ids[0] != "link-a" || ids[1] != "link-b" {
		t.Errorf("ids = %v, want sorted [link-a link-b]", ids)
	}
}

func TestObserverLinkIDsPayload(t *testing.T) {
	d := &Daemon{StateStore: newTestDaemonStateStore(nil, nil, &linuxRuntimeState{})}
	d.linuxObservation.replaceIPsec(map[string]linkInstanceState{"link-b": {}, "link-a": {}}, nil)
	payload, ok := d.observerLinkIDsPayload().(map[string]any)
	if !ok {
		t.Fatal("observerLinkIDsPayload should return a map payload")
	}
	ids, ok := payload["link_ids"].([]string)
	if !ok || len(ids) != 2 || ids[0] != "link-a" || ids[1] != "link-b" {
		t.Errorf("link_ids = %v, want sorted [link-a link-b]", payload["link_ids"])
	}
}

func TestObserverLinkIDsPayloadEmptyState(t *testing.T) {
	d := &Daemon{StateStore: newTestDaemonStateStore(nil, nil, nil)}
	if got := d.observerLinkIDsPayload(); got != nil {
		t.Errorf("payload = %v, want nil with no link instances", got)
	}
}

func TestObserverPeerIDsPayload(t *testing.T) {
	checkpoint := &corestate.GossipCheckpoint{Peers: map[string]corestate.PeerCheckpoint{
		"peer-b": {LastSyncUnix: 1},
		"peer-a": {LastSyncUnix: 1},
	}}
	d := &Daemon{StateStore: newTestDaemonStateStore(nil, checkpoint, nil)}
	payload, ok := d.observerPeerIDsPayload().(map[string]any)
	if !ok {
		t.Fatal("observerPeerIDsPayload should return a map payload")
	}
	ids, ok := payload["peer_ids"].([]string)
	if !ok || len(ids) != 2 || ids[0] != "peer-a" || ids[1] != "peer-b" {
		t.Errorf("peer_ids = %v, want sorted [peer-a peer-b]", payload["peer_ids"])
	}
}

func TestObserverHealthLinkIDsPayloadWithoutManager(t *testing.T) {
	d := &Daemon{}
	if got := d.observerHealthLinkIDsPayload(); got != nil {
		t.Errorf("payload = %v, want nil without health manager", got)
	}
}

func TestNotifyObserverBroadcastsPayloadWithTimestamp(t *testing.T) {
	hub := observer.NewHub()
	ch, unsubscribe := hub.Subscribe()
	defer unsubscribe()
	d := &Daemon{observerHub: hub}
	d.notifyObserver("link_updated", map[string]any{"link_ids": []string{"link-a"}})
	select {
	case received := <-ch:
		if received.Type != "link_updated" {
			t.Errorf("type = %q, want link_updated", received.Type)
		}
		if received.Time == 0 {
			t.Error("hub should fill the event timestamp")
		}
		payload, ok := received.Payload.(map[string]any)
		if !ok {
			t.Fatalf("payload type = %T, want map", received.Payload)
		}
		ids, ok := payload["link_ids"].([]string)
		if !ok || len(ids) != 1 || ids[0] != "link-a" {
			t.Errorf("payload link_ids = %v, want [link-a]", payload["link_ids"])
		}
	default:
		t.Fatal("event not received")
	}
}

func TestNotifyStateChangedBroadcastsIDPayloads(t *testing.T) {
	runtime := &linuxRuntimeState{}
	checkpoint := &corestate.GossipCheckpoint{Peers: map[string]corestate.PeerCheckpoint{
		"peer-a": {LastSyncUnix: 1},
	}}
	hub := observer.NewHub()
	d := &Daemon{
		StateStore:  newTestDaemonStateStore(nil, checkpoint, runtime),
		observerHub: hub,
		// Sync and Linux runtime are nil: common peer notifications remain,
		// while platform link/route notifications must not be fabricated.
	}
	ch, unsubscribe := hub.Subscribe()
	defer unsubscribe()
	d.notifyStateChanged()
	var linkEvent, peerEvent *observer.Event
	for range 6 {
		select {
		case ev := <-ch:
			switch ev.Type {
			case "link_updated":
				linkEvent = &ev
			case "peer_updated":
				peerEvent = &ev
			}
		default:
		}
	}
	if linkEvent != nil {
		t.Fatalf("link_updated event emitted without Linux runtime: %+v", linkEvent)
	}
	if peerEvent == nil {
		t.Fatal("peer_updated event not received")
	}
	peerPayload, peerOK := peerEvent.Payload.(map[string]any)
	if !peerOK {
		t.Fatalf("peer_updated payload type = %T, want map", peerEvent.Payload)
	}
	peerIDs, ok := peerPayload["peer_ids"].([]string)
	if !ok || len(peerIDs) != 1 || peerIDs[0] != "peer-a" {
		t.Errorf("peer_updated payload = %v, want peer_ids [peer-a]", peerPayload)
	}
}
