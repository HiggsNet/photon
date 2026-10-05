package ike

import (
	"errors"
	"testing"
)

func configForExistingChild(child ChildResult, newSPI uint32) ChildExchangeConfig {
	return ChildExchangeConfig{Child: ChildConfig{InitiatorSPI: newSPI, LocalSelectors: child.LocalSelectors, RemoteSelectors: child.RemoteSelectors}, RekeySPI: child.InitiatorSPI}
}

func TestChildLostSimultaneousRequestSurvivesPeerEarlyDelete(t *testing.T) {
	a := informationalFixture(t)
	b := mirrorIKE(a)
	oldA := a.auth.child.InitiatorSPI
	oldB := a.children[oldA].result.ResponderSPI
	oldAChild, _ := a.Child(oldA)
	oldBChild, _ := b.Child(oldB)
	lost, err := a.ChildRequest(configForExistingChild(oldAChild, 0x11223344))
	if err != nil {
		t.Fatal(err)
	}
	peerRequest, err := b.ChildRequest(configForExistingChild(oldBChild, 0x55667788))
	if err != nil {
		t.Fatal(err)
	}
	reply, result, err := a.HandleChildRequest(peerRequest, configForExistingChild(oldAChild, 0x22334455))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.HandleChildResponse(reply); err != nil {
		t.Fatal(err)
	}
	before, err := a.ResolveChildRekey(oldA)
	if err != nil || !before.Pending || before.SurvivingSPI != 0 {
		t.Fatal("activated peer rekey before readiness proof")
	}
	peerDelete, err := b.ChildDeleteRequest([]uint32{oldB})
	if err != nil {
		t.Fatal(err)
	}
	deleteReply, deleted, err := a.HandleChildDelete(peerDelete)
	if err != nil || len(deleted.Removed) != 1 || deleted.Removed[0] != oldA {
		t.Fatal("early peer Delete failed", err)
	}
	provisional, err := a.ResolveChildRekey(oldA)
	if err != nil || !provisional.Pending || provisional.SurvivingSPI != result.Child.InitiatorSPI || provisional.DeleteSPI != 0 || provisional.LocalInitiated || a.PendingRequest() == nil {
		t.Fatal("peer replacement unusable after old Delete", err)
	}
	if _, _, err := b.HandleChildDelete(deleteReply); err != nil {
		t.Fatal(err)
	}
	// Our delayed request now arrives at a peer which has removed the old SA.
	rejection, created, err := b.HandleChildRequest(lost, ChildExchangeConfig{})
	if err != nil || created != nil || rejection == nil {
		t.Fatal("late rekey did not produce NOT_FOUND", err)
	}
	_, err = a.HandleChildResponse(rejection)
	var refusal *ChildExchangeError
	if !errors.As(err, &refusal) || refusal.Notification != NotifyChildNotFound || refusal.IKERekey || refusal.RekeySPI != oldA || refusal.RemovedSPI != 0 {
		t.Fatalf("wrong late rekey refusal: %v", err)
	}
	final, err := a.ResolveChildRekey(oldA)
	if err != nil || final.Pending || final.SurvivingSPI != provisional.SurvivingSPI || final.LocalInitiated || a.PendingRequest() != nil {
		t.Fatal("late refusal lost established peer replacement", err)
	}
}

func TestChildResolutionReportsInitiatorAndIKERefusalType(t *testing.T) {
	a := informationalFixture(t)
	b := mirrorIKE(a)
	oldA := a.auth.child.InitiatorSPI
	oldAChild, _ := a.Child(oldA)
	oldB := oldAChild.ResponderSPI
	oldBChild, _ := b.Child(oldB)
	request, err := a.ChildRequest(configForExistingChild(oldAChild, 0x11223344))
	if err != nil {
		t.Fatal(err)
	}
	reply, _, err := b.HandleChildRequest(request, configForExistingChild(oldBChild, 0x55667788))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.HandleChildResponse(reply); err != nil {
		t.Fatal(err)
	}
	ar, err := a.ResolveChildRekey(oldA)
	if err != nil || !ar.LocalInitiated {
		t.Fatal("local winner not marked")
	}
	br, err := b.ResolveChildRekey(oldB)
	if err != nil || br.LocalInitiated {
		t.Fatal("peer winner marked local")
	}
	// A busy peer returns TEMPORARY_FAILURE to IKE rekey. The caller must back
	// off its IKE timer, never downgrade a CHILD DH policy or retry each tick.
	a = informationalFixture(t)
	b = mirrorIKE(a)
	oldBChild, _ = b.Child(a.children[a.auth.child.InitiatorSPI].result.ResponderSPI)
	if _, err := b.ChildRequest(configForExistingChild(oldBChild, 0x55667788)); err != nil {
		t.Fatal(err)
	}
	request, err = a.IKERekeyRequest()
	if err != nil {
		t.Fatal(err)
	}
	reply, _, err = b.HandleIKERekeyRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.HandleIKERekeyResponse(reply)
	var refusal *ChildExchangeError
	if !errors.As(err, &refusal) || !refusal.IKERekey || refusal.Notification != NotifyTemporaryFailure || a.PendingRequest() != nil {
		t.Fatal("IKE refusal lacks exchange identity", err)
	}
}
