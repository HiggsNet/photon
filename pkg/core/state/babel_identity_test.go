package state

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/routing"
)

func TestBabelIdentityTypedPublicationRejectsInvalidLease(t *testing.T) {
	now := time.Unix(1000, 0)
	network, _, private, _ := managedAuthorityFixture(t, true)
	store := NewStore(&VerifiedState{ManagedZone: "node-a.catofes.", Network: network, IdentityPrivateKey: private}, nil, nil)
	intent := PutProtocolRecordIntent{Kind: ProtocolRecordBabelIdentity, Zone: "node-a.catofes.", Key: routing.RecordKeyBabelIdentity, Type: routing.RecordTypeBabelIdentity}
	for _, expiry := range []time.Time{now, now.Add(25 * time.Hour)} {
		intent.Value, _ = json.Marshal(routing.BabelIdentityRecord{Version: 1, RouterIDs: []string{"0123456789abcdef"}, ExpiresAt: expiry.Unix()})
		if _, err := store.ApplyLocalIntent(context.Background(), intent, now); err == nil {
			t.Fatal("invalid lease was published")
		}
		if store.VerifiedRevision() != 0 {
			t.Fatal("rejected publication changed verified state")
		}
	}
	if _, err := store.ApplyLocalIntent(context.Background(), PutRecordIntent{Zone: intent.Zone, Key: "other", Type: routing.RecordTypeBabelIdentity, Value: intent.Value}, now); !errors.Is(err, ErrReservedRecordIntent) {
		t.Fatal("generic publication bypassed typed record owner", err)
	}
}
