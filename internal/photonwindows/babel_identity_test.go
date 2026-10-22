package photonwindows

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
	"github.com/HiggsNet/photon/pkg/routing"
)

func TestEnsureBabelIdentityPublicationLeaseAndForeignOwner(t *testing.T) {
	path, _, root, _ := saveCommonState(t, 7)
	config := &Config{ManagedZone: "node-a.catofes.", TrustedRootPublicKey: root, Overlay: OverlayConfig{ID: "main"}}
	source, err := OpenState(path, config.ManagedZone, root, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	now := time.Now().Truncate(time.Second)
	id, err := source.EnsureLocalBabelIdentity(context.Background(), config, now)
	if err != nil {
		t.Fatal(err)
	}
	view := source.Store().ReadView()
	record := view.State.Network.Zones[config.ManagedZone].Records[routing.RecordKeyBabelIdentity]
	if err := photoncrypto.VerifyRecord(record, view.State.Network.Zones[config.ManagedZone].Authority, now); err != nil {
		t.Fatal(err)
	}
	if _, err := routing.ParseBabelIdentityRecord(record, now); err != nil {
		t.Fatal(err)
	}
	again, err := source.EnsureLocalBabelIdentity(context.Background(), config, now.Add(time.Minute))
	if err != nil || again != id || source.Store().VerifiedRevision() != view.Revision {
		t.Fatal("unnecessary publication or unstable ID", err)
	}
	if renewed, err := source.EnsureLocalBabelIdentity(context.Background(), config, now.Add(31*time.Minute)); err != nil || renewed != id || source.Store().VerifiedRevision() != view.Revision+1 {
		t.Fatal("lease not renewed", err)
	}
	if _, err := source.EnsureLocalBabelIdentity(context.Background(), config, now.Add(30*time.Minute)); err == nil {
		t.Fatal("future publication accepted after clock rollback")
	}
	value, _ := json.Marshal(routing.BabelIdentityRecord{Version: 1, RouterIDs: []string{"0123456789abcdef"}, ExpiresAt: now.Add(time.Hour).Unix()})
	if _, err := source.Store().ApplyLocalIntentsAtRevision(context.Background(), []corestate.LocalIntent{corestate.PutProtocolRecordIntent{Kind: corestate.ProtocolRecordBabelIdentity, Zone: config.ManagedZone, Key: routing.RecordKeyBabelIdentity, Type: routing.RecordTypeBabelIdentity, Value: value}}, now.Add(32*time.Minute), source.Store().VerifiedRevision()); err != nil {
		t.Fatal(err)
	}
	if _, err := source.EnsureLocalBabelIdentity(context.Background(), config, now.Add(33*time.Minute)); err == nil {
		t.Fatal("foreign ID was silently replaced")
	}
}
