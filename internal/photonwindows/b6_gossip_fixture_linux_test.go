//go:build linux

package photonwindows

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/routing"
)

// Start the real public GossipDriver and object-pull server in the gateway
// container. The Windows snapshot deliberately lacks the gateway's signed
// Babel identity: business readiness requires receiving and persisting it over
// the published UDP/TCP endpoint, not a preloaded or local sidecar update.
func startB6GatewayGossip(t *testing.T, ctx context.Context, config *Config, contact netip.AddrPort) {
	t.Helper()
	peer := startB4AuthorityPeerAt(t, ctx, config, "0.0.0.0:5201")
	config.Gateway.BootstrapHints[0].Address = contact.String()
	disk, err := corestate.OpenBoltStore(config.State.Path, 0600, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	candidate, revision, _, found, err := disk.LoadCommon()
	if err != nil || !found || candidate == nil || candidate.Verified == nil {
		disk.Close()
		t.Fatal("load Windows gossip fixture snapshot", err)
	}
	gateway := config.Gateway.AllowedZones[0]
	if peer.state.Store().ReadView().State.Network.Zones[gateway].Records[routing.RecordKeyBabelIdentity] == nil {
		disk.Close()
		t.Fatal("gateway gossip source has no signed Babel identity")
	}
	delete(candidate.Verified.Network.Zones[gateway].Records, routing.RecordKeyBabelIdentity)
	err = disk.CommitCommon(ctx, candidate, corestate.ChangeSet{VerifiedRevision: revision + 1, NetworkChanged: true})
	closeErr := disk.Close()
	if err != nil || closeErr != nil {
		t.Fatal("persist deliberately incomplete Windows snapshot", err, closeErr)
	}
	// Public evidence only, copied separately from the signed fixture/config.
	evidence := struct {
		Gateway         string                     `json:"gateway"`
		MissingRecord   string                     `json:"missing_record"`
		InitialRevision corestate.VerifiedRevision `json:"initial_revision"`
	}{string(gateway), routing.RecordKeyBabelIdentity, revision + 1}
	data, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(config.State.Path), "gossip-evidence.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	t.Log("gateway production GossipDriver ready; Windows must receive missing signed Babel identity remotely")
}
