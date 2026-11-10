package inspect

import (
	"testing"
	"time"
)

func TestBuildPeerLifecycleDebugNormalizesConfigAndCopiesPeers(t *testing.T) {
	peers := []PeerStatusInfo{{PeerID: "node-a", State: PeerStateActive}}
	view := BuildPeerLifecycleDebug(PeerLifecycleConfig{}, peers)
	peers[0].PeerID = "changed"

	def := DefaultPeerLifecycleConfig()
	if view.Config.StaleAfter != def.StaleAfter || view.Config.OfflineAfter != def.OfflineAfter || view.Config.CleanupAfter != def.CleanupAfter {
		t.Fatalf("config = %+v, want defaults %+v", view.Config, def)
	}
	if !view.Config.KeepSAWhileStale {
		t.Fatalf("KeepSAWhileStale = false, want default true")
	}
	if got := view.Peers[0].PeerID; got != "node-a" {
		t.Fatalf("peer copied = %q, want node-a", got)
	}
}

func TestBuildPeerLifecycleStatusPriorityAndThresholds(t *testing.T) {
	now := time.Unix(2000, 0)
	cfg := DefaultPeerLifecycleConfig()

	tests := []struct {
		name   string
		input  PeerLifecycleInput
		state  string
		reason string
	}{
		{
			name: "revoked overrides active link",
			input: PeerLifecycleInput{
				StateAvailable: true,
				PeerZoneKnown:  true,
				ZoneRevoked:    true,
				UpLinks:        1,
			},
			state:  PeerStateRevoked,
			reason: "zone_revoked",
		},
		{
			name: "policy denied from reconcile skip",
			input: PeerLifecycleInput{
				StateAvailable:     true,
				PeerZoneKnown:      true,
				HasIPsecConfig:     true,
				PolicyDeniedReason: "mesh_policy_denied",
			},
			state:  PeerStatePolicyDenied,
			reason: "mesh_policy_denied",
		},
		{
			name: "active link",
			input: PeerLifecycleInput{
				StateAvailable: true,
				PeerZoneKnown:  true,
				UpLinks:        1,
				ActualLinks:    1,
				DesiredLinks:   1,
			},
			state:  PeerStateActive,
			reason: "link_up",
		},
		{
			name: "connecting link",
			input: PeerLifecycleInput{
				StateAvailable: true,
				PeerZoneKnown:  true,
				ActualLinks:    1,
				DesiredLinks:   1,
			},
			state:  PeerStateConnecting,
			reason: "link_connecting",
		},
		{
			name: "desired link pending",
			input: PeerLifecycleInput{
				StateAvailable: true,
				PeerZoneKnown:  true,
				DesiredLinks:   1,
			},
			state:  PeerStateDiscovered,
			reason: "link_pending",
		},
		{
			name: "stale threshold",
			input: PeerLifecycleInput{
				StateAvailable: true,
				PeerZoneKnown:  true,
				LastSyncUnix:   now.Add(-20 * time.Minute).Unix(),
			},
			state:  PeerStateStale,
			reason: "stale_after_exceeded",
		},
		{
			name: "offline threshold",
			input: PeerLifecycleInput{
				StateAvailable: true,
				PeerZoneKnown:  true,
				LastSyncUnix:   now.Add(-13 * time.Hour).Unix(),
			},
			state:  PeerStateOffline,
			reason: "offline_after_exceeded",
		},
		{
			name: "committed tunnel suspension",
			input: PeerLifecycleInput{
				StateAvailable:  true,
				PeerZoneKnown:   true,
				TunnelSuspended: true,
			},
			state:  PeerStateOffline,
			reason: "cleanup_after_exceeded",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.input.PeerID = "node-b.catofes."
			tc.input.PeerZone = "node-b.catofes."
			tc.input.Now = now
			tc.input.Config = cfg
			got := BuildPeerLifecycleStatus(tc.input)
			if got.State != tc.state || got.Reason != tc.reason {
				t.Fatalf("state/reason = %s/%s, want %s/%s; got=%+v", got.State, got.Reason, tc.state, tc.reason, got)
			}
		})
	}
}

func TestBuildPeerLifecycleStatusOverlayRefinesIPsecRecordPeers(t *testing.T) {
	got := BuildPeerLifecycleStatus(PeerLifecycleInput{
		PeerID:              "node-b.catofes.",
		PeerZone:            "node-b.catofes.",
		StateAvailable:      true,
		PeerZoneKnown:       true,
		HasIPsecConfig:      true,
		HasOverlayConfig:    true,
		PeerHasIPsecRecords: true,
		Now:                 time.Unix(2000, 0),
		Config:              DefaultPeerLifecycleConfig(),
	})
	if got.State != PeerStateDiscovered || got.Reason != "has_ipsec_records_no_link" {
		t.Fatalf("state/reason = %s/%s, want discovered/has_ipsec_records_no_link", got.State, got.Reason)
	}
}

func TestPeerLifecycleHelpers(t *testing.T) {
	if !PeerStatusRequiresCleanup(PeerStatusInfo{State: PeerStateRevoked}) {
		t.Fatal("revoked peer should require cleanup")
	}
	if !PeerStatusRequiresCleanup(PeerStatusInfo{State: PeerStateOffline, Reason: "cleanup_after_exceeded"}) {
		t.Fatal("cleanup-after offline peer should require cleanup")
	}
	if PeerStatusRequiresCleanup(PeerStatusInfo{State: PeerStateOffline, Reason: "offline_after_exceeded"}) {
		t.Fatal("ordinary offline peer should not require cleanup")
	}
}
