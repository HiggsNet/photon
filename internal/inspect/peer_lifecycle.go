package inspect

import (
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

const (
	PeerStateEligible     = "eligible"
	PeerStateDiscovered   = "discovered"
	PeerStateConnecting   = "connecting"
	PeerStateActive       = "active"
	PeerStateStale        = "stale"
	PeerStateOffline      = "offline"
	PeerStatePolicyDenied = "policy_denied"
	PeerStateConfigError  = "config_error"
	PeerStateRevoked      = "revoked"
)

// PeerLifecycleConfig holds stale/offline/cleanup thresholds. Zero values use
// defaults from DefaultPeerLifecycleConfig().
type PeerLifecycleConfig struct {
	StaleAfter       time.Duration `yaml:"stale_after" json:"stale_after,omitempty"`
	OfflineAfter     time.Duration `yaml:"offline_after" json:"offline_after,omitempty"`
	CleanupAfter     time.Duration `yaml:"cleanup_after" json:"cleanup_after,omitempty"`
	KeepSAWhileStale bool          `yaml:"keep_sa_while_stale" json:"keep_sa_while_stale,omitempty"`
}

type PeerLifecycleDebugView struct {
	Config PeerLifecycleDebugConfig
	Peers  []PeerStatusInfo
}

type PeerLifecycleDebugConfig struct {
	StaleAfter       time.Duration
	OfflineAfter     time.Duration
	CleanupAfter     time.Duration
	KeepSAWhileStale bool
}

type PeerLifecycleInput struct {
	PeerID               string
	PeerZone             zone.ZonePath
	StateAvailable       bool
	PeerZoneKnown        bool
	ZoneRevoked          bool
	HasIPsecConfig       bool
	HasOverlayConfig     bool
	PeerHasIPsecRecords  bool
	PolicyDeniedReason   string
	PolicyDeniedDetail   string
	LastSyncUnix         int64
	ObservedLastSeenUnix int64
	UpLinks              int
	ActualLinks          int
	DesiredLinks         int
	LastTransitionUnix   int64
	Now                  time.Time
	Config               PeerLifecycleConfig
}

func DefaultPeerLifecycleConfig() PeerLifecycleConfig {
	return PeerLifecycleConfig{
		StaleAfter:       15 * time.Minute,
		OfflineAfter:     12 * time.Hour,
		CleanupAfter:     48 * time.Hour,
		KeepSAWhileStale: true,
	}
}

func NormalizePeerLifecycleConfig(cfg PeerLifecycleConfig) PeerLifecycleConfig {
	def := DefaultPeerLifecycleConfig()
	out := cfg
	allZero := out.StaleAfter <= 0 && out.OfflineAfter <= 0 && out.CleanupAfter <= 0
	if allZero && !out.KeepSAWhileStale {
		out.KeepSAWhileStale = def.KeepSAWhileStale
	}
	if out.StaleAfter <= 0 {
		out.StaleAfter = def.StaleAfter
	}
	if out.OfflineAfter <= 0 {
		out.OfflineAfter = def.OfflineAfter
	}
	if out.CleanupAfter <= 0 {
		out.CleanupAfter = def.CleanupAfter
	}
	return out
}

func BuildPeerLifecycleDebug(config PeerLifecycleConfig, peers []PeerStatusInfo) PeerLifecycleDebugView {
	cfg := NormalizePeerLifecycleConfig(config)
	return PeerLifecycleDebugView{
		Config: PeerLifecycleDebugConfig{
			StaleAfter:       cfg.StaleAfter,
			OfflineAfter:     cfg.OfflineAfter,
			CleanupAfter:     cfg.CleanupAfter,
			KeepSAWhileStale: cfg.KeepSAWhileStale,
		},
		Peers: append([]PeerStatusInfo(nil), peers...),
	}
}

func BuildPeerLifecycleStatus(input PeerLifecycleInput) PeerStatusInfo {
	info := PeerStatusInfo{
		PeerID: input.PeerID,
		Zone:   input.PeerZone,
	}
	if !input.StateAvailable {
		info.State = PeerStateConfigError
		info.Reason = "state_nil"
		return info
	}
	cfg := NormalizePeerLifecycleConfig(input.Config)
	info.LastSeenUnix = max(input.LastSyncUnix, input.ObservedLastSeenUnix)
	info.LastSyncUnix = input.LastSyncUnix
	info.UpLinks = input.UpLinks
	info.ActualLinks = input.ActualLinks
	info.DesiredLinks = input.DesiredLinks
	info.LastReconcileUnix = input.LastTransitionUnix

	if input.ZoneRevoked {
		info.State = PeerStateRevoked
		info.Reason = "zone_revoked"
		return info
	}
	if !input.PeerZoneKnown {
		info.State = PeerStateConfigError
		info.Reason = "peer_zone_unknown"
		return info
	}
	lastActive := input.LastSyncUnix
	if input.ObservedLastSeenUnix > 0 && input.ObservedLastSeenUnix > lastActive {
		lastActive = input.ObservedLastSeenUnix
	}
	if lastActive != 0 {
		lastActiveTime := time.Unix(lastActive, 0)
		if input.Now.Sub(lastActiveTime) >= cfg.CleanupAfter {
			// cleanup_after is an owner-resource retention limit, so it must
			// override stale LinkInstances/desired snapshots that are precisely
			// the resources the daemon is about to remove.
			info.State = PeerStateOffline
			info.Reason = "cleanup_after_exceeded"
			info.OfflineSinceUnix = lastActive
			info.NextCleanupUnix = input.Now.Unix()
			return info
		}
	}
	if input.DesiredLinks == 0 && input.HasIPsecConfig {
		if input.PolicyDeniedReason != "" {
			info.State = PeerStatePolicyDenied
			info.Reason = input.PolicyDeniedReason
			info.Detail = input.PolicyDeniedDetail
			return info
		}
		info.State = PeerStateEligible
		info.Reason = "no_ipsec_records"
		if input.HasOverlayConfig && input.PeerHasIPsecRecords {
			info.State = PeerStateDiscovered
			info.Reason = "has_ipsec_records_no_link"
		}
		return info
	}
	if input.UpLinks > 0 {
		info.State = PeerStateActive
		info.Reason = "link_up"
		return info
	}
	if input.ActualLinks > 0 {
		info.State = PeerStateConnecting
		info.Reason = "link_connecting"
		return info
	}
	if input.DesiredLinks > 0 {
		info.State = PeerStateDiscovered
		info.Reason = "link_pending"
		return info
	}

	if lastActive == 0 {
		if input.HasIPsecConfig {
			info.State = PeerStateEligible
			info.Reason = "no_ipsec_records"
		} else {
			info.State = PeerStateEligible
			info.Reason = "no_overlay_config"
		}
		return info
	}
	lastActiveTime := time.Unix(lastActive, 0)
	elapsed := input.Now.Sub(lastActiveTime)
	info.OfflineSinceUnix = lastActive
	if elapsed >= cfg.OfflineAfter {
		info.State = PeerStateOffline
		info.Reason = "offline_after_exceeded"
		info.NextCleanupUnix = lastActiveTime.Add(cfg.CleanupAfter).Unix()
		return info
	}
	if elapsed >= cfg.StaleAfter {
		info.State = PeerStateStale
		info.Reason = "stale_after_exceeded"
		info.NextCleanupUnix = lastActiveTime.Add(cfg.CleanupAfter).Unix()
		return info
	}
	if input.HasIPsecConfig {
		info.State = PeerStateDiscovered
		info.Reason = "recently_seen_no_link"
	} else {
		info.State = PeerStateEligible
		info.Reason = "no_overlay_config"
	}
	return info
}

func PeerStatusRequiresCleanup(info PeerStatusInfo) bool {
	switch info.State {
	case PeerStateRevoked:
		return true
	case PeerStateOffline:
		return info.Reason == "cleanup_after_exceeded"
	default:
		return false
	}
}
