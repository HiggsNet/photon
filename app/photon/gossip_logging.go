package main

import (
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
)

func syncDebugLogger(config *appConfig) func(gossip.Event) {
	logger := newAppLogger(config)
	if !logger.debugEnabled() {
		return nil
	}
	return func(event gossip.Event) {
		fields := map[string]any{
			"direction": event.Direction, "peer_id": event.PeerID, "message_type": event.Type,
			"addr": event.Addr, "bytes": event.Bytes, "zones": event.Zones,
			"records": event.Records, "duration_ms": event.Duration.Milliseconds(),
		}
		if event.Reason != "" {
			fields["reject_reason"] = event.Reason
		}
		if event.Error != "" {
			fields["error"] = event.Error
		}
		if event.QuotaRequestedBytes > 0 || event.QuotaRequestedObjects > 0 {
			fields["quota_requested_bytes"] = event.QuotaRequestedBytes
			fields["quota_requested_objects"] = event.QuotaRequestedObjects
			fields["quota_available_bytes"] = event.QuotaAvailableBytes
			fields["quota_available_objects"] = event.QuotaAvailableObjects
			fields["quota_byte_rate"] = event.QuotaByteRate
			fields["quota_byte_burst"] = event.QuotaByteBurst
			fields["quota_object_rate"] = event.QuotaObjectRate
			fields["quota_object_burst"] = event.QuotaObjectBurst
			if event.QuotaLastRefillUnixNano > 0 {
				fields["quota_last_refill"] = time.Unix(0, event.QuotaLastRefillUnixNano).UTC().Format(time.RFC3339Nano)
			}
		}
		logger.Debug("gossip", "message", fields)
	}
}
