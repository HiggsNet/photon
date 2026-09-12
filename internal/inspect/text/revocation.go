package text

import (
	"io"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
)

// WriteRevocationImpacts writes debug revoke-impact details to w.
func WriteRevocationImpacts(w io.Writer, impacts []inspect.RevocationImpact) error {
	out := newLineWriter(w)
	if len(impacts) == 0 {
		out.Linef("no revoked zones")
		return out.Err()
	}
	for _, imp := range impacts {
		writeRevocationImpactDetail(out, imp)
	}
	return out.Err()
}

func writeRevocationImpactDetail(out *lineWriter, imp inspect.RevocationImpact) {
	out.Linef("revoked_zone: %s", imp.RevokedZone)
	out.LineIf(imp.SourceZone != "", "  source_zone: %s", imp.SourceZone)
	if len(imp.RevokedSubtree) > 0 {
		out.Linef("  affected_subtree:")
		for _, z := range imp.RevokedSubtree {
			out.Linef("    - %s", z)
		}
	} else {
		out.Linef("  affected_subtree: (none)")
	}
	if len(imp.AffectedLinkInstances) > 0 {
		out.Linef("  affected_link_instances:")
		for _, id := range imp.AffectedLinkInstances {
			out.Linef("    - %s", id)
		}
	}
	if len(imp.AffectedSyncPeers) > 0 {
		out.Linef("  affected_sync_peers:")
		for _, id := range imp.AffectedSyncPeers {
			out.Linef("    - %s", id)
		}
	}
	if len(imp.ConfiguredButRevoked) > 0 {
		out.Linef("  configured_but_revoked:")
		for _, id := range imp.ConfiguredButRevoked {
			out.Linef("    - %s", id)
		}
		out.Linef("    note: bootstrap config still points to revoked peer; remove from config or update peer identity")
	}
	if len(imp.AffectedIPAMPrefixes) > 0 {
		out.Linef("  affected_ipam_prefixes:")
		for _, pfx := range imp.AffectedIPAMPrefixes {
			out.Linef("    - %s", pfx)
		}
	}
	if len(imp.Layers) > 0 {
		out.Linef("  cleanup_layers:")
		for _, layer := range inspect.RevocationLayerOrder() {
			status := imp.Layers[layer]
			if status == nil {
				continue
			}
			out.Linef("    %s:", layer)
			out.Linef("      status: %s", status.Status)
			out.LineIf(status.Reason != "", "      reason: %s", status.Reason)
			out.LineIf(status.Failure != nil, "      failure: %s", failureDisplay(status.Failure))
			out.LineIf(status.UnixTime != 0, "      time: %s", time.Unix(status.UnixTime, 0).UTC().Format(time.RFC3339))
		}
	}
	out.Blank()
}
