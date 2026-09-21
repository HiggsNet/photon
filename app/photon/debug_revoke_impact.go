package main

import (
	"context"
	"fmt"
	"os"

	"github.com/HiggsNet/photon/internal/inspect"
	inspecttext "github.com/HiggsNet/photon/internal/inspect/text"
)

// debugRevokeImpact implements `photon debug revoke-impact [zone]`: it shows
// the revocation impact (affected subtree, link instances, sync peers,
// configured-but-revoked peers, IPAM prefixes and per-layer cleanup status)
// for all currently-revoked zones, or for a single zone if specified.
func debugRevokeImpact(_ context.Context, zoneArg string) error {
	config, err := loadAppConfig()
	if err != nil {
		return err
	}

	if impacts, ok, err := readCanonicalViewViaControl[[]inspect.RevocationImpact](config, controlRequest{Method: "revocation_view", Zone: zoneArg}, false); err != nil {
		return err
	} else if ok {
		return inspecttext.WriteRevocationImpacts(os.Stdout, impacts)
	}
	return fmt.Errorf("daemon control socket unavailable; revocation runtime impact requires a running daemon")
}
