package main

import (
	"context"
	"errors"
	"time"

	photonstate "github.com/HiggsNet/photon/internal/state"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

var errStateRevisionStale = corestate.ErrVerifiedRevisionStale

type protocolPublishResult struct {
	LinuxStateCommitted bool
	Common              corestate.LocalIntentBatchResult
}

// commitLocalProtocols persists a private transport key before publishing
// public protocol records that may reference it.
func commitLocalProtocols(ctx context.Context, state *State, sourceRevision uint64, intents []corestate.LocalIntent, transportKey *photonstate.IPsecTransportKeyState, now time.Time) (protocolPublishResult, error) {
	var out protocolPublishResult
	if state == nil || state.Common == nil {
		return out, errors.New("state is not initialized")
	}
	if uint64(state.Common.VerifiedRevision()) != sourceRevision {
		return out, errStateRevisionStale
	}
	if transportKey != nil {
		committed, err := state.ReplaceIPsecTransportKeyIfRevision(corestate.VerifiedRevision(sourceRevision), transportKey)
		if err != nil {
			return out, err
		}
		out.LinuxStateCommitted = committed
	}
	if len(intents) > 0 {
		result, err := state.Common.ApplyLocalIntentsAtRevision(ctx, intents, now, corestate.VerifiedRevision(sourceRevision))
		if err != nil {
			return out, err
		}
		out.Common = result
	}
	return out, nil
}
