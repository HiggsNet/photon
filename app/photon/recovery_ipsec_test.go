package main

import (
	"context"
	"strings"
	"testing"

	photonlinux "github.com/HiggsNet/photon/internal/photonlinux"
)

func TestRecoveryCleanupIPsecDirectRequiresExplicitOrphans(t *testing.T) {
	config := defaultAppConfig()
	// An invalid driver must never be initialized without the explicit flag.
	config.IPsec.Driver = "invalid"
	cleaned, err := recoveryCleanupIPsecDirect(context.Background(), config, false)
	if cleaned != 0 || err == nil || !strings.Contains(err.Error(), "requires --orphans") {
		t.Fatalf("cleanup = (%d, %v), want --orphans validation error", cleaned, err)
	}
}

func TestRecoveryCleanupIPsecDirectNilConfig(t *testing.T) {
	_, err := recoveryCleanupIPsecDirect(context.Background(), nil, true)
	if err == nil || err.Error() != "config is nil" {
		t.Fatalf("error = %v, want config is nil", err)
	}
}

func TestRecoveryCleanupIPsecDirectDryRun(t *testing.T) {
	config := defaultAppConfig()
	config.IPsec.Driver = photonlinux.IPsecDriverDryRun
	cleaned, err := recoveryCleanupIPsecDirect(context.Background(), config, true)
	if err != nil || cleaned != 0 {
		t.Fatalf("cleanup = (%d, %v), want (0, nil)", cleaned, err)
	}
}
