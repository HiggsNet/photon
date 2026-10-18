//go:build linux

package main

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/photonopenwrt"
)

func TestOpenWrtReviewDisabledWANNeverBorrowsListenOrGossipAddresses(t *testing.T) {
	config := defaultAppConfig()
	config.OpenWrt = &photonopenwrt.Config{WANNetworks: []string{"wan"}, AnnounceIPsec: true}
	config.ListenAddr = "198.51.100.11:33434"
	config.AdvertiseAddrs = []string{"198.51.100.12:33434"}
	config.IPsec.AnnounceGossipEndpoints = true
	config.openWrtAddresses = nil
	record := localIPsecAddressRecord(config, nil, time.Unix(5000, 0))
	if len(record.Addresses) != 0 {
		t.Fatalf("empty observed WAN fell back to unrelated address: %+v", record)
	}
	// Explicit operator intent remains explicit, including a private address
	// behind DNAT. It must not turn into a wildcard interface-selection fallback.
	config.IPsec.AnnounceAddrs = []string{"192.168.10.2"}
	config.openWrtAddresses = []string{"2001:db8::10"}
	record = localIPsecAddressRecord(config, nil, time.Unix(5001, 0))
	got := map[string]bool{}
	for _, address := range record.Addresses {
		got[address.Address] = true
	}
	if !reflect.DeepEqual(got, map[string]bool{"192.168.10.2": true, "2001:db8::10": true}) {
		t.Fatalf("unexpected selected publication: %+v", record)
	}
}

func TestOpenWrtReviewCleanupIsNotSkippedAfterConfigurationOptOut(t *testing.T) {
	// Shutdown of the existing owner must still withdraw its rules when the
	// new on-disk intent is disabled; no new writes or process is introduced.
	for _, config := range []*photonopenwrt.Config{nil, {}, {WANNetworks: []string{"wan"}, AnnounceIPsec: true}} {
		backend := &openWrtFirewallRecorder{}
		daemon := &Daemon{Config: defaultAppConfig(), openWrtFirewall: backend}
		daemon.Config.OpenWrt = config
		daemon.cleanupOpenWrtOnStop()
		if !backend.cleaned {
			t.Fatalf("owned rules retained after opt-out %+v", config)
		}
		// Auto-firewall=false with announcement still enabled also cleans via
		// the normal reconcile, without opening ports from a stale runtime.
		if config != nil && config.AnnounceIPsec {
			backend.cleaned = false
			if err := daemon.reconcileOpenWrtFirewall(context.Background(), nil); err != nil || !backend.cleaned {
				t.Fatalf("opt-out reconcile failed: %v", err)
			}
		}
	}
}
