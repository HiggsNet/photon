package main

import (
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestLinksViewQueriesLiveSAsOnlyWhenRequested(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	service := newTestDaemonFromOwners(&testApp{Config: defaultAppConfig()}, verified, checkpoint, runtime, config, time.Second)
	driver := &observedIPsecDriver{sas: []ipsec.SAState{{Name: "live-ike", Established: true}}}
	installTestIPsecDrivers(service, driver, driver)
	// Use an injected driver while exercising the live-query control branch.
	service.Config.IPsec.Driver = "strongswan"
	for _, live := range []bool{false, true, false} {
		before := driver.listCalls
		response := controlViewRequestViaPipe[inspect.LinksDebugView](t, service, controlRequest{Method: "links_view", LiveSAs: live})
		if !response.OK {
			t.Fatalf("links_view live=%v: %s", live, response.Error)
		}
		want := before
		if live {
			want++
		}
		if driver.listCalls != want {
			t.Fatalf("live=%v: SA queries=%d, want %d", live, driver.listCalls, want)
		}
		if live {
			if len(response.View.LiveSAs) != 1 || response.View.LiveSAs[0].Name != "live-ike" {
				t.Fatalf("live SA projection = %+v", response.View.LiveSAs)
			}
		} else if len(response.View.LiveSAs) != 0 {
			t.Fatalf("ordinary links view included live SAs: %+v", response.View.LiveSAs)
		}
	}
}
