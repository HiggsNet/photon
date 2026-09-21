package main

import (
	"os"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	inspecttext "github.com/HiggsNet/photon/internal/inspect/text"
)

func debugEndpoints() error {
	config, err := loadAppConfig()
	if err != nil {
		return err
	}
	if view, ok, err := readCanonicalViewViaControl[inspect.EndpointDebugView](config, controlRequest{Method: "endpoints_view"}, false); err != nil {
		return err
	} else if ok {
		return inspecttext.WriteEndpointsDebug(os.Stdout, view)
	}
	common, _, err := loadOfflineOwnerViews(config)
	if err != nil {
		return err
	}
	if common.State == nil {
		return nil
	}
	view := inspect.BuildEndpointDebug(common.State, time.Now())
	return inspecttext.WriteEndpointsDebug(os.Stdout, view)
}
