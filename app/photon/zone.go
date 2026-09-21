package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	inspecttext "github.com/HiggsNet/photon/internal/inspect/text"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

func showZones(filter string, verbose bool) error {
	config, err := loadAppConfig()
	if err != nil {
		return err
	}
	if details, ok, err := readCanonicalViewViaControl[[]inspect.ZoneDetail](config, controlRequest{Method: "zones_view"}, false); err != nil {
		return err
	} else if ok {
		return writeZoneDetails(details, filter, verbose)
	}
	common, _, err := loadOfflineOwnerViews(config)
	if err != nil {
		return err
	}
	if common.State == nil || common.State.Network == nil {
		return inspecttext.WriteZones(os.Stdout, nil, filter, verbose)
	}
	return writeZoneDetails(buildZoneDetails(common.State.Network, time.Now()), filter, verbose)
}

func buildZoneDetails(network *zone.NetworkState, now time.Time) []inspect.ZoneDetail {
	if network == nil {
		return nil
	}
	paths := make([]zone.ZonePath, 0, len(network.Zones))
	for path := range network.Zones {
		paths = append(paths, path)
	}
	inspect.SortZonePaths(paths)
	details := make([]inspect.ZoneDetail, 0, len(paths))
	for _, path := range paths {
		zs := network.Zones[path]
		if zs == nil {
			continue
		}
		details = append(details, inspect.BuildZoneDetail(network, path, now, false))
	}
	return details
}

func writeZoneDetails(details []inspect.ZoneDetail, filter string, verbose bool) error {
	filter = strings.TrimSpace(filter)
	if filter != "" {
		for _, detail := range details {
			if detail.Path == filter {
				return inspecttext.WriteZone(os.Stdout, detail, "", verbose)
			}
		}
	}
	return inspecttext.WriteZones(os.Stdout, details, filter, verbose)
}

func showRecords(path zone.ZonePath, filter string, verbose bool) error {
	config, err := loadAppConfig()
	if err != nil {
		return err
	}
	if view, ok, err := readCanonicalViewViaControl[inspect.RecordsDebugView](config, controlRequest{Method: "records_view", Zone: path.String()}, false); err != nil {
		return err
	} else if ok {
		return inspecttext.WriteRecords(os.Stdout, view, filter, verbose)
	}
	common, _, err := loadOfflineOwnerViews(config)
	if err != nil {
		return err
	}
	if common.State == nil || common.State.Network == nil {
		return fmt.Errorf("common state is not initialized")
	}
	view, err := buildRecordsInspection(common.State.Network, path, "")
	if err != nil {
		return err
	}
	return inspecttext.WriteRecords(os.Stdout, view, filter, verbose)
}
