package main

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	inspecttext "github.com/HiggsNet/photon/internal/inspect/text"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

func debugZone(path zone.ZonePath, jsonOutput, includeHistory bool) error {
	config, err := loadAppConfig()
	if err != nil {
		return err
	}
	history := 0
	if includeHistory {
		history = 1
	}
	if view, ok, err := readCanonicalViewViaControl[inspect.ZoneInspectionView](config, controlRequest{Method: "zone_debug", Zone: path.String(), History: history}, false); err != nil {
		return err
	} else if ok {
		if jsonOutput {
			return inspecttext.WriteJSON(os.Stdout, view.Detail)
		}
		return inspecttext.WriteZoneDebug(os.Stdout, view)
	}
	common, _, err := loadOfflineOwnerViews(config)
	if err != nil {
		return err
	}
	if common.State == nil || common.State.Network == nil {
		return fmt.Errorf("common state is not initialized")
	}
	network := common.State.Network
	configureValidation(network)
	view, ok := inspect.BuildZoneInspection(network, path, time.Now(), includeHistory)
	if !ok {
		return fmt.Errorf("%w: %s", zone.ErrZoneNotFound, path)
	}
	if jsonOutput {
		return inspecttext.WriteJSON(os.Stdout, view.Detail)
	}
	return inspecttext.WriteZoneDebug(os.Stdout, view)
}

func debugRecords(path zone.ZonePath, prefix string, values bool) error {
	config, err := loadAppConfig()
	if err != nil {
		return err
	}
	if view, ok, err := readCanonicalViewViaControl[inspect.RecordsDebugView](config, controlRequest{Method: "records_view", Zone: path.String(), Key: prefix}, false); err != nil {
		return err
	} else if ok {
		return inspecttext.WriteRecordsDebug(os.Stdout, view, values)
	}
	common, _, err := loadOfflineOwnerViews(config)
	if err != nil {
		return err
	}
	if common.State == nil {
		return fmt.Errorf("common state is not initialized")
	}
	return writeDebugRecords(os.Stdout, common.State.Network, path, prefix, values)
}

func writeDebugRecords(w io.Writer, network *zone.NetworkState, path zone.ZonePath, prefix string, values bool) error {
	view, err := buildRecordsInspection(network, path, prefix)
	if err != nil {
		return err
	}
	return inspecttext.WriteRecordsDebug(w, view, values)
}

func buildRecordsInspection(network *zone.NetworkState, path zone.ZonePath, prefix string) (inspect.RecordsDebugView, error) {
	if network == nil {
		return inspect.RecordsDebugView{}, fmt.Errorf("network is nil")
	}
	if path.Valid() && network.Zones[path] == nil {
		return inspect.RecordsDebugView{}, fmt.Errorf("%w: %s", zone.ErrZoneNotFound, path)
	}
	return inspect.BuildRecordsDebug(inspect.RecordsDebugInput{
		Network: network,
		Path:    path,
		Prefix:  prefix,
	}), nil
}
