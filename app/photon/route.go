package main

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	inspecttext "github.com/HiggsNet/photon/internal/inspect/text"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

type routeMutationRequest struct {
	Zone   zone.ZonePath `json:"zone"`
	Prefix string        `json:"prefix"`
	Active bool          `json:"active"`
	DryRun bool          `json:"dry_run,omitempty"`
}

func commonRouteIntent(request routeMutationRequest) corestate.LocalIntent {
	if request.Active {
		return corestate.AnnounceRouteIntent{Zone: request.Zone, Prefix: request.Prefix}
	}
	return corestate.WithdrawRouteIntent{Zone: request.Zone, Prefix: request.Prefix}
}

func announceRoute(path zone.ZonePath, prefix string, direct bool) error {
	config, err := loadAppConfig()
	if err != nil {
		return err
	}

	return mutateRouteWithConfig(config, path, prefix, true, time.Now(), direct)
}

func withdrawRoute(path zone.ZonePath, prefix string, direct bool) error {
	config, err := loadAppConfig()
	if err != nil {
		return err
	}

	return mutateRouteWithConfig(config, path, prefix, false, time.Now(), direct)
}

func showRoutes(filter string, includeAll bool, verbose bool) error {
	config, err := loadAppConfig()
	if err != nil {
		return err
	}
	report, err := buildRouteShowReport(config, "", includeAll, time.Now(), false)
	if err != nil {
		return err
	}
	return inspecttext.WriteRouteShowReport(os.Stdout, report, includeAll, filter, verbose)
}

func mutateRouteWithConfig(config *appConfig, path zone.ZonePath, prefix string, active bool, now time.Time, direct bool) error {
	request := routeMutationRequest{Zone: path, Prefix: prefix, Active: active}
	if version, ok, err := sendVersionedMutationViaControl(config, controlRequest{Method: "route_mutate", Route: &request}, direct); ok {
		if err != nil {
			return err
		}
		fmt.Printf("%s route %s version %d via daemon\n", routeOpVerb(request.Active), request.Prefix, version)
		return nil
	}
	result, err := applyOfflineCommonIntent(config, commonRouteIntent(request), request.DryRun, now)
	if err != nil {
		return err
	}
	if result.Record == nil {
		return errors.New("route mutation did not return a record")
	}
	fmt.Printf("%s route %s/%s version %d\n", routeOpVerb(request.Active), result.Record.Zone, result.Record.Key, result.Record.Version)
	return nil
}

func buildRouteShowReport(config *appConfig, filterZone zone.ZonePath, includeAll bool, now time.Time, direct bool) (*inspect.RouteShowReport, error) {
	if report, ok, err := readCanonicalViewViaControl[inspect.RouteShowReport](config, controlRequest{Method: "route_view", Zone: filterZone.String(), IncludeAll: includeAll}, direct); err != nil {
		return nil, err
	} else if ok {
		return &report, nil
	}
	common, _, err := loadOfflineOwnerViews(config)
	if err != nil {
		return nil, err
	}
	if common.State == nil {
		return nil, errors.New("common state is not initialized")
	}
	return inspect.BuildRouteShowReport(common.State, now, filterZone, includeAll), nil
}

func routeOpVerb(active bool) string {
	if active {
		return "announced"
	}
	return "withdrew"
}
