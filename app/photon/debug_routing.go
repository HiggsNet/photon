package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	inspecttext "github.com/HiggsNet/photon/internal/inspect/text"
	"github.com/HiggsNet/photon/internal/photonlinux"
	"github.com/HiggsNet/photon/pkg/routing"
	"github.com/HiggsNet/photon/pkg/routing/bird"
	"github.com/urfave/cli/v3"
)

func debugBabel(_ context.Context, _ *cli.Command) error {
	config, err := loadAppConfig()
	if err != nil {
		return err
	}
	return debugBabelWithConfig(config, os.Stdout)
}

func debugRoutingReload(_ context.Context, _ *cli.Command) error {
	config, err := loadAppConfig()
	if err != nil {
		return err
	}
	return debugRoutingReloadWithConfig(config, os.Stdout)
}

func debugRoutingReloadWithConfig(config *appConfig, w io.Writer) error {
	response, ok, err := routingReloadViaControl(config)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("daemon control socket unavailable; start the daemon to reload routing")
	}
	msg := "routing reloaded"
	if response.Message != "" {
		msg = response.Message
	}
	fmt.Fprintln(w, msg)
	return nil
}

func debugBird(_ context.Context, netnsName string, view bird.DebugView) error {
	config, err := loadAppConfig()
	if err != nil {
		return err
	}
	return debugBirdWithConfig(config, netnsName, view, os.Stdout)
}

func debugBirdWithConfig(config *appConfig, netnsName string, view bird.DebugView, w io.Writer) error {
	dump, ok, err := readCanonicalViewViaControl[inspect.BirdDumpResponse](config, controlRequest{Method: "bird_dump", NetNS: netnsName, BirdView: string(view)}, false)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("daemon control socket unavailable; BIRD live query requires a running daemon")
	}
	return inspecttext.WriteBirdDump(w, &dump)
}

func addBirdFilterDefinitions(item *inspect.BirdDumpInstance, configPath string) {
	if item == nil {
		return
	}
	item.ConfigPath = configPath
	if configPath == "" {
		item.FilterFailure = inspect.BuildFailure(inspect.FailureCodeBirdFilter, errors.New("config file is not configured"))
		return
	}
	config, err := os.ReadFile(configPath)
	if err != nil {
		item.FilterFailure = inspect.BuildFailure(inspect.FailureCodeBirdFilter, err)
		return
	}
	item.FilterDefinitions = inspect.ExtractBirdFilterDefinitions(string(config))
}

func debugBabelWithConfig(config *appConfig, w io.Writer) error {
	view, ok, err := readCanonicalViewViaControl[inspect.BabelDebugView](config, controlRequest{Method: "babel_view"}, false)
	if err != nil {
		return err
	}
	if ok {
		return inspecttext.WriteBabelDebug(w, view)
	}
	return fmt.Errorf("daemon control socket unavailable; BIRD runtime state requires a running daemon")
}

func buildBabelDebugView(config *appConfig, instances map[string]*bird.InstanceObservation, lastRoutingFailure error) inspect.BabelDebugView {
	routingInstances := []photonlinux.RoutingInstance{}
	if config != nil {
		routingInstances = config.Routing.Instances
	}
	input := inspect.BabelDebugInput{LastReconcileFailure: lastRoutingFailure}
	if len(routingInstances) == 0 {
		return inspect.BuildBabelDebug(input)
	}
	input.LinuxStates = instances
	for _, inst := range routingInstances {
		input.Instances = append(input.Instances, inspect.BabelInstanceInput{
			NetNS:          inst.Bird.NetNSName,
			InstanceID:     inst.ID,
			Mode:           string(inst.Bird.Mode),
			ShutdownPolicy: inst.ShutdownPolicy,
			Enabled:        inst.Enabled,
		})
	}
	return inspect.BuildBabelDebug(input)
}

func debugRoutes(_ context.Context, _ *cli.Command) error {
	config, err := loadAppConfig()
	if err != nil {
		return err
	}
	return debugRoutesWithConfig(config, os.Stdout, time.Now(), false)
}

func debugRoutesWithConfig(config *appConfig, w io.Writer, now time.Time, direct bool) error {
	dump, err := loadRoutesView(config, now, direct)
	if err != nil {
		return err
	}
	return inspecttext.WriteRoutesDebug(w, dump)
}

func debugRoute(_ context.Context, cmd *cli.Command) error {
	config, err := loadAppConfig()
	if err != nil {
		return err
	}
	return debugRouteWithConfig(config, cmd.Args().First(), os.Stdout, time.Now(), false)
}

func debugRouteWithConfig(config *appConfig, prefixArg string, w io.Writer, now time.Time, direct bool) error {
	canonical, err := routing.CanonicalizePrefix(prefixArg)
	if err != nil {
		return fmt.Errorf("invalid prefix %q: %w", prefixArg, err)
	}
	prefix, err := netip.ParsePrefix(canonical)
	if err != nil {
		return err
	}
	dump, err := loadRoutesView(config, now, direct)
	if err != nil {
		return err
	}
	return inspecttext.WriteRouteDebug(w, prefix, dump)
}

func loadRoutesView(config *appConfig, now time.Time, direct bool) (*inspect.RoutesResponse, error) {
	view, ok, err := readCanonicalViewViaControl[inspect.RoutesResponse](config, controlRequest{Method: "routes_view"}, direct)
	if err != nil {
		return nil, err
	}
	if ok {
		return &view, nil
	}
	common, _, err := loadOfflineOwnerViews(config)
	if err != nil {
		return nil, err
	}
	if common.State == nil {
		return nil, fmt.Errorf("common state is not initialized")
	}
	configureValidation(common.State.Network)
	ars, err := routing.BuildAuthorizedRouteSet(common.State.Network, now)
	if err != nil {
		return nil, err
	}
	return inspect.RoutesFromAuthorizedSet(common.State.ManagedZone, ars), nil
}

// routingNetnsForOverlay returns the netns name for a given overlay group ID.
// Used by debug links routing state lookup.
func routingNetnsForOverlay(config *appConfig, overlayID string) string {
	if config == nil {
		return ""
	}
	// Find the overlay group, resolve its netns name.
	for _, group := range config.IPsec.LinkGroups {
		if group.ID == overlayID {
			return photonlinux.NetNSTarget(group.NetNS)
		}
	}
	return ""
}
