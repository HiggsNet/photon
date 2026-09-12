package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"

	"github.com/HiggsNet/photon/internal/inspect"
	inspecttext "github.com/HiggsNet/photon/internal/inspect/text"
	"github.com/HiggsNet/photon/pkg/routing"
	"github.com/HiggsNet/photon/pkg/routing/bird"
	"github.com/urfave/cli/v3"
)

func debugBabel(_ context.Context, _ *cli.Command) error {
	rt, err := NewAppContext()
	if err != nil {
		return err
	}
	return debugBabelWithRuntime(rt, os.Stdout)
}

func debugRoutingReload(_ context.Context, _ *cli.Command) error {
	rt, err := NewAppContext()
	if err != nil {
		return err
	}
	return debugRoutingReloadWithRuntime(rt, os.Stdout)
}

func debugRoutingReloadWithRuntime(rt *AppContext, w io.Writer) error {
	response, ok, err := routingReloadViaControl(rt)
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
	rt, err := NewAppContext()
	if err != nil {
		return err
	}
	return debugBirdWithRuntime(rt, netnsName, view, os.Stdout)
}

func debugBirdWithRuntime(rt *AppContext, netnsName string, view bird.DebugView, w io.Writer) error {
	dump, ok, err := readCanonicalViewViaControl[inspect.BirdDumpResponse](rt, controlRequest{Method: "bird_dump", NetNS: netnsName, BirdView: string(view)})
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

func debugBabelWithRuntime(rt *AppContext, w io.Writer) error {
	view, ok, err := readCanonicalViewViaControl[inspect.BabelDebugView](rt, controlRequest{Method: "babel_view"})
	if err != nil {
		return err
	}
	if ok {
		return inspecttext.WriteBabelDebug(w, view)
	}
	return fmt.Errorf("daemon control socket unavailable; BIRD runtime state requires a running daemon")
}

func buildBabelDebugView(rt *AppContext, instances map[string]*bird.InstanceObservation, lastRoutingFailure error) inspect.BabelDebugView {
	routingInstances := []RoutingInstance{}
	if rt != nil && rt.Config != nil {
		routingInstances = rt.Config.Routing.Instances
	}
	input := inspect.BabelDebugInput{}
	if len(routingInstances) == 0 {
		return inspect.BuildBabelDebug(input)
	}
	input.LastReconcileFailure = lastRoutingFailure
	input.LinuxStates = instances
	for _, inst := range routingInstances {
		input.Instances = append(input.Instances, inspect.BabelInstanceInput{
			NetNS:          inst.NetNS,
			InstanceID:     inst.ID,
			Mode:           inst.Mode,
			ShutdownPolicy: inst.ShutdownPolicy,
			Enabled:        inst.Enabled,
		})
	}
	return inspect.BuildBabelDebug(input)
}

func debugRoutes(_ context.Context, _ *cli.Command) error {
	rt, err := NewAppContext()
	if err != nil {
		return err
	}
	return debugRoutesWithRuntime(rt, os.Stdout)
}

func debugRoutesWithRuntime(rt *AppContext, w io.Writer) error {
	dump, err := loadRoutesView(rt)
	if err != nil {
		return err
	}
	return inspecttext.WriteRoutesDebug(w, dump)
}

func debugRoute(_ context.Context, cmd *cli.Command) error {
	rt, err := NewAppContext()
	if err != nil {
		return err
	}
	return debugRouteWithRuntime(rt, cmd.Args().First(), os.Stdout)
}

func debugRouteWithRuntime(rt *AppContext, prefixArg string, w io.Writer) error {
	canonical, err := routing.CanonicalizePrefix(prefixArg)
	if err != nil {
		return fmt.Errorf("invalid prefix %q: %w", prefixArg, err)
	}
	prefix, err := netip.ParsePrefix(canonical)
	if err != nil {
		return err
	}
	dump, err := loadRoutesView(rt)
	if err != nil {
		return err
	}
	return inspecttext.WriteRouteDebug(w, prefix, dump)
}

func loadRoutesView(rt *AppContext) (*inspect.RoutesResponse, error) {
	view, ok, err := readCanonicalViewViaControl[inspect.RoutesResponse](rt, controlRequest{Method: "routes_view"})
	if err != nil {
		return nil, err
	}
	if ok {
		return &view, nil
	}
	common, _, err := loadOfflineOwnerViews(rt)
	if err != nil {
		return nil, err
	}
	if common.State == nil {
		return nil, fmt.Errorf("common state is not initialized")
	}
	configureValidation(common.State.Network)
	ars, err := routing.BuildAuthorizedRouteSet(common.State.Network, rt.Now())
	if err != nil {
		return nil, err
	}
	return inspect.RoutesFromAuthorizedSet(common.State.ManagedZone, ars), nil
}

// routingNetnsForOverlay returns the netns name for a given overlay group ID.
// Used by debug links routing state lookup.
func routingNetnsForOverlay(rt *AppContext, overlayID string) string {
	if rt == nil || rt.Config == nil {
		return ""
	}
	// Find the overlay group, resolve its netns name.
	for _, group := range rt.Config.IPsec.LinkGroups {
		if group.ID == overlayID {
			return resolveOverlayNetNSName(group, rt.Config.Overlay.DefaultNetNS)
		}
	}
	return ""
}
