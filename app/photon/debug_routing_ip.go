package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/HiggsNet/photon/internal/inspect"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func debugRoutingIPRoute(ctx context.Context, netnsName, family string) error {
	rt, err := NewAppContext()
	if err != nil {
		return err
	}
	view, online, err := readCanonicalViewViaControlContext[[]inspect.KernelRouteDump](ctx, rt, controlRequest{
		Method: "kernel_routes_view",
		NetNS:  netnsName,
		Family: family,
	})
	if err != nil {
		return err
	}
	if !online {
		return errors.New("daemon control socket unavailable; kernel FIB requires a running daemon")
	}
	return writeKernelRoutes(os.Stdout, view)
}

func (d *Daemon) kernelRoutesView(ctx context.Context, netnsName, family string) ([]inspect.KernelRouteDump, error) {
	if d == nil || d.App == nil || d.App.Config == nil {
		return nil, errors.New("routing configuration is unavailable")
	}
	if d.linuxDriver == nil {
		return nil, errors.New("linux routing driver is not configured")
	}
	families, err := routingIPFamilies(family)
	if err != nil {
		return nil, err
	}
	instances := make([]RoutingInstance, 0, len(d.App.Config.Routing.Instances))
	for _, inst := range d.App.Config.Routing.Instances {
		if !inst.Enabled || inst.Mode == ipsec.RoutingModeDisabled {
			continue
		}
		if netnsName != "" && inst.NetNS != netnsName && inst.ID != netnsName {
			continue
		}
		instances = append(instances, inst)
	}
	sort.Slice(instances, func(i, j int) bool {
		if instances[i].NetNS != instances[j].NetNS {
			return instances[i].NetNS < instances[j].NetNS
		}
		return instances[i].ID < instances[j].ID
	})
	if len(instances) == 0 && netnsName != "" {
		return nil, fmt.Errorf("routing netns or instance %q not found", netnsName)
	}

	view := make([]inspect.KernelRouteDump, 0, len(instances)*len(families))
	for _, inst := range instances {
		for _, routeFamily := range families {
			namespace, raw, queryErr := d.linuxDriver.KernelRoutes(ctx, inst.NetNS, routeFamily)
			view = append(view, inspect.KernelRouteDump{
				NetNS: inst.NetNS, InstanceID: inst.ID, Namespace: namespace,
				Family: routeFamily, Raw: raw,
				Failure: inspect.BuildFailure(inspect.FailureCodeKernelRouteQuery, queryErr),
			})
		}
	}
	return view, nil
}

func routingIPFamilies(family string) ([]string, error) {
	switch strings.ToLower(strings.TrimSpace(family)) {
	case "", "all":
		return []string{"ipv4", "ipv6"}, nil
	case "ipv4", "4":
		return []string{"ipv4"}, nil
	case "ipv6", "6":
		return []string{"ipv6"}, nil
	default:
		return nil, fmt.Errorf("unsupported address family %q; use ipv4, ipv6, or all", family)
	}
}

func writeKernelRoutes(w io.Writer, view []inspect.KernelRouteDump) error {
	if len(view) == 0 {
		fmt.Fprintln(w, "kernel_routes: no enabled routing instances")
		return nil
	}
	var failures []error
	lastInstance := ""
	for _, row := range view {
		instance := row.NetNS + "\x00" + row.InstanceID
		if instance != lastInstance {
			fmt.Fprintf(w, "netns %s\n", row.NetNS)
			fmt.Fprintf(w, "  instance_id: %s\n", row.InstanceID)
			fmt.Fprintf(w, "  namespace: %s\n", row.Namespace)
			lastInstance = instance
		}
		fmt.Fprintf(w, "  %s:\n", row.Family)
		writeIndentedRoutingIPOutput(w, []byte(row.Raw))
		if row.Failure != nil {
			fmt.Fprintf(w, "    error: %s\n", row.Failure.Message)
			failures = append(failures, fmt.Errorf("netns %q %s: %s", row.NetNS, row.Family, row.Failure.Message))
		}
	}
	return errors.Join(failures...)
}

func writeIndentedRoutingIPOutput(w io.Writer, output []byte) {
	text := strings.TrimRight(string(output), "\n")
	if text == "" {
		fmt.Fprintln(w, "    -")
		return
	}
	for line := range strings.SplitSeq(text, "\n") {
		fmt.Fprintf(w, "    %s\n", line)
	}
}
