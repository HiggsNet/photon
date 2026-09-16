package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	photonlinux "github.com/HiggsNet/photon/internal/photonlinux"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestKernelRoutesViewShowsKernelFIBByFamily(t *testing.T) {
	config := defaultAppConfig()
	config.Netns = photonlinux.NetNSConfig{Names: map[string]ipsec.NetNSSpec{
		"mesh": {Kind: ipsec.NetNSName, Name: "mesh"},
	}}
	config.Routing = routingConfig{Instances: []photonlinux.RoutingInstance{
		{ID: "main", NetNS: "mesh", Enabled: true, Mode: ipsec.RoutingModeManaged},
	}}
	var commands []string
	driver := newTestLinuxDriverWithOptions(photonlinux.LinuxDriverOptions{
		IPsecDriver:       &ipsec.DryRunDriver{},
		XFRMDriver:        &ipsec.DryRunDriver{},
		NetworkNamespaces: config.Netns.Names,
		KernelRouteRunner: func(_ context.Context, name string, args ...string) ([]byte, error) {
			command := name + " " + strings.Join(args, " ")
			commands = append(commands, command)
			switch {
			case strings.Contains(command, " -4 route show"):
				return []byte("10.42.0.0/24 proto bird metric 32\n"), nil
			case strings.Contains(command, " -6 route show"):
				return []byte("fd42::/64 proto bird metric 32\n"), nil
			default:
				return nil, errors.New("unexpected command")
			}
		},
	})
	d := &Daemon{App: &AppContext{Config: config}, linuxDriver: driver}

	view, err := d.kernelRoutesView(context.Background(), "main", "all")
	if err != nil {
		t.Fatalf("kernelRoutesView: %v", err)
	}
	if len(commands) != 2 {
		t.Fatalf("commands = %#v, want IPv4 and IPv6", commands)
	}
	var output strings.Builder
	if err := writeKernelRoutes(&output, view); err != nil {
		t.Fatalf("writeKernelRoutes: %v", err)
	}
	for _, want := range []string{
		"netns mesh", "instance_id: main", "namespace: name:mesh", "ipv4:",
		"10.42.0.0/24 proto bird metric 32", "ipv6:", "fd42::/64 proto bird metric 32",
	} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("output missing %q:\n%s", want, output.String())
		}
	}
}

func TestRoutingIPFamiliesRejectsUnknownFamily(t *testing.T) {
	if _, err := routingIPFamilies("mpls"); err == nil {
		t.Fatal("routingIPFamilies accepted unsupported family")
	}
}
