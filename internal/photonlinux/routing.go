package photonlinux

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/HiggsNet/photon/pkg/routing/bird"
	transportipsec "github.com/HiggsNet/photon/pkg/transport/ipsec"
)

type UpstreamRouteSpec struct {
	NetNS          string
	Interface      string
	Prefixes       []netip.Prefix
	SourcePrefixes []netip.Prefix
	MeshIPv4LL     string
	MeshIPv6LL     string
}

type UpstreamRouteManager interface {
	EnsureRoutes(context.Context, UpstreamRouteSpec) error
}

type BirdClient interface {
	Status(context.Context) (*bird.BirdObservedState, error)
	Configure(context.Context, string) error
	Raw(context.Context, string) (string, error)
}

func (r *LinuxDriver) EnsureRoutingVeth(ctx context.Context, spec bird.VethSpec) error {
	if r == nil || r.vethManager == nil {
		return fmt.Errorf("linux routing driver is not configured")
	}
	return r.vethManager.EnsureVethPair(ctx, spec)
}

func (r *LinuxDriver) EnsureUpstreamRoutes(ctx context.Context, spec UpstreamRouteSpec) error {
	if r == nil || r.upstreamRoutes == nil {
		return fmt.Errorf("linux routing driver is not configured")
	}
	return r.upstreamRoutes.EnsureRoutes(ctx, spec)
}

func (r *LinuxDriver) WriteBirdConfig(path string, config []byte) error {
	if r == nil {
		return fmt.Errorf("linux routing driver is not configured")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create BIRD config directory: %w", err)
	}
	if err := os.WriteFile(path, config, 0o600); err != nil {
		return fmt.Errorf("write BIRD config: %w", err)
	}
	return nil
}

func (r *LinuxDriver) BirdProcessStatus(ctx context.Context, netns string) (bool, *bird.ProcessExit) {
	manager := r.birdProcessManager(netns)
	if manager == nil {
		return false, nil
	}
	return manager.IsRunning(ctx), manager.LastExit()
}

func (r *LinuxDriver) StartBird(ctx context.Context, spec bird.BirdInstanceSpec) error {
	manager := r.birdProcessManager(spec.NetNSName)
	if manager == nil {
		return fmt.Errorf("linux BIRD driver is not configured")
	}
	return manager.Start(ctx, spec)
}

func (r *LinuxDriver) StopBird(ctx context.Context, spec bird.BirdInstanceSpec) error {
	manager := r.existingBirdProcessManager(spec.NetNSName)
	if manager == nil {
		return nil
	}
	return manager.Stop(ctx, spec)
}

func (r *LinuxDriver) ConfigureBird(ctx context.Context, socketPath, configPath string) error {
	if r == nil {
		return fmt.Errorf("linux BIRD driver is not configured")
	}
	return r.birdClient(socketPath, nil).Configure(ctx, configPath)
}

func (r *LinuxDriver) ObserveBird(ctx context.Context, socketPath string, routeTables ...string) (*bird.BirdObservedState, error) {
	if r == nil {
		return nil, fmt.Errorf("linux BIRD driver is not configured")
	}
	return r.birdClient(socketPath, routeTables).Status(ctx)
}

func (r *LinuxDriver) RawBird(ctx context.Context, socketPath, command string) (string, error) {
	if r == nil {
		return "", fmt.Errorf("linux BIRD driver is not configured")
	}
	return r.birdClient(socketPath, nil).Raw(ctx, command)
}

func (r *LinuxDriver) birdProcessManager(netns string) bird.ProcessManager {
	if r == nil {
		return nil
	}
	r.birdMu.Lock()
	defer r.birdMu.Unlock()
	if r.birdProcess != nil {
		return r.birdProcess
	}
	if manager := r.birdProcesses[netns]; manager != nil {
		return manager
	}
	if r.birdProcesses == nil {
		r.birdProcesses = make(map[string]bird.ProcessManager)
	}
	manager := bird.NewExecProcessManager("")
	r.birdProcesses[netns] = manager
	return manager
}

func (r *LinuxDriver) existingBirdProcessManager(netns string) bird.ProcessManager {
	if r == nil {
		return nil
	}
	r.birdMu.Lock()
	defer r.birdMu.Unlock()
	if r.birdProcess != nil {
		return r.birdProcess
	}
	return r.birdProcesses[netns]
}

func (r *LinuxDriver) birdClient(socketPath string, routeTables []string) BirdClient {
	if r != nil && r.birdClientFactory != nil {
		return r.birdClientFactory(socketPath, 10*time.Second)
	}
	return bird.NewClientWithRouteTables(socketPath, 10*time.Second, routeTables)
}

type execUpstreamRouteManager struct {
	runner func(ctx context.Context, name string, args ...string) *exec.Cmd
}

func newExecUpstreamRouteManager() *execUpstreamRouteManager {
	return &execUpstreamRouteManager{runner: exec.CommandContext}
}

func (m *execUpstreamRouteManager) EnsureRoutes(ctx context.Context, spec UpstreamRouteSpec) error {
	if spec.Interface == "" {
		return fmt.Errorf("upstream route interface is required")
	}
	sourcePrefixes := append([]netip.Prefix(nil), spec.SourcePrefixes...)
	sort.Slice(sourcePrefixes, func(i, j int) bool { return prefixLess(sourcePrefixes[i], sourcePrefixes[j]) })
	for _, source := range sourcePrefixes {
		if err := m.replaceAddress(ctx, spec.NetNS, spec.Interface, source); err != nil {
			return err
		}
	}
	nextHopByFamily, err := upstreamNextHopByFamily(spec.MeshIPv4LL, spec.MeshIPv6LL)
	if err != nil {
		return err
	}
	sourceByFamily := upstreamSourceByFamily(sourcePrefixes)
	prefixes := append([]netip.Prefix(nil), spec.Prefixes...)
	sort.Slice(prefixes, func(i, j int) bool { return prefixLess(prefixes[i], prefixes[j]) })
	for _, prefix := range prefixes {
		is4 := prefix.Addr().Is4()
		if err := m.replaceRoute(ctx, spec.NetNS, spec.Interface, prefix, sourceByFamily[is4], nextHopByFamily[is4]); err != nil {
			return err
		}
	}
	return nil
}

func (m *execUpstreamRouteManager) replaceAddress(ctx context.Context, netnsName, iface string, prefix netip.Prefix) error {
	family := "-6"
	if prefix.Addr().Is4() {
		family = "-4"
	}
	return m.runIP(ctx, netnsName, []string{family, "addr", "replace", prefix.String(), "dev", iface})
}

func (m *execUpstreamRouteManager) replaceRoute(ctx context.Context, netnsName, iface string, prefix netip.Prefix, source netip.Addr, nextHop netip.Addr) error {
	family := "-6"
	if prefix.Addr().Is4() {
		family = "-4"
	}
	args := []string{family, "route", "replace", prefix.String(), "dev", iface, "proto", "static"}
	if nextHop.IsValid() {
		args = append(args, "via", nextHop.String())
	}
	if source.IsValid() {
		args = append(args, "src", source.String())
	}
	return m.runIP(ctx, netnsName, args)
}

func (m *execUpstreamRouteManager) runIP(ctx context.Context, netnsName string, args []string) error {
	if netnsName != "" && netnsName != transportipsec.NetNSHost {
		args = append([]string{"netns", "exec", netnsName, "ip"}, args...)
	}
	cmd := m.runner(ctx, "ip", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %s: %w (%s)", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func upstreamSourceByFamily(prefixes []netip.Prefix) map[bool]netip.Addr {
	out := make(map[bool]netip.Addr, 2)
	for _, prefix := range prefixes {
		is4 := prefix.Addr().Is4()
		if _, ok := out[is4]; !ok {
			out[is4] = prefix.Addr()
		}
	}
	return out
}

func upstreamNextHopByFamily(ipv4LL, ipv6LL string) (map[bool]netip.Addr, error) {
	out := make(map[bool]netip.Addr, 2)
	if ipv4LL != "" {
		prefix, err := netip.ParsePrefix(ipv4LL)
		if err != nil {
			return nil, fmt.Errorf("invalid mesh ipv4_ll %q: %w", ipv4LL, err)
		}
		out[true] = prefix.Addr()
	}
	if ipv6LL != "" {
		prefix, err := netip.ParsePrefix(ipv6LL)
		if err != nil {
			return nil, fmt.Errorf("invalid mesh ipv6_ll %q: %w", ipv6LL, err)
		}
		out[false] = prefix.Addr()
	}
	return out, nil
}

func prefixLess(left, right netip.Prefix) bool {
	if left.Addr().Less(right.Addr()) {
		return true
	}
	if right.Addr().Less(left.Addr()) {
		return false
	}
	return left.Bits() < right.Bits()
}
