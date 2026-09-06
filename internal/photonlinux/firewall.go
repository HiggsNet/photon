package photonlinux

import (
	"context"
	"fmt"

	"github.com/HiggsNet/photon/pkg/firewall"
	transportipsec "github.com/HiggsNet/photon/pkg/transport/ipsec"
)

// ResolveFirewallBackend probes the Linux host (or an injected test driver)
// and selects the backend allowed by one instance's native hook requirements.
func (r *LinuxDriver) ResolveFirewallBackend(ctx context.Context, spec firewall.FirewallInstanceSpec) (string, firewall.FirewallPreflight, error) {
	if r == nil {
		return firewall.BackendNone, firewall.FirewallPreflight{}, fmt.Errorf("linux driver is not configured")
	}
	var (
		preflight firewall.FirewallPreflight
		err       error
	)
	if r.firewallDriver != nil {
		preflight, err = r.firewallDriver.Preflight(ctx, spec)
	} else {
		preflight = firewall.PreflightProbe(ctx)
	}
	if err != nil {
		return firewall.BackendNone, preflight, err
	}
	backend, err := firewall.ResolveBackendForInstance(spec, preflight)
	return backend, preflight, err
}

// ApplyFirewall observes and applies one desired firewall instance through the
// selected Linux backend. Desired policy construction remains outside the
// platform driver; all driver I/O and namespace selection are owned here.
func (r *LinuxDriver) ApplyFirewall(ctx context.Context, spec firewall.FirewallInstanceSpec, backend string, owner firewall.Owner, desired *firewall.FirewallDesiredState) (firewall.FirewallApplyResult, error) {
	driver, err := r.newFirewallDriver(spec, backend)
	if err != nil {
		return firewall.FirewallApplyResult{}, err
	}
	if driver == nil {
		driver = firewall.NewDryRunDriver()
	}
	observed, _ := driver.ListOwned(ctx, owner)
	plan, err := driver.Plan(ctx, desired, observed)
	if err != nil {
		return firewall.FirewallApplyResult{}, err
	}
	return driver.Apply(ctx, plan, desired)
}

func (r *LinuxDriver) newFirewallDriver(spec firewall.FirewallInstanceSpec, backend string) (firewall.FirewallDriver, error) {
	if r == nil {
		return nil, fmt.Errorf("linux driver is not configured")
	}
	if r.firewallDriver != nil {
		return r.firewallDriver, nil
	}
	if backend == firewall.BackendNone || backend == "" {
		return nil, nil
	}

	netns, err := r.firewallNetNS(spec)
	if err != nil {
		return nil, err
	}
	switch backend {
	case firewall.BackendNFT:
		driver := firewall.NewNFTDriver()
		driver.NetNS = netns
		return driver, nil
	case firewall.BackendIptables:
		driver := firewall.NewIPTablesDriver()
		driver.NetNS = netns
		return driver, nil
	default:
		return nil, fmt.Errorf("unsupported resolved firewall backend %q", backend)
	}
}

func (r *LinuxDriver) firewallNetNS(spec firewall.FirewallInstanceSpec) (string, error) {
	if spec.IsHost {
		return "", nil
	}
	netns, ok := r.networkNamespaces[spec.NetNS]
	if !ok {
		return "", fmt.Errorf("netns %q not found", spec.NetNS)
	}
	netns = netns.Normalized()
	switch netns.Kind {
	case transportipsec.NetNSHost:
		return "", nil
	case transportipsec.NetNSName:
		return netns.Name, nil
	default:
		return "", fmt.Errorf("netns %q kind %q is not supported by firewall CLI drivers", spec.NetNS, netns.Kind)
	}
}
