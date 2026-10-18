//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/HiggsNet/photon/internal/photonlinux"
	"github.com/HiggsNet/photon/internal/photonopenwrt"
	"github.com/HiggsNet/photon/pkg/firewall"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

type openWrtFirewallManager interface {
	Apply(context.Context, photonopenwrt.FirewallDesired) error
	Cleanup(context.Context) error
}

type openWrtStatus struct {
	Enabled         bool     `json:"enabled"`
	AnnounceIPsec   bool     `json:"announce_ipsec"`
	AutoFirewall    bool     `json:"auto_firewall"`
	WANNetworks     []string `json:"wan_networks"`
	Devices         []string `json:"devices"`
	Addresses       []string `json:"addresses"`
	UpdatedAt       int64    `json:"updated_at"`
	FirewallApplied bool     `json:"firewall_applied"`
	LastError       string   `json:"last_error,omitempty"`
}

// The daemon loop owns integration I/O. Only this detached status projection
// is shared with control readers; no reader can publish records or edit rules.
type openWrtObservation struct {
	mu     sync.RWMutex
	status openWrtStatus
}

func (o *openWrtObservation) read() openWrtStatus {
	o.mu.RLock()
	defer o.mu.RUnlock()
	s := o.status
	s.WANNetworks = slices.Clone(s.WANNetworks)
	s.Devices = slices.Clone(s.Devices)
	s.Addresses = slices.Clone(s.Addresses)
	return s
}

func (d *Daemon) openWrtEnabled() bool {
	return d.Config != nil && d.Config.OpenWrt != nil && d.Config.OpenWrt.Enabled()
}

// Port range translation remains owned by the existing host firewall planner.
// Reject an incomplete setup instead of announcing ports with no DNAT path or
// implicitly adopting another nft table by its name.
func validateOpenWrtFirewall(config *appConfig) error {
	if config.OpenWrt == nil || !config.OpenWrt.AutoFirewall || config.IPsec.PortMode != ipsec.PortModeRange {
		return nil
	}
	var host *firewall.FirewallInstanceSpec
	for i := range config.Firewall.Instances {
		instance := &config.Firewall.Instances[i]
		if !instance.IsHost {
			continue
		}
		if host != nil {
			return errors.New("openwrt.auto_firewall with range ports requires exactly one managed host firewall instance")
		}
		host = instance
	}
	if host == nil || !host.Enabled || host.Mode != firewall.ModeManaged || !host.RedirectGrace.Enabled || host.Backend == firewall.BackendNone || host.CharonIKEPort != 500 || host.CharonNATTPort != 4500 {
		return errors.New("openwrt.auto_firewall with ipsec.port_mode=range requires an enabled firewall.instances entry with host: true, mode: managed, redirect_grace enabled, and charon ports 500/4500")
	}
	return nil
}

func (d *Daemon) refreshOpenWrtNetworks(ctx context.Context) {
	if !d.openWrtEnabled() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	config := *d.Config.OpenWrt
	status := openWrtStatus{Enabled: true, AnnounceIPsec: config.AnnounceIPsec, AutoFirewall: config.AutoFirewall,
		WANNetworks: slices.Clone(config.WANNetworks), Devices: []string{}, Addresses: []string{}, UpdatedAt: d.now().Unix()}
	inventory, err := photonopenwrt.ReadNetworkInventory(ctx, d.openWrtRunner)
	var selected []photonopenwrt.NetworkInterface
	var observationErrors []error
	if err != nil {
		observationErrors = append(observationErrors, err)
	} else {
		// Each selected network converges independently: a down wan6 cannot
		// withdraw a healthy wan, and a missing selection never means "all".
		for _, name := range config.WANNetworks {
			one := config
			one.WANNetworks = []string{name}
			networks, resolveErr := photonopenwrt.ResolveWANNetworks(one, inventory)
			if resolveErr != nil {
				observationErrors = append(observationErrors, resolveErr)
				continue
			}
			selected = append(selected, networks...)
		}
	}
	for _, network := range selected {
		status.Devices = append(status.Devices, network.L3Device)
		for _, addr := range append(slices.Clone(network.IPv4), network.IPv6...) {
			status.Addresses = append(status.Addresses, addr.String())
		}
	}
	slices.Sort(status.Devices)
	status.Devices = slices.Compact(status.Devices)
	slices.Sort(status.Addresses)
	status.Addresses = slices.Compact(status.Addresses)
	if config.AnnounceIPsec && len(status.Addresses) == 0 && len(observationErrors) == 0 {
		observationErrors = append(observationErrors, errors.New("selected WAN logical networks have no eligible unicast addresses"))
	}
	if err := errors.Join(observationErrors...); err != nil {
		status.LastError = err.Error()
		d.logWarn("openwrt", "wan_observation_failed", map[string]any{"error": err})
	}
	d.openWrtAddresses = slices.Clone(status.Addresses)
	d.openWrtObservation.mu.Lock()
	// Observation cannot certify kernel firewall application. Preserve that
	// result only until the next firewall reconcile writes it explicitly.
	d.openWrtObservation.status = status
	d.openWrtObservation.mu.Unlock()
	d.firewallDirty = true
}

func (d *Daemon) reconcileOpenWrtFirewall(ctx context.Context, hostFirewallErr error) error {
	if d.Config == nil || d.Config.OpenWrt == nil || !d.Config.OpenWrt.AutoFirewall {
		// SIGKILL skips the old process's defer. A respawn with integration
		// disabled must still withdraw owned rules from that previous process.
		// Ordinary Linux installations without these package/runtime paths do
		// not acquire a fw4 lock or invoke nft.
		if d.openWrtFirewall == nil && !d.openWrtCleanupChecked {
			d.openWrtCleanupChecked = true
			for _, path := range []string{"/usr/share/nftables.d/table-pre/30-photon.nft", "/run/photon/fw4/input.nft"} {
				if _, err := os.Lstat(path); err == nil {
					d.openWrtFirewall = photonopenwrt.NewFirewall(photonopenwrt.FirewallOptions{})
					break
				}
			}
		}
		if d.openWrtFirewall == nil {
			return nil
		}
		err := d.openWrtFirewall.Cleanup(ctx)
		d.openWrtObservation.mu.Lock()
		d.openWrtObservation.status.FirewallApplied = false
		if err != nil {
			d.openWrtObservation.status.LastError = err.Error()
		}
		d.openWrtObservation.mu.Unlock()
		if err == nil {
			d.openWrtFirewall = nil
		}
		return err
	}
	status := d.openWrtObservation.read()
	var err error
	if d.Config.OpenWrt.AutoFirewall {
		if d.openWrtFirewall == nil {
			d.openWrtFirewall = photonopenwrt.NewFirewall(photonopenwrt.FirewallOptions{})
		}
		desired := photonopenwrt.FirewallDesired{Devices: slices.Clone(status.Devices), RangeMode: d.Config.IPsec.PortMode == ipsec.PortModeRange}
		_, rawPort, parseErr := net.SplitHostPort(d.Config.ListenAddr)
		if parseErr != nil {
			err = fmt.Errorf("OpenWrt gossip listen address: %w", parseErr)
		} else {
			port, portErr := strconv.ParseUint(rawPort, 10, 16)
			if portErr != nil || port == 0 {
				err = errors.New("OpenWrt gossip listening port must be a fixed nonzero port")
			} else {
				desired.GossipPort = uint16(port)
			}
		}
		if err == nil && d.State != nil && (!desired.RangeMode || hostFirewallErr == nil) {
			view := d.State.Common.ReadView()
			if view.State != nil && len(d.Config.IPsec.LinkGroups) > 0 && d.Config.IPsec.Role != ipsec.RoleOut {
				ike, natt, oldIKE, oldNATT := photonlinux.IPsecRedirectPortsFromNetwork(view.State.Network, view.State.ManagedZone, d.now())
				desired.IKEPorts = append(ike, oldIKE...)
				desired.NATTPorts = append(natt, oldNATT...)
			}
		}
		if err == nil {
			err = d.openWrtFirewall.Apply(ctx, desired)
		}
		if desired.RangeMode && hostFirewallErr != nil {
			err = errors.Join(err, fmt.Errorf("IPsec port redirect is not ready: %w", hostFirewallErr))
		}
	}
	d.openWrtObservation.mu.Lock()
	d.openWrtObservation.status.FirewallApplied = d.Config.OpenWrt.AutoFirewall && err == nil
	if err != nil {
		d.openWrtObservation.status.LastError = err.Error()
		if status.LastError != "" {
			d.openWrtObservation.status.LastError = status.LastError + "; " + err.Error()
		}
	}
	d.openWrtObservation.mu.Unlock()
	return err
}

func (d *Daemon) cleanupOpenWrtOnStop() {
	if d.openWrtFirewall == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if err := d.openWrtFirewall.Cleanup(ctx); err != nil {
		d.logWarn("openwrt", "firewall_cleanup_failed", map[string]any{"error": err})
	}
}
