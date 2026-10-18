//go:build linux

package photonopenwrt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
)

type NetworkInterface struct {
	Name     string       `json:"name"`
	Up       bool         `json:"up"`
	L3Device string       `json:"l3_device"`
	IPv4     []netip.Addr `json:"ipv4_addresses"`
	IPv6     []netip.Addr `json:"ipv6_addresses"`
}

// ReadNetworkInventory performs one fixed, read-only netifd call. Its logical
// network names are data, never a client-selected ubus object or shell command.
func ReadNetworkInventory(ctx context.Context, run Runner) ([]NetworkInterface, error) {
	if run == nil {
		run = runCommand
	}
	data, err := run(ctx, "ubus", "call", "network.interface", "dump")
	if err != nil {
		return nil, fmt.Errorf("read OpenWrt logical networks: %w", err)
	}
	return parseNetworkInventory(data)
}

type inventoryAddress struct {
	Address    string   `json:"address"`
	Mask       *int     `json:"mask"`
	Preferred  *int64   `json:"preferred"`
	Valid      *int64   `json:"valid"`
	Temporary  bool     `json:"temporary"`
	Deprecated bool     `json:"deprecated"`
	Tentative  bool     `json:"tentative"`
	Flags      []string `json:"flags"`
}

func (a inventoryAddress) active() bool {
	if a.Temporary || a.Deprecated || a.Tentative || a.Preferred != nil && *a.Preferred <= 0 || a.Valid != nil && *a.Valid <= 0 {
		return false
	}
	for _, flag := range a.Flags {
		if flag == "temporary" || flag == "deprecated" || flag == "tentative" || flag == "dadfailed" {
			return false
		}
	}
	return true
}

func inventoryUnicast(address netip.Addr) bool {
	return address.IsValid() && !address.Is4In6() && address.IsGlobalUnicast() && !address.IsLoopback() && !address.IsLinkLocalUnicast()
}

func parseNetworkInventory(data []byte) ([]NetworkInterface, error) {
	var dump struct {
		Interfaces []struct {
			Name        string             `json:"interface"`
			Up          *bool              `json:"up"`
			L3Device    string             `json:"l3_device"`
			IPv4        []inventoryAddress `json:"ipv4-address"`
			IPv6        []inventoryAddress `json:"ipv6-address"`
			Assignments []struct {
				inventoryAddress
				Local inventoryAddress `json:"local-address"`
			} `json:"ipv6-prefix-assignment"`
		} `json:"interface"`
	}
	if err := json.Unmarshal(data, &dump); err != nil || dump.Interfaces == nil {
		return nil, errors.New("invalid netifd network.interface dump response")
	}
	result := make([]NetworkInterface, 0, len(dump.Interfaces))
	seen := map[string]bool{}
	for _, entry := range dump.Interfaces {
		if !logicalNetworkName.MatchString(entry.Name) || entry.Up == nil || seen[entry.Name] {
			return nil, fmt.Errorf("invalid or duplicate netifd logical network %q", entry.Name)
		}
		seen[entry.Name] = true
		network := NetworkInterface{Name: entry.Name, Up: *entry.Up, L3Device: entry.L3Device, IPv4: []netip.Addr{}, IPv6: []netip.Addr{}}
		collect := func(entries []inventoryAddress, is4 bool) error {
			for _, candidate := range entries {
				if !candidate.active() {
					continue
				}
				address, err := netip.ParseAddr(candidate.Address)
				if err != nil || address.Is4() != is4 || address.Is4In6() || candidate.Mask == nil || !netip.PrefixFrom(address, *candidate.Mask).IsValid() {
					return fmt.Errorf("invalid netifd address/family in logical network %q", entry.Name)
				}
				if !inventoryUnicast(address) {
					continue
				}
				if is4 {
					network.IPv4 = append(network.IPv4, address)
				} else {
					network.IPv6 = append(network.IPv6, address)
				}
			}
			return nil
		}
		if err := collect(entry.IPv4, true); err != nil {
			return nil, err
		}
		if err := collect(entry.IPv6, false); err != nil {
			return nil, err
		}
		for _, assignment := range entry.Assignments {
			// A delegated prefix is not a local address. Only netifd's explicit
			// local-address is usable; an empty object means not yet assigned.
			if assignment.active() && assignment.Local.Address != "" {
				if err := collect([]inventoryAddress{assignment.Local}, false); err != nil {
					return nil, err
				}
			}
		}
		network.IPv4, network.IPv6 = uniqueInventoryAddresses(network.IPv4), uniqueInventoryAddresses(network.IPv6)
		result = append(result, network)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}

func uniqueInventoryAddresses(addresses []netip.Addr) []netip.Addr {
	sort.Slice(addresses, func(i, j int) bool { return addresses[i].Less(addresses[j]) })
	result := addresses[:0]
	for _, address := range addresses {
		if len(result) == 0 || result[len(result)-1] != address {
			result = append(result, address)
		}
	}
	return result
}

// ResolveWANNetworks fails closed for every explicitly selected logical
// network. It never substitutes a physical device, another WAN, or LAN.
func ResolveWANNetworks(config Config, inventory []NetworkInterface) ([]NetworkInterface, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	selected := make([]NetworkInterface, 0, len(config.WANNetworks))
	for _, name := range config.WANNetworks {
		var found *NetworkInterface
		for i := range inventory {
			if inventory[i].Name == name {
				found = &inventory[i]
				break
			}
		}
		if found == nil {
			return nil, fmt.Errorf("selected WAN logical network %q does not exist", name)
		}
		if !found.Up || found.L3Device == "" {
			return nil, fmt.Errorf("selected WAN logical network %q is down or has no L3 device", name)
		}
		selected = append(selected, *found)
	}
	return selected, nil
}
