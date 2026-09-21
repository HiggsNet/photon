package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"sort"
	"strings"

	photonstate "github.com/HiggsNet/photon/internal/state"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/firewall"
	"github.com/HiggsNet/photon/pkg/routing"
	photonservice "github.com/HiggsNet/photon/pkg/service"
)

const (
	endpointACLScopePort = "port"
	endpointACLScopeIP   = "ip"
)

func applyEndpointACL(name, destination, scope, protocol string, port uint16, selectors []string) error {
	config, err := loadAppConfig()
	if err != nil {
		return err
	}
	acl, err := validateEndpointACL(photonstate.EndpointACL{Name: name, Destination: destination, Scope: scope, Protocol: protocol, Port: port, Selectors: selectors})
	if err != nil {
		return err
	}
	if _, err := sendControlRequest(controlSocketPath(config), controlRequest{Method: "endpoint_acl_apply", EndpointACL: &acl}); err != nil {
		return err
	}
	fmt.Printf("applied endpoint ACL %s\n", acl.Name)
	return nil
}

func removeEndpointACL(name string) error {
	config, err := loadAppConfig()
	if err != nil {
		return err
	}
	if _, err := sendControlRequest(controlSocketPath(config), controlRequest{Method: "endpoint_acl_remove", Key: name}); err != nil {
		return err
	}
	fmt.Printf("removed endpoint ACL %s\n", name)
	return nil
}

func listEndpointACLs() error {
	config, err := loadAppConfig()
	if err != nil {
		return err
	}
	acls, ok, err := readCanonicalViewViaControl[[]photonstate.EndpointACL](config, controlRequest{Method: "endpoint_acl_list"}, false)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("endpoint ACL listing requires a running Photon daemon")
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(acls)
}

func validateEndpointACL(acl photonstate.EndpointACL) (photonstate.EndpointACL, error) {
	acl.Scope = strings.ToLower(strings.TrimSpace(acl.Scope))
	acl.Protocol = strings.ToLower(strings.TrimSpace(acl.Protocol))
	name, err := photonservice.NormalizeID(acl.Name)
	if err != nil {
		return photonstate.EndpointACL{}, fmt.Errorf("endpoint ACL name: %w", err)
	}
	acl.Name = name
	address, err := netip.ParseAddr(acl.Destination)
	if err != nil {
		return photonstate.EndpointACL{}, fmt.Errorf("endpoint ACL destination: %w", err)
	}
	acl.Destination = address.Unmap().String()
	if acl.Scope == "" {
		acl.Scope = endpointACLScopePort
	}
	switch acl.Scope {
	case endpointACLScopeIP:
		if acl.Protocol != "" || acl.Port != 0 {
			return photonstate.EndpointACL{}, errors.New("IP-scope endpoint ACL must not specify protocol or port")
		}
	case endpointACLScopePort:
		if acl.Protocol != firewall.ProtoTCP && acl.Protocol != firewall.ProtoUDP {
			return photonstate.EndpointACL{}, errors.New("port-scope endpoint ACL protocol must be tcp or udp")
		}
		if acl.Port == 0 {
			return photonstate.EndpointACL{}, errors.New("port-scope endpoint ACL port is required")
		}
	default:
		return photonstate.EndpointACL{}, errors.New("endpoint ACL scope must be ip or port")
	}
	if len(acl.Selectors) == 0 {
		return photonstate.EndpointACL{}, errors.New("endpoint ACL requires at least one selector; omit the ACL for an unrestricted endpoint")
	}
	seen := map[string]bool{}
	selectors := make([]string, 0, len(acl.Selectors))
	for _, raw := range acl.Selectors {
		selector, err := photonservice.ParseZoneSelector(raw)
		if err != nil {
			return photonstate.EndpointACL{}, err
		}
		value := selector.String()
		if !seen[value] {
			seen[value] = true
			selectors = append(selectors, value)
		}
	}
	sort.Strings(selectors)
	acl.Selectors = selectors
	return acl, nil
}

func resolveEndpointServices(acls map[string]photonstate.EndpointACL, ars *routing.AuthorizedRouteSet) ([]firewall.EndpointService, error) {
	if len(acls) == 0 {
		return nil, nil
	}
	names := make([]string, 0, len(acls))
	for name := range acls {
		names = append(names, name)
	}
	sort.Strings(names)
	services := make([]firewall.EndpointService, 0, len(names))
	for _, name := range names {
		acl, err := validateEndpointACL(acls[name])
		if err != nil {
			return nil, fmt.Errorf("endpoint ACL %s: %w", name, err)
		}
		var selectors []photonservice.ZoneSelector
		for _, raw := range acl.Selectors {
			selector, _ := photonservice.ParseZoneSelector(raw)
			selectors = append(selectors, selector)
		}
		address, _ := netip.ParseAddr(acl.Destination)
		var sources []netip.Prefix
		if ars != nil {
			for sourceZone, routes := range ars.Announced {
				matched := false
				for _, selector := range selectors {
					if selector.Matches(sourceZone) {
						matched = true
						break
					}
				}
				if matched {
					for prefix := range routes {
						if prefix.Addr().Is4() == address.Is4() {
							sources = append(sources, prefix)
						}
					}
				}
			}
		}
		services = append(services, firewall.EndpointService{
			Name: acl.Name, Proto: acl.Protocol, Port: acl.Port,
			Destination: address, Sources: canonicalEndpointPrefixes(sources),
		})
	}
	return services, nil
}

func canonicalEndpointPrefixes(prefixes []netip.Prefix) []netip.Prefix {
	seen := map[netip.Prefix]bool{}
	out := make([]netip.Prefix, 0, len(prefixes))
	for _, prefix := range prefixes {
		prefix = prefix.Masked()
		if !seen[prefix] {
			seen[prefix] = true
			out = append(out, prefix)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

func (d *Daemon) handleEndpointACLApplyEvent(acl photonstate.EndpointACL) (bool, error) {
	validated, err := validateEndpointACL(acl)
	if err != nil {
		return false, err
	}
	common := d.State.Common.ReadView()
	runtime := d.State.ReadLinux()
	if common.State == nil || common.State.Network == nil || runtime == nil {
		return false, errors.New("daemon state is not loaded")
	}
	if !d.hasEnforcingHostFirewall() {
		return false, errors.New("endpoint ACL requires an enabled managed host firewall instance with an available nftables or iptables backend")
	}
	// Legacy keys can differ only in case. Do not silently merge their policies.
	for key := range runtime.EndpointACLs {
		if key != validated.Name && strings.EqualFold(key, validated.Name) {
			return false, fmt.Errorf("legacy endpoint ACL %q conflicts with %q; remove it by its exact name before applying", key, validated.Name)
		}
	}
	if current, ok := runtime.EndpointACLs[validated.Name]; ok && endpointACLEqual(current, validated) {
		return false, nil
	}
	ars, err := routing.BuildAuthorizedRouteSet(common.State.Network, d.now())
	if err != nil {
		return false, fmt.Errorf("build route authorization: %w", err)
	}
	destination, _ := netip.ParseAddr(validated.Destination)
	owned := false
	for _, assignment := range ars.AllAssignments {
		if assignment.AssignedTo == common.State.ManagedZone && assignment.Prefix.Contains(destination) {
			owned = true
			break
		}
	}
	if !owned {
		return false, fmt.Errorf("endpoint ACL destination %s is outside the managed Zone's active assignments", destination)
	}
	if runtime.EndpointACLs == nil {
		runtime.EndpointACLs = make(map[string]photonstate.EndpointACL)
	}
	runtime.EndpointACLs[validated.Name] = validated
	if err := d.commitEndpointACLMutation(common.Revision, runtime.EndpointACLs); err != nil {
		return false, err
	}
	return true, nil
}

func (d *Daemon) handleEndpointACLRemoveEvent(name string) (bool, error) {
	rawName := strings.TrimSpace(name)
	name, err := photonservice.NormalizeID(name)
	if err != nil {
		return false, err
	}
	common := d.State.Common.ReadView()
	runtime := d.State.ReadLinux()
	if common.State == nil || runtime == nil {
		return false, errors.New("daemon state is not loaded")
	}
	// Keep legacy mixed-case entries removable by the exact listed name.
	if _, ok := runtime.EndpointACLs[rawName]; ok {
		name = rawName
	}
	if _, ok := runtime.EndpointACLs[name]; !ok {
		return false, nil
	}
	delete(runtime.EndpointACLs, name)
	if err := d.commitEndpointACLMutation(common.Revision, runtime.EndpointACLs); err != nil {
		return false, err
	}
	return true, nil
}

func endpointACLEqual(left, right photonstate.EndpointACL) bool {
	return left.Name == right.Name &&
		left.Destination == right.Destination &&
		left.Scope == right.Scope &&
		left.Protocol == right.Protocol &&
		left.Port == right.Port &&
		slices.Equal(left.Selectors, right.Selectors)
}

func (d *Daemon) commitEndpointACLMutation(rev corestate.VerifiedRevision, acls map[string]photonstate.EndpointACL) error {
	if d.State == nil {
		return errors.New("daemon service is not initialized")
	}
	if committed, err := d.State.ReplaceEndpointACLsIfRevision(rev, acls); err != nil {
		return err
	} else if !committed {
		return errStateRevisionStale
	}
	if d.Hooks.OnStateChanged != nil {
		d.Hooks.OnStateChanged()
	}
	d.notifyObserver("state_changed", nil)
	d.firewallDirty = true
	return nil
}

func (d *Daemon) hasEnforcingHostFirewall() bool {
	if d.Config == nil {
		return false
	}
	for _, instance := range d.Config.Firewall.ManagedInstances() {
		if instance.IsHost && instance.Backend != firewall.BackendNone {
			backend, _, err := d.linuxDriver.ResolveFirewallBackend(context.Background(), firewall.FirewallInstanceSpec{
				ID: instance.ID, Backend: instance.Backend, NativeHooks: instance.NativeHooks,
			})
			if err != nil {
				continue
			}
			if backend == firewall.BackendNFT || backend == firewall.BackendIptables {
				return true
			}
		}
	}
	return false
}
