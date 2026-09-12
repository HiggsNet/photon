package main

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

func allAuthorityPermissions() []zone.Permission {
	return []zone.Permission{
		zone.PermWrite,
		zone.PermDelegate,
		zone.PermAllocateIP,
	}
}

func defaultRootCapabilities() []zone.Capability {
	return []zone.Capability{{Permissions: allAuthorityPermissions()}}
}

func defaultDelegationCapabilities() []zone.Capability {
	return []zone.Capability{{Permissions: []zone.Permission{zone.PermWrite, zone.PermDelegate}}}
}

func parseAuthorityPermissions(input []string) ([]zone.Permission, error) {
	var out []zone.Permission
	seen := map[zone.Permission]bool{}
	for _, raw := range input {
		for part := range strings.SplitSeq(raw, ",") {
			perm, err := parseAuthorityPermission(strings.TrimSpace(part))
			if err != nil {
				return nil, err
			}
			if seen[perm] {
				continue
			}
			seen[perm] = true
			out = append(out, perm)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("at least one permission is required")
	}
	slices.Sort(out)
	return out, nil
}

func parseAuthorityPermission(raw string) (zone.Permission, error) {
	switch zone.Permission(raw) {
	case zone.PermWrite, zone.PermDelegate, zone.PermAllocateIP:
		return zone.Permission(raw), nil
	default:
		return "", fmt.Errorf("unsupported authority permission %q", raw)
	}
}

func grantDelegationPermissions(path zone.ZonePath, permissions []zone.Permission, outPath string, direct bool) error {
	rt, err := NewAppContext()
	if err != nil {
		return err
	}
	rt.DisableControl = direct
	bundle, controlled, err := grantDelegationPermissionsViaControl(rt, path, permissions)
	if err != nil {
		return err
	}
	if controlled {
		if err := writeDelegationGrantBundle(bundle, outPath); err != nil {
			return err
		}
		fmt.Printf("granted delegated permissions for %s via daemon\n", path)
		return nil
	}

	if !direct {
		logControlFallback("delegate_grant")
	}
	bundle, err = grantDelegationPermissionsDirect(rt, path, permissions)
	if err != nil {
		return err
	}
	if err := writeDelegationGrantBundle(bundle, outPath); err != nil {
		return err
	}
	fmt.Printf("granted delegated permissions for %s\n", path)
	return nil
}

func writeDelegationGrantBundle(bundle *joinBundle, outPath string) error {
	if bundle == nil || outPath == "" {
		return nil
	}
	if err := writeBase64JSONFile(outPath, 0o644, bundle); err != nil {
		return err
	}
	fmt.Printf("wrote authority bundle: %s\n", outPath)
	return nil
}

func grantDelegationPermissionsDirect(rt *AppContext, path zone.ZonePath, permissions []zone.Permission) (*joinBundle, error) {
	if !path.Valid() {
		return nil, fmt.Errorf("invalid delegated zone: %s", path)
	}
	if len(permissions) == 0 {
		return nil, errors.New("at least one permission is required")
	}
	state, err := openState(rt)
	if err != nil {
		return nil, err
	}
	defer state.Close()
	view := state.Common.ReadView()
	zs := view.State.Network.Zones[path]
	if zs == nil || zs.Authority == nil {
		return nil, fmt.Errorf("%w: %s", zone.ErrZoneNotFound, path)
	}
	authority := cloneAuthorityForJoinBundle(zs.Authority)
	if authority == nil {
		return nil, fmt.Errorf("%w: %s", zone.ErrZoneNotFound, path)
	}
	grantPermissionsToAuthority(authority, permissions)
	authority.Epoch++

	var intent corestate.LocalIntent
	if path.IsRoot() {
		intent = corestate.UpdateRootAuthorityIntent{Authority: authority}
	} else {
		intent = corestate.PutDelegationIntent{Parent: path.Parent(), Authority: authority}
	}
	if _, err := state.Common.ApplyLocalIntent(context.Background(), intent, rt.Now()); err != nil {
		return nil, err
	}
	if path.IsRoot() {
		return nil, nil
	}
	return joinBundleFromNetwork(state.Common.ReadView().State.Network, path, rt.Now())
}

func grantPermissionsToAuthority(authority *zone.ZoneAuthority, permissions []zone.Permission) {
	for i := range authority.Keys {
		if len(authority.Keys[i].Capabilities) == 0 {
			authority.Keys[i].Capabilities = []zone.Capability{{}}
		}
		capability := &authority.Keys[i].Capabilities[0]
		seen := map[zone.Permission]bool{}
		for _, existing := range capability.Permissions {
			seen[existing] = true
		}
		for _, perm := range permissions {
			if seen[perm] {
				continue
			}
			capability.Permissions = append(capability.Permissions, perm)
			seen[perm] = true
		}
		slices.Sort(capability.Permissions)
	}
}
