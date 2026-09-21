package main

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

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
	config, err := loadAppConfig()
	if err != nil {
		return err
	}

	bundle, controlled, err := grantDelegationPermissionsViaControl(config, path, permissions, direct)
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
	bundle, err = grantDelegationPermissionsDirect(config, path, permissions, time.Now())
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

func grantDelegationPermissionsDirect(config *appConfig, path zone.ZonePath, permissions []zone.Permission, now time.Time) (*joinBundle, error) {
	if !path.Valid() {
		return nil, fmt.Errorf("invalid delegated zone: %s", path)
	}
	if path == zone.RootZone {
		return nil, errors.New("root authority is immutable and its key is implicitly privileged")
	}
	if len(permissions) == 0 {
		return nil, errors.New("at least one permission is required")
	}
	state, err := openState(config)
	if err != nil {
		return nil, err
	}
	defer state.Close()
	intent := corestate.GrantDelegationIntent{Zone: path, Permissions: permissions}
	if _, err := state.Common.ApplyLocalIntent(context.Background(), intent, now); err != nil {
		return nil, err
	}
	return joinBundleFromNetwork(state.Common.ReadView().State.Network, path, now)
}
