package photonlinux

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"sort"
	"strings"

	transportipsec "github.com/HiggsNet/photon/pkg/transport/ipsec"
)

// CleanupLinkInstances tears down the selected Photon-owned StrongSwan/XFRM
// resources and returns the remaining platform driver instances. Missing IDs
// are already clean and therefore succeed, making retries idempotent.
func (r *LinuxDriver) CleanupIPsecLinks(ctx context.Context, instances map[string]transportipsec.LinkInstance, ids []string) (map[string]transportipsec.LinkInstance, int, error) {
	remaining := maps.Clone(instances)
	if remaining == nil {
		remaining = make(map[string]transportipsec.LinkInstance)
	}
	if len(ids) == 0 {
		return remaining, 0, nil
	}
	if r == nil || r.ipsecDriver == nil {
		return nil, 0, errors.New("ipsec driver is nil")
	}
	if r.xfrmDriver == nil {
		return nil, 0, errors.New("xfrm driver is nil")
	}
	sortedIDs := append([]string(nil), ids...)
	sort.Strings(sortedIDs)
	cleaned := 0
	for _, id := range sortedIDs {
		instance, ok := remaining[id]
		if !ok {
			continue
		}
		if err := instance.Owner.Validate(instance); err != nil {
			return nil, cleaned, fmt.Errorf("refuse cleanup of unmanaged ipsec link %s: %w", id, err)
		}
		action := transportipsec.ReconcileAction{Action: transportipsec.ReconcileActionTeardown, Instance: &instance}
		if _, err := transportipsec.ApplyReconcileAction(ctx, r.ipsecDriver, r.xfrmDriver, action, transportipsec.NetNSSpec{}); err != nil {
			return nil, cleaned, fmt.Errorf("cleanup ipsec link %s: %w", id, err)
		}
		delete(remaining, id)
		cleaned++
	}
	return remaining, cleaned, nil
}

// CleanupOrphanConnections removes Photon-named StrongSwan connections that
// are no longer referenced by platform state.
func (r *LinuxDriver) CleanupIPsecOrphans(ctx context.Context, keep map[string]bool) (int, error) {
	if r == nil || r.ipsecDriver == nil {
		return 0, errors.New("ipsec driver is nil")
	}
	connections, err := r.ipsecDriver.ListConnections(ctx)
	if err != nil {
		return 0, fmt.Errorf("list ipsec connections: %w", err)
	}
	cleaned := 0
	for _, connection := range connections {
		if !strings.HasPrefix(connection.Name, "ipsec-") || keep[connection.Name] {
			continue
		}
		if err := r.ipsecDriver.TerminateSA(ctx, connection.Name); err != nil {
			return cleaned, fmt.Errorf("terminate orphan ipsec connection %s: %w", connection.Name, err)
		}
		if err := r.ipsecDriver.UnloadConnection(ctx, connection.Name); err != nil {
			return cleaned, fmt.Errorf("unload orphan ipsec connection %s: %w", connection.Name, err)
		}
		cleaned++
	}
	return cleaned, nil
}
