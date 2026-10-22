package photonwindows

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
	"github.com/HiggsNet/photon/pkg/routing"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

var (
	errLeafRouteAuthorityUnavailable   = errors.New("leaf: verified route authority unavailable")
	errLeafHostAssignmentUnavailable   = errors.New("leaf: no authorized unicast host assignment in configured split routes")
	errLeafHostAnnouncementUnavailable = errors.New("leaf: authorized host assignment has no active route announcement")
)

// leafAssignedHosts never picks an address from a network or shared/anycast
// assignment. A Windows leaf owns explicit unicast /32 and /128 assignments.
func leafAssignedHosts(config *Config, set *routing.AuthorizedRouteSet) []netip.Prefix {
	var hosts []netip.Prefix
	if set == nil {
		return nil
	}
	for _, a := range set.AllAssignments {
		p := a.Prefix
		if a.AssignedTo != config.ManagedZone || a.Shared || p.Bits() != p.Addr().BitLen() || !businessAddress(p.Addr()) {
			continue
		}
		for _, split := range config.Overlay.SplitRoutes {
			if split.Contains(p.Addr()) {
				hosts = append(hosts, p)
				break
			}
		}
	}
	slices.SortFunc(hosts, func(a, b netip.Prefix) int { return a.Addr().Compare(b.Addr()) })
	return slices.Compact(hosts)
}

// EnsureLocalLeafRoutes reconciles only this node's existing typed auto-route
// owner. Manual withdrawals remain manual; no address is inferred from a pool.
func (source *State) EnsureLocalLeafRoutes(ctx context.Context, config *Config, now time.Time) error {
	if source == nil {
		return corestate.ErrVerifiedStoreClosed
	}
	source.mu.RLock()
	defer source.mu.RUnlock()
	if source.closed {
		return corestate.ErrVerifiedStoreClosed
	}
	view := source.common.ReadView()
	if config == nil || view.State == nil || view.State.ManagedZone != config.ManagedZone || !bytes.Equal(view.State.TrustedRootPublicKey, config.TrustedRootPublicKey) {
		return errors.New("leaf: identity configuration mismatch")
	}
	if err := photoncrypto.VerifyChain(view.State.Network, config.ManagedZone, now); err != nil {
		return err
	}
	set := currentAuthorizedRouteSet(config, view, now)
	if set == nil {
		return errLeafRouteAuthorityUnavailable
	}
	desired := leafAssignedHosts(config, set)
	local := view.State.Network.Zones[config.ManagedZone]
	var intents []corestate.LocalIntent
	for _, p := range desired {
		key, _ := routing.NormalizeRouteAnnouncementKey(p.String())
		if record := local.Records[key]; record != nil {
			if photoncrypto.VerifyRecord(record, local.Authority, now) != nil {
				return errors.New("leaf: existing route is untrusted")
			}
			previous, err := routing.ParseRouteAnnouncementRecord(record)
			if err != nil {
				return err
			}
			if previous.Active || previous.Controller != routing.RouteControllerAuto {
				continue
			}
		}
		intents = append(intents, corestate.AnnounceRouteIntent{Zone: config.ManagedZone, Prefix: p.String(), Controller: routing.RouteControllerAuto})
	}
	for key, record := range local.Records {
		if !strings.HasPrefix(key, routing.RecordKeyPrefixRoutes) {
			continue
		}
		previous, err := routing.ParseRouteAnnouncementRecord(record)
		if err != nil || !previous.Active || previous.Controller != routing.RouteControllerAuto {
			continue
		}
		if photoncrypto.VerifyRecord(record, local.Authority, now) != nil {
			return errors.New("leaf: existing auto route is untrusted")
		}
		prefix, err := netip.ParsePrefix(previous.Prefix)
		if err != nil {
			return err
		}
		if !slices.Contains(desired, prefix) {
			intents = append(intents, corestate.WithdrawRouteIntent{Zone: config.ManagedZone, Prefix: previous.Prefix, Controller: routing.RouteControllerAuto})
		}
	}
	if len(intents) == 0 {
		return nil
	}
	_, err := source.common.ApplyLocalIntentsAtRevision(ctx, intents, now, view.Revision)
	return err
}

// leafDeviceIntent requires both the host assignment and its current signed
// announcement. The OS route merely directs a split aggregate to the device;
// the userspace pipeline still checks each actual route on every packet.
func leafDeviceIntent(config *Config, view corestate.View, now time.Time) (addresses, splitRoutes []netip.Prefix) {
	return leafDeviceIntentFromSet(config, currentAuthorizedRouteSet(config, view, now))
}

func leafDeviceIntentFromSet(config *Config, set *routing.AuthorizedRouteSet) (addresses, splitRoutes []netip.Prefix) {
	for _, p := range leafAssignedHosts(config, set) {
		if set.Announced[config.ManagedZone][p] != nil {
			addresses = append(addresses, p)
		}
	}
	for _, p := range config.Overlay.SplitRoutes {
		for _, a := range addresses {
			if p.Addr().BitLen() == a.Addr().BitLen() {
				splitRoutes = append(splitRoutes, p)
				break
			}
		}
	}
	return addresses, splitRoutes
}

// requiredLeafDeviceIntentFromSet explains the same address admission used to
// open the device. A missing verified route set is never an IPAM diagnosis.
func requiredLeafDeviceIntentFromSet(config *Config, set *routing.AuthorizedRouteSet) (addresses, splitRoutes []netip.Prefix, err error) {
	if set == nil {
		return nil, nil, errLeafRouteAuthorityUnavailable
	}
	if len(leafAssignedHosts(config, set)) == 0 {
		return nil, nil, errLeafHostAssignmentUnavailable
	}
	addresses, splitRoutes = leafDeviceIntentFromSet(config, set)
	if len(addresses) == 0 {
		return nil, nil, errLeafHostAnnouncementUnavailable
	}
	return addresses, splitRoutes, nil
}

// leafLinkLocalAddresses uses the same link identity, path and address epoch as
// Linux's transport planner. Unsupported/automatic OS link-local modes are not
// guessed, nor is a peer address learned from unauthenticated traffic.
func leafLinkLocalAddresses(config *Config, view corestate.View, plan GatewayPlan, now time.Time) (netip.Addr, netip.Addr, error) {
	return leafLinkLocalAddressesWithVerifier(config, view, plan, now, nil)
}

func leafLinkLocalAddressesWithVerifier(config *Config, view corestate.View, plan GatewayPlan, now time.Time, verifier *photoncrypto.Verifier) (netip.Addr, netip.Addr, error) {
	fail := func(err error) (netip.Addr, netip.Addr, error) { return netip.Addr{}, netip.Addr{}, err }
	if config == nil || view.State == nil || view.State.Network == nil || plan.Selected == nil {
		return fail(errors.New("leaf: no gateway"))
	}
	if err := photoncrypto.VerifyPinnedRoot(view.State.Network, config.TrustedRootPublicKey); err != nil {
		return fail(err)
	}
	key := ipsec.OverlayIntentRecordKey(config.Overlay.ID)
	var overlay *ipsec.OverlayIntentRecord
	for _, path := range []zone.ZonePath{config.ManagedZone, plan.Selected.Zone} {
		zs := view.State.Network.Zones[path]
		if zs == nil {
			return fail(errors.New("leaf: overlay authority absent"))
		}
		if err := verifier.VerifyChain(view.State.Network, path, now); err != nil {
			return fail(err)
		}
		record := zs.Records[key]
		if record == nil || record.Zone != path || record.Key != key {
			return fail(errors.New("leaf: overlay absent"))
		}
		if err := verifier.VerifyRecord(record, zs.Authority, now); err != nil {
			return fail(err)
		}
		current, err := ipsec.ParseOverlayIntentRecord(record)
		if err != nil {
			return fail(err)
		}
		if current.TunnelAddress.Mode != ipsec.TunnelAddressDerivedLinkLocal {
			return fail(errors.New("leaf: Babel requires derived-link-local overlay"))
		}
		if overlay != nil && (overlay.TunnelAddress != current.TunnelAddress || !slices.Equal(overlay.PathKeys, current.PathKeys)) {
			return fail(errors.New("leaf: overlay path mismatch"))
		}
		overlay = current
	}
	address, err := netip.ParseAddr(plan.Selected.Contact.Address)
	if err != nil {
		return fail(err)
	}
	family := ipsec.FamilyIPv6
	if address.Is4() {
		family = ipsec.FamilyIPv4
	}
	pathKey := "family:" + family
	if !slices.Contains(overlay.PathKeys, pathKey) {
		pathKey = ipsec.DefaultPathKey
		if !slices.Contains(overlay.PathKeys, pathKey) {
			return fail(fmt.Errorf("leaf: overlay has no %s path", family))
		}
	}
	group := ipsec.LinkGroupSpec{ID: config.Overlay.ID, TunnelAddressSpec: overlay.TunnelAddress}
	base := ipsec.TransportLinkSpec{LocalZone: config.ManagedZone, PeerZone: plan.Selected.Zone, LinkID: ipsec.StableLinkID(config.ManagedZone, plan.Selected.Zone, group.ID, pathKey), PathKey: pathKey}
	spec, err := ipsec.RuntimeSpecForPortGeneration(base, group, plan.Selected.Contact.Generation)
	if err != nil {
		return fail(err)
	}
	return spec.LocalTunnelAddr, spec.PeerTunnelAddr, nil
}
