package photonwindows

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/netip"
	"slices"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

// GatewayCandidate is an offline transport diagnosis, never a route or SA grant.
type GatewayCandidate struct {
	Zone        zone.ZonePath        `json:"zone"`
	Contacts    []ipsec.ContactPoint `json:"contacts,omitempty"`
	Fingerprint string               `json:"fingerprint,omitempty"`
	Rejected    string               `json:"rejected,omitempty"`
}

// GatewayCandidates rechecks authority and key lifetimes at now, even when the
// verified revision has not changed. Bootstrap hints cannot authorize contacts.
// DNS-only addresses are left for the future online connection planner.
func GatewayCandidates(config *Config, view corestate.View, now time.Time) []GatewayCandidate {
	out := make([]GatewayCandidate, 0, len(config.Gateway.AllowedZones))
	for _, peer := range config.Gateway.AllowedZones {
		candidate := GatewayCandidate{Zone: peer}
		contacts, fingerprint, err := gatewayContacts(config, view, peer, now)
		if err != nil {
			candidate.Rejected = err.Error()
		} else {
			candidate.Contacts, candidate.Fingerprint = contacts, fingerprint
		}
		out = append(out, candidate)
	}
	return out
}

func gatewayContacts(config *Config, view corestate.View, peer zone.ZonePath, now time.Time) ([]ipsec.ContactPoint, string, error) {
	fail := func(reason string) ([]ipsec.ContactPoint, string, error) { return nil, "", errors.New(reason) }
	if view.State == nil || view.State.Network == nil {
		return fail("verified state is absent")
	}
	network := view.State.Network
	if peer == config.ManagedZone {
		return fail("gateway is the local node")
	}
	if err := photoncrypto.VerifyPinnedRoot(network, config.TrustedRootPublicKey); err != nil {
		return fail(err.Error())
	}
	if err := photoncrypto.VerifyChain(network, peer, now); err != nil {
		return fail(err.Error())
	}
	zs := network.Zones[peer]
	// Extract only the selected overlay so unrelated records do not authorize
	// this candidate or cause an otherwise valid candidate to be rejected.
	selected := zone.NewNetworkState()
	selected.Zones[peer] = zone.NewZoneState(peer, zs.Authority)
	for _, key := range []string{ipsec.RecordKeyProfile, ipsec.RecordKeyAddresses, ipsec.RecordKeyPorts, ipsec.RecordKeyTransportKey, ipsec.OverlayIntentRecordKey(config.Overlay.ID)} {
		record := zs.Records[key]
		if record == nil || record.Zone != peer || record.Key != key {
			return fail("missing or mismatched record: " + key)
		}
		if err := photoncrypto.VerifyRecord(record, zs.Authority, now); err != nil {
			return fail(key + ": " + err.Error())
		}
		selected.Zones[peer].Records[key] = record
	}
	records, err := ipsec.ExtractNodeRecords(selected, peer, now)
	if err != nil {
		return fail(err.Error())
	}
	profile, key := records.Profile, records.TransportKey
	if !profile.Enabled || (profile.Role != ipsec.RoleIn && profile.Role != ipsec.RoleBoth) {
		return fail("gateway does not accept inbound connections")
	}
	if !slices.Contains(profile.PathModes, ipsec.PathModeFamilyRedundant) {
		return fail("gateway does not support family-redundant paths")
	}
	if key.Algorithm != ipsec.AlgorithmEd25519 {
		return fail("Windows v1 requires an Ed25519 transport key")
	}
	if (key.NotBefore != 0 && now.Unix() < key.NotBefore) || (key.NotAfter != 0 && now.Unix() >= key.NotAfter) {
		return fail("transport key is outside its validity period")
	}
	public, err := ipsec.DecodeTransportPublicKey(*key)
	if err != nil {
		return fail(err.Error())
	}
	if len(public) != ed25519.PublicKeySize || profile.TransportKeyFingerprint != key.Fingerprint {
		return fail("profile and transport key do not match")
	}
	contacts, err := ipsec.ResolveContactPoints(context.Background(), records.Addresses, records.Ports, now, ipsec.AddressCandidateOptions{Now: now, AllowPrivateLocal: true})
	if err != nil {
		return fail(err.Error())
	}
	intent := records.OverlayIntents[config.Overlay.ID]
	var accepted []ipsec.ContactPoint
	for _, contact := range contacts {
		addr, err := netip.ParseAddr(contact.Address)
		if err != nil || addr.IsUnspecified() || addr.IsMulticast() || addr.IsLoopback() || addr.IsLinkLocalUnicast() {
			continue
		}
		if !slices.Contains(profile.AddressFamilies, contact.Family) {
			continue
		}
		if !slices.Contains(intent.PathKeys, ipsec.DefaultPathKey) && !slices.Contains(intent.PathKeys, "family:"+contact.Family) {
			continue
		}
		if profile.NAT.InboundReachable == ipsec.NATReachableFalse {
			continue
		}
		accepted = append(accepted, contact)
	}
	if len(accepted) == 0 {
		return fail("no usable signed IP contact (DNS resolution is not performed offline)")
	}
	return accepted, key.Fingerprint, nil
}
