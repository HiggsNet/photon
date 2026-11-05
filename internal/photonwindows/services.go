package photonwindows

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
	photonservice "github.com/HiggsNet/photon/pkg/service"
)

type ServiceDirectory struct {
	InstanceID      string         `json:"instance_id"`
	RootFingerprint string         `json:"root_fingerprint"`
	ManagedZone     zone.ZonePath  `json:"managed_zone"`
	Revision        uint64         `json:"revision"`
	ObservedAt      time.Time      `json:"observed_at"`
	ValidUntil      time.Time      `json:"valid_until"`
	Services        []ServiceEntry `json:"services"`
	AdapterName     string         `json:"adapter_name"`
	BypassPrefixes  []netip.Prefix `json:"bypass_prefixes"`
	BypassDomains   []string       `json:"bypass_domains"`
}

type ServiceEntry struct {
	ID         string            `json:"id"`
	Owner      zone.ZonePath     `json:"owner"`
	RecordKey  string            `json:"record_key"`
	Version    uint64            `json:"version"`
	Status     string            `json:"status"`
	Diagnostic string            `json:"diagnostic,omitempty"`
	Endpoints  []ServiceEndpoint `json:"endpoints"`
}

type ServiceEndpoint struct {
	ID      string `json:"id"`
	Region  string `json:"region"`
	Address string `json:"address"`
	Port    uint16 `json:"port"`
}

// Services borrows the owner's store handle, then detaches and verifies outside
// the packet-owner loop. No database handle or signing material crosses IPC.
func (d *Daemon) Services(ctx context.Context) (ServiceDirectory, error) {
	ctx, cancel := context.WithTimeout(ctx, controlTimeout)
	defer cancel()
	result := make(chan gatewayPlanSample, 1)
	select {
	case d.plans <- result:
	case <-d.done:
		return ServiceDirectory{}, net.ErrClosed
	case <-ctx.Done():
		return ServiceDirectory{}, ctx.Err()
	}
	select {
	case sample := <-result:
		directory, err := buildServiceDirectory(ctx, d.config, sample.store.ReadView(), d.instanceID, time.Now())
		if err != nil {
			return ServiceDirectory{}, err
		}
		for _, candidate := range sample.plan.Candidates {
			for _, contact := range candidate.Contacts {
				if host := proxyBypassDomain(contact.Host); host != "" {
					directory.BypassDomains = append(directory.BypassDomains, host)
				}
				if address, err := netip.ParseAddr(contact.Address); err == nil {
					directory.BypassPrefixes = append(directory.BypassPrefixes, netip.PrefixFrom(address, address.BitLen()))
				}
			}
		}
		slices.SortFunc(directory.BypassPrefixes, func(a, b netip.Prefix) int { return strings.Compare(a.String(), b.String()) })
		directory.BypassPrefixes = slices.Compact(directory.BypassPrefixes)
		slices.Sort(directory.BypassDomains)
		directory.BypassDomains = slices.Compact(directory.BypassDomains)
		return directory, nil
	case <-d.done:
		return ServiceDirectory{}, net.ErrClosed
	case <-ctx.Done():
		return ServiceDirectory{}, ctx.Err()
	}
}

func buildServiceDirectory(ctx context.Context, config *Config, view corestate.View, instanceID string, now time.Time) (ServiceDirectory, error) {
	if config == nil || view.State == nil || view.State.Network == nil {
		return ServiceDirectory{}, errors.New("verified service state is unavailable")
	}
	network := view.State.Network
	if err := photoncrypto.VerifyPinnedRoot(network, config.TrustedRootPublicKey); err != nil {
		return ServiceDirectory{}, err
	}
	root := sha256.Sum256(config.TrustedRootPublicKey)
	out := ServiceDirectory{InstanceID: instanceID, RootFingerprint: hex.EncodeToString(root[:]), ManagedZone: config.ManagedZone, Revision: uint64(view.Revision), ObservedAt: now, ValidUntil: now.Add(5 * time.Second), Services: []ServiceEntry{}}
	out.AdapterName = config.Wintun.AdapterName
	out.BypassPrefixes = slices.Clone(config.Overlay.SplitRoutes)
	for _, address := range gossipRouteTargets(view, now) {
		out.BypassPrefixes = append(out.BypassPrefixes, netip.PrefixFrom(address, address.BitLen()))
	}
	for _, hint := range config.Gateway.BootstrapHints {
		if endpoint, err := netip.ParseAddrPort(hint.Address); err == nil {
			out.BypassPrefixes = append(out.BypassPrefixes, netip.PrefixFrom(endpoint.Addr(), endpoint.Addr().BitLen()))
		} else if host, _, err := net.SplitHostPort(hint.Address); err == nil {
			if domain := proxyBypassDomain(host); domain != "" {
				out.BypassDomains = append(out.BypassDomains, domain)
			}
		}
	}
	verifier := &photoncrypto.Verifier{}
	authorized := currentAuthorizedRouteSetWithVerifier(config, view, now, verifier)
	paths := make([]zone.ZonePath, 0, len(network.Zones))
	for path := range network.Zones {
		paths = append(paths, path)
	}
	slices.Sort(paths)
	for _, path := range paths {
		if err := ctx.Err(); err != nil {
			return ServiceDirectory{}, err
		}
		zs := network.Zones[path]
		if zs == nil {
			continue
		}
		// A snapshot must not outlive a known trust transition, even at an
		// unchanged verified revision. Using all zones is conservative.
		if zs.Authority != nil {
			for _, key := range zs.Authority.Keys {
				if key.NotAfter > now.Unix() && time.Unix(key.NotAfter, 0).Before(out.ValidUntil) {
					out.ValidUntil = time.Unix(key.NotAfter, 0)
				}
			}
		}
		for _, revocation := range zs.Revocations {
			if revocation != nil && revocation.RevokedAt > now.Unix() && time.Unix(revocation.RevokedAt, 0).Before(out.ValidUntil) {
				out.ValidUntil = time.Unix(revocation.RevokedAt, 0)
			}
		}
		keys := make([]string, 0)
		for key, record := range zs.Records {
			if strings.HasPrefix(key, photonservice.RecordKeyPrefix) && record != nil && record.Type == photonservice.RecordTypeSOCKS5 {
				keys = append(keys, key)
			}
		}
		slices.Sort(keys)
		chainErr := verifier.VerifyChain(network, path, now)
		for _, key := range keys {
			if err := ctx.Err(); err != nil {
				return ServiceDirectory{}, err
			}
			record := zs.Records[key]
			entry := ServiceEntry{ID: string(path) + "/" + key, Owner: path, RecordKey: key, Version: record.Version, Status: "invalid", Endpoints: []ServiceEndpoint{}}
			value, parseErr := photonservice.ParseSOCKS5Record(record)
			switch {
			case chainErr != nil:
				entry.Status, entry.Diagnostic = "untrusted", "owner_authority_invalid"
			case record.Zone != path || record.Key != key || verifier.VerifyRecord(record, zs.Authority, now) != nil:
				entry.Diagnostic = "service_signature_invalid"
			case parseErr != nil:
				entry.Diagnostic = "service_record_invalid"
			case !value.IsActive():
				entry.Status = "withdrawn"
			default:
				if _, err := photonservice.AuthorizeSOCKS5Record(record, authorized); err != nil {
					entry.Status, entry.Diagnostic = "unauthorized", "endpoint_assignment_invalid"
				} else {
					entry.Status = "active"
					for _, endpoint := range value.EffectiveEndpoints() {
						id := sha256.Sum256([]byte(entry.ID + "\x00" + endpoint.Region + "\x00" + net.JoinHostPort(endpoint.Address, strconv.Itoa(int(endpoint.Port)))))
						entry.Endpoints = append(entry.Endpoints, ServiceEndpoint{ID: hex.EncodeToString(id[:16]), Region: endpoint.Region, Address: endpoint.Address, Port: endpoint.Port})
					}
					slices.SortFunc(entry.Endpoints, func(a, b ServiceEndpoint) int { return strings.Compare(a.ID, b.ID) })
				}
			}
			out.Services = append(out.Services, entry)
		}
	}
	return out, ctx.Err()
}

func proxyBypassDomain(host string) string {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if _, err := netip.ParseAddr(host); err == nil || host == "" || len(host) > 253 {
		return ""
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return ""
		}
		for _, c := range label {
			if c != '-' && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
				return ""
			}
		}
	}
	return host
}
