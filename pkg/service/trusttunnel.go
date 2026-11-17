package service

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/routing"
)

const (
	RecordTypeTrustTunnel = "service.trusttunnel.v1"
	TypeTrustTunnel       = "trusttunnel"
	// This public protocol label is not a credential. Access to the internal
	// listener is authorized by Photon/IPsec and the endpoint's Zone ACL.
	TrustTunnelUser = "photon"
)

// TrustTunnelRecord advertises HTTP/3 only. No password or private key belongs
// in the public directory. The signed certificate pin authenticates the server.
// Initial support is deliberately restricted to fixed, non-anycast endpoints.
type TrustTunnelRecord struct {
	Type        string           `json:"type"`
	Endpoints   []SOCKS5Endpoint `json:"endpoints"`
	ServerName  string           `json:"server_name"`
	Fingerprint string           `json:"fingerprint"`
	Active      *bool            `json:"active,omitempty"`
}

func (r TrustTunnelRecord) IsActive() bool { return r.Active == nil || *r.Active }

func (r TrustTunnelRecord) Validate() error {
	if r.Type != TypeTrustTunnel {
		return errors.New("service type must be trusttunnel")
	}
	if err := (SOCKS5Record{Type: TypeSOCKS5, Endpoints: r.Endpoints}).Validate(); err != nil {
		return err
	}
	for _, endpoint := range r.Endpoints {
		if endpoint.Region != "local" {
			return errors.New("trusttunnel currently requires local endpoints")
		}
	}
	if len(r.ServerName) == 0 || len(r.ServerName) > 253 || strings.ContainsAny(r.ServerName, "\r\n\t ,:/") {
		return errors.New("invalid trusttunnel server_name")
	}
	for _, label := range strings.Split(r.ServerName, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("invalid trusttunnel server_name")
		}
		for _, c := range label {
			if c != '-' && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
				return errors.New("invalid trusttunnel server_name")
			}
		}
	}
	decoded, err := hex.DecodeString(r.Fingerprint)
	if err != nil || len(decoded) != 32 || strings.ToLower(r.Fingerprint) != r.Fingerprint {
		return errors.New("trusttunnel requires a lowercase SHA256 certificate fingerprint")
	}
	return nil
}

func ParseTrustTunnelRecord(record *zone.Record) (*TrustTunnelRecord, error) {
	if record == nil || record.Type != RecordTypeTrustTunnel {
		return nil, errors.New("expected trusttunnel service record")
	}
	if record.Key != "services/trusttunnel" {
		return nil, errors.New("service_record_key_mismatch: expected services/trusttunnel")
	}
	var value TrustTunnelRecord
	decoder := json.NewDecoder(bytes.NewReader(record.Value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("unmarshal trusttunnel service: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, err
	}
	if err := value.Validate(); err != nil {
		return nil, err
	}
	return &value, nil
}

// ProxyRecord is a detached read model shared by service consumers, not a new
// wire schema. The strict SOCKS5 v1 parser and its compatibility remain intact.
type ProxyRecord struct {
	Type                    string
	Endpoints               []SOCKS5Endpoint
	Active                  bool
	AuthRequired            bool
	ServerName, Fingerprint string
}

func (r ProxyRecord) IsActive() bool                       { return r.Active }
func (r ProxyRecord) EffectiveEndpoints() []SOCKS5Endpoint { return r.Endpoints }
func IsProxyRecordType(kind string) bool {
	return kind == RecordTypeSOCKS5 || kind == RecordTypeTrustTunnel || kind == RecordTypeHTTP
}

func ParseProxyRecord(record *zone.Record) (*ProxyRecord, error) {
	if record == nil {
		return nil, errors.New("nil service record")
	}
	if record.Type == RecordTypeHTTP {
		r, err := ParseHTTPRecord(record)
		if err != nil {
			return nil, err
		}
		return &ProxyRecord{Type: TypeHTTP, Endpoints: r.Endpoints, Active: r.IsActive(), AuthRequired: r.AuthRequired}, nil
	}
	if record.Type == RecordTypeSOCKS5 {
		r, err := ParseSOCKS5Record(record)
		if err != nil {
			return nil, err
		}
		return &ProxyRecord{Type: TypeSOCKS5, Endpoints: r.EffectiveEndpoints(), Active: r.IsActive()}, nil
	}
	r, err := ParseTrustTunnelRecord(record)
	if err != nil {
		return nil, err
	}
	return &ProxyRecord{Type: TypeTrustTunnel, Endpoints: r.Endpoints, Active: r.IsActive(), ServerName: r.ServerName, Fingerprint: r.Fingerprint}, nil
}

func AuthorizeProxyRecord(record *zone.Record, authorized *routing.AuthorizedRouteSet) (*routing.AssignmentEntry, error) {
	r, err := ParseProxyRecord(record)
	if err != nil {
		return nil, err
	}
	if authorized == nil {
		return nil, errors.New("service authorization set is nil")
	}
	if !r.Active {
		return nil, errors.New("service record is withdrawn")
	}
	assignment, err := authorizeEndpoints(record, r.Endpoints, authorized)
	if err != nil {
		return nil, err
	}
	if r.Type == TypeTrustTunnel {
		for _, endpoint := range r.Endpoints {
			// Anycast needs an explicit multi-publisher pin/session contract.
			// Do not silently treat it as a fixed authenticated server.
			for _, candidate := range authorized.AllAssignments {
				if candidate != nil && candidate.AssignedTo == record.Zone && candidate.Shared && candidate.Prefix.Contains(netip.MustParseAddr(endpoint.Address)) {
					return nil, errors.New("trusttunnel shared assignments are not supported")
				}
			}
		}
	}
	return assignment, nil
}
