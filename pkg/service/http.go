package service

import (
	"bytes"
	"encoding/json"
	"errors"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

const TypeHTTP = "http"
const RecordTypeHTTP = "service.http.v1"

// Authentication policy is public; HTTP passwords remain on the serving node.
type HTTPRecord struct {
	Type         string           `json:"type"`
	Endpoints    []SOCKS5Endpoint `json:"endpoints"`
	AuthRequired bool             `json:"auth_required,omitempty"`
	Active       *bool            `json:"active,omitempty"`
}

func (r HTTPRecord) IsActive() bool { return r.Active == nil || *r.Active }
func (r HTTPRecord) Validate() error {
	if r.Type != TypeHTTP {
		return errors.New("service type must be http")
	}
	return (SOCKS5Record{Type: TypeSOCKS5, Endpoints: r.Endpoints}).Validate()
}

func ParseHTTPRecord(record *zone.Record) (*HTTPRecord, error) {
	if record == nil || record.Type != RecordTypeHTTP || record.Key != "services/http" {
		return nil, errors.New("expected http record services/http")
	}
	var value HTTPRecord
	decoder := json.NewDecoder(bytes.NewReader(record.Value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, err
	}
	if err := value.Validate(); err != nil {
		return nil, err
	}
	return &value, nil
}
