package service

import (
	"encoding/json"
	"testing"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

func TestHTTPRecordHasIndependentStrictSchema(t *testing.T) {
	value := HTTPRecord{Type: TypeHTTP, Endpoints: []SOCKS5Endpoint{{Region: "local", Address: "fd42::21", Port: 3128}}, AuthRequired: true}
	data, _ := json.Marshal(value)
	r := &zone.Record{Key: "services/http", Type: RecordTypeHTTP, Value: data}
	parsed, err := ParseProxyRecord(r)
	if err != nil || parsed.Type != TypeHTTP || !parsed.AuthRequired {
		t.Fatal(parsed, err)
	}
	if _, err := ParseSOCKS5Record(r); err == nil {
		t.Fatal("HTTP was treated as SOCKS5")
	}
	var raw map[string]any
	_ = json.Unmarshal(data, &raw)
	raw["password"] = "must-stay-local"
	r.Value, _ = json.Marshal(raw)
	if _, err := ParseProxyRecord(r); err == nil {
		t.Fatal("secret credential accepted in HTTP directory record")
	}
}
