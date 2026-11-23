package state

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/service"
)

func TestProxyV2PublicationAndWithdrawal(t *testing.T) {
	install, _ := identityInstallFixture(t)
	store := NewStore(&VerifiedState{ManagedZone: install.ManagedZone, Network: install.Network, IdentityPrivateKey: install.IdentityPrivateKey}, nil, nil)
	now := time.Unix(1800000000, 0)
	lease := service.ProxyV2Lease{Active: true, ExpiresAt: now.Add(time.Hour).Unix()}
	body := func(value any) json.RawMessage {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	id := service.ProxyV2Record{Key: service.ProxyV2IdentityKey, Type: service.ProxyV2IdentityType, Value: body(service.ProxyV2Identity{
		ProxyV2Lease: lease, PublicKey: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	})}
	tls := service.ProxyV2Record{Key: service.ProxyV2TLSPrefix + "node", Type: service.ProxyV2TLSType, Value: body(service.ProxyV2TLS{
		ProxyV2Lease: lease, Pins: []string{strings.Repeat("ab", 32)},
	})}
	apply := func(records ...service.ProxyV2Record) (LocalIntentResult, error) {
		return store.ApplyLocalIntent(t.Context(), ProxyV2Intent{Publication: service.ProxyV2Publication{Records: records, Replace: true}}, now)
	}
	invalid := tls
	invalid.Key = "unrelated/key"
	if _, err := apply(id, invalid); err == nil {
		t.Fatal("invalid record accepted")
	}
	if got := store.ReadView().State.Network.Zones[install.ManagedZone].Records[id.Key]; got != nil {
		t.Fatal("partial publication")
	}
	if result, err := apply(id, tls); err != nil || !result.Committed {
		t.Fatalf("valid publication: %+v %v", result, err)
	}
	if result, err := apply(id, tls); err != nil || result.Committed {
		t.Fatalf("same publication changed revision: %+v %v", result, err)
	}
	if _, err := apply(id); err != nil {
		t.Fatal(err)
	}
	record := store.ReadView().State.Network.Zones[install.ManagedZone].Records[tls.Key]
	_, withdrawn, err := service.ParseProxyV2Record(service.ProxyV2Record{Key: record.Key, Type: record.Type, Value: record.Value})
	if err != nil || withdrawn.Active || record.Version != 2 {
		t.Fatalf("withdrawal %+v %v", withdrawn, err)
	}
}
