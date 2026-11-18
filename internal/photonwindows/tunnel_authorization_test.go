package photonwindows

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestActiveGatewayRevalidatesCurrentRecordsAcrossRevision(t *testing.T) {
	config, view, now, put := gatewayPlanFixture(t)
	plan := planGateway(context.Background(), config, view, now, gatewayResolvedHosts{"gateway.example": {{IP: net.ParseIP("192.0.2.4")}}})
	view.Revision++
	if RevalidateGatewayPlan(config, view, plan, now).Selected != nil {
		t.Fatal("stale asynchronous plan admitted")
	}
	if revalidateActiveGateway(config, view, plan, now.Add(time.Second)).Selected == nil {
		t.Fatal("unrelated revision broke authenticated binding")
	}
	if revalidateActiveGateway(config, view, plan, now.Add(11*time.Second)).Selected != nil || revalidateActiveGateway(config, view, plan, now.Add(-time.Second)).Selected != nil {
		t.Fatal("DNS cache age/clock regression bypass")
	}
	if !plan.EvaluatedAt.Equal(now) {
		t.Fatal("packet revalidation renewed original DNS timestamp")
	}
	profile, err := ipsec.ParseProfileRecord(view.State.Network.Zones[plan.Selected.Zone].Records[ipsec.RecordKeyProfile])
	if err != nil {
		t.Fatal(err)
	}
	profile.Enabled = false
	put(plan.Selected.Zone, ipsec.RecordKeyProfile, ipsec.RecordTypeProfile, profile)
	if revalidateActiveGateway(config, view, plan, now.Add(time.Second)).Selected != nil {
		t.Fatal("revoked gateway retained across revision")
	}
}

func TestEstablishedGatewayRevalidatesSignedDNSContactWithoutFreshLookup(t *testing.T) {
	config, view, now, put := gatewayPlanFixture(t)
	plan := planGateway(t.Context(), config, view, now, meshPolicyFixtureResolver())
	if plan.Selected == nil {
		t.Fatal(plan.Rejected)
	}
	pinned := plan.Selected
	view.Revision++
	later := now.Add(11 * time.Second)
	current := revalidateEstablishedGateway(config, view, pinned, later, nil)
	if current.Selected == nil || !dataplaneGatewayEqual(*current.Selected, *pinned) {
		t.Fatalf("unchanged signed contact lost its authenticated address: %+v", current)
	}
	if current := revalidateEstablishedGateway(config, view, pinned, now.Add(61*time.Second), nil); current.Selected != nil {
		t.Fatal("expired signed contact retained the tunnel")
	}
	put(pinned.Zone, ipsec.RecordKeyAddresses, ipsec.RecordTypeAddresses, ipsec.AddressRecord{
		Version: 1, UpdatedAt: later.Unix(), Addresses: []ipsec.AddressAdvertisement{{
			ID: pinned.Contact.AddressID, Host: "replacement.example", Source: ipsec.SourceManualDNS, Family: ipsec.FamilyIPv4, TTLSeconds: 60,
		}},
	})
	if current := revalidateEstablishedGateway(config, view, pinned, later, nil); current.Selected != nil {
		t.Fatal("replaced signed hostname retained the old endpoint")
	}
}

func TestActiveLocalTransportBindingRejectsWithdrawal(t *testing.T) {
	state, config, plan, now := transportIdentityFixture(t)
	defer state.Close()
	if _, err := state.EnsureLocalTransport(context.Background(), config, now, plan, netip.MustParseAddrPort("127.0.0.1:17980")); err != nil {
		t.Fatal(err)
	}
	view := state.Store().ReadView()
	binding, err := localTransportAuthorization(config, view, now)
	if err != nil {
		t.Fatal(err)
	}
	view.Revision++
	if fresh, err := localTransportAuthorization(config, view, now.Add(time.Second)); err != nil || fresh != binding {
		t.Fatal("unrelated revision changed local binding")
	}
	delete(view.State.Network.Zones[config.ManagedZone].Records, ipsec.OverlayIntentRecordKey(config.Overlay.ID))
	if _, err := localTransportAuthorization(config, view, now); err == nil {
		t.Fatal("local overlay withdrawal retained SA")
	}
}
