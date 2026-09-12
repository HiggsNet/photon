package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	photonstate "github.com/HiggsNet/photon/internal/state"

	"github.com/HiggsNet/photon/internal/inspect"
	inspecttext "github.com/HiggsNet/photon/internal/inspect/text"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

type manualPortRotateResult struct {
	Zone               zone.ZonePath `json:"zone"`
	PreviousGeneration uint64        `json:"previous_generation,omitempty"`
	CurrentGeneration  uint64        `json:"current_generation"`
	PreviousIKE        uint16        `json:"previous_ike,omitempty"`
	PreviousNATT       uint16        `json:"previous_natt,omitempty"`
	CurrentIKE         uint16        `json:"current_ike"`
	CurrentNATT        uint16        `json:"current_natt"`
	PreviousValidUntil int64         `json:"previous_valid_until,omitempty"`
}

func debugRotatePort(direct bool) error {
	rt, err := NewAppContext()
	if err != nil {
		return err
	}
	if !direct {
		result, ok, err := rotateIPsecPortViaControl(rt)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("daemon control socket unavailable; start the daemon to trigger firewall/IPsec reconcile, or rerun with --direct to write the local DB only")
		}
		printManualPortRotateResult("daemon", result)
		return nil
	}
	result, err := rotateIPsecPortDirect(rt)
	if err != nil {
		return err
	}
	printManualPortRotateResult("direct", result)
	return nil
}

func debugRotate(ctx context.Context, filter string) error {
	rt, err := NewAppContext()
	if err != nil {
		return err
	}
	if view, ok, err := readCanonicalViewViaControl[inspect.LinksDebugView](rt, controlRequest{Method: "links_view"}); err != nil {
		return err
	} else if ok {
		fmt.Printf("daemon: online link_instances=%d desired_links=%d last_link_error=%s\n",
			view.Inspection.Summary.LinkInstances,
			view.Inspection.Summary.DesiredLinks,
			dash(view.Inspection.Summary.LastError),
		)
		return writeDebugRotateFromView(os.Stdout, view, filter)
	}
	return fmt.Errorf("daemon control socket unavailable; IPsec rotation runtime state requires a running daemon")
}

func writeDebugRotateFromView(w io.Writer, view inspect.LinksDebugView, filter string) error {
	rotate := inspect.BuildRotateDebug(inspect.RotateDebugInput{
		Inspection:       view.Inspection,
		ReplannedDesired: view.ReplannedDesired, ReplanIgnored: view.ReplanIgnored,
		LastDesiredLinks: view.LastDesiredLinks, DesiredPlanSource: view.DesiredPlanSource,
		Filter: filter, StoredLabel: "daemon_sas", LiveLabel: "live_sas",
		StoredSAs: view.StoredSAs, LiveSAs: view.LiveSAs, LiveSAError: view.LiveSAError,
	})
	return inspecttext.WriteRotateDebug(w, rotate)
}

func linkSAStatesFromIPsecSAs(sas []ipsec.SAState) []photonstate.LinkSAState {
	out := make([]photonstate.LinkSAState, 0, len(sas))
	for _, sa := range sas {
		out = append(out, photonstate.LinkSAState{
			Name:            sa.Name,
			IKEAgeSeconds:   sa.IKEAgeSeconds,
			ChildAgeSeconds: sa.ChildAgeSeconds,
			InboundBytes:    sa.InboundBytes,
			InboundPackets:  sa.InboundPackets,
			InboundIdleSecs: sa.InboundIdleSecs,
			InboundKnown:    sa.InboundKnown,
			Peer:            sa.Peer,
			ChildSA:         sa.ChildSA,
			IKEState:        sa.IKEState,
			ChildState:      sa.ChildState,
			XFRMIfID:        sa.XFRMIfID,
			ReqID:           sa.ReqID,
			LocalIdentity:   sa.LocalIdentity,
			RemoteIdentity:  sa.RemoteIdentity,
			LocalEndpoint:   sa.LocalEndpoint,
			RemoteEndpoint:  sa.RemoteEndpoint,
			Endpoint:        sa.Endpoint,
			Established:     sa.Established,
		})
	}
	return out
}

func printManualPortRotateResult(mode string, result *manualPortRotateResult) {
	if result == nil {
		return
	}
	_ = inspecttext.WriteManualPortRotateResult(os.Stdout, mode, inspect.ManualPortRotateView{
		Zone:               result.Zone,
		PreviousGeneration: result.PreviousGeneration,
		CurrentGeneration:  result.CurrentGeneration,
		PreviousIKE:        result.PreviousIKE,
		PreviousNATT:       result.PreviousNATT,
		CurrentIKE:         result.CurrentIKE,
		CurrentNATT:        result.CurrentNATT,
		PreviousValidUntil: result.PreviousValidUntil,
	})
}

func rotateIPsecPortDirect(rt *AppContext) (*manualPortRotateResult, error) {
	state, err := openState(rt)
	if err != nil {
		return nil, err
	}
	defer state.Close()
	common := state.Common.ReadView()
	if common.State == nil {
		return nil, fmt.Errorf("state owners are not initialized")
	}
	daemon := &Daemon{State: state}
	record, result, err := planLocalIPsecPortRotation(rt.Config, common.State, rt.Now())
	if err != nil {
		return nil, err
	}
	value, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	committed, err := daemon.commitLocalProtocols(context.Background(), uint64(common.Revision), []corestate.LocalIntent{
		corestate.PutProtocolRecordIntent{Kind: corestate.ProtocolRecordIPsec, Zone: common.State.ManagedZone, Key: ipsec.RecordKeyPorts, Type: ipsec.RecordTypePorts, Value: value},
	}, nil, rt.Now())
	if err != nil {
		return nil, err
	}
	if !committed.LinuxStateCommitted && !committed.Common.Committed {
		return nil, fmt.Errorf("manual port rotate produced unchanged state")
	}
	return result, nil
}

func planLocalIPsecPortRotation(config *appConfig, verified *corestate.VerifiedState, now time.Time) (*ipsec.PortRecord, *manualPortRotateResult, error) {
	if config == nil {
		config = defaultAppConfig()
	}
	if verified == nil || verified.Network == nil {
		return nil, nil, fmt.Errorf("verified state is nil")
	}
	if verified.ManagedZone == zone.RootZone || !verified.ManagedZone.Valid() {
		return nil, nil, fmt.Errorf("managed zone is required")
	}
	if len(verified.IdentityPrivateKey) == 0 {
		return nil, nil, fmt.Errorf("managed zone private key is required")
	}
	mode := config.IPsec.PortMode
	if mode == "" {
		mode = ipsec.PortModeFixed
	}
	if mode != ipsec.PortModeRange {
		return nil, nil, fmt.Errorf("manual port rotate requires ipsec.port_mode=range, got %q", mode)
	}
	if now.IsZero() {
		now = time.Now()
	}
	existing := existingIPsecPortRecord(verified)
	nextGeneration := uint64(1)
	if existing != nil && existing.Current != nil && existing.Current.Generation > 0 {
		nextGeneration = existing.Current.Generation + 1
	}
	record, err := ipsec.PlanPortRecord(ipsec.PortPlanOptions{
		Mode:          mode,
		Range:         &config.IPsec.PortRange,
		FixedIKE:      uint16(ipsec.DefaultIKEPort),
		FixedNATT:     uint16(ipsec.DefaultNATTPort),
		Generation:    nextGeneration,
		Previous:      existing,
		PreviousGrace: config.IPsec.PortPreviousGrace,
		Now:           now,
	})
	if err != nil {
		return nil, nil, err
	}
	result := &manualPortRotateResult{
		Zone:              verified.ManagedZone,
		CurrentGeneration: record.Current.Generation,
		CurrentIKE:        record.Current.IKE.Advertised,
		CurrentNATT:       record.Current.NATT.Advertised,
	}
	if existing != nil && existing.Current != nil {
		result.PreviousGeneration = existing.Current.Generation
		result.PreviousIKE = existing.Current.IKE.Advertised
		result.PreviousNATT = existing.Current.NATT.Advertised
	}
	if len(record.Previous) > 0 {
		result.PreviousValidUntil = record.Previous[0].ValidUntil
	}
	return record, result, nil
}
