package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/HiggsNet/photon/internal/controlapi"
	"github.com/HiggsNet/photon/internal/inspect"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/routing/bird"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

const controlSocketName = "photon.sock"

type controlRequest struct {
	Method      string                  `json:"method"`
	Zone        string                  `json:"zone,omitempty"`
	Key         string                  `json:"key,omitempty"`
	Value       []byte                  `json:"value,omitempty"`
	ValueText   string                  `json:"value_text,omitempty"`
	Type        string                  `json:"type,omitempty"`
	History     int                     `json:"history,omitempty"`
	Reason      string                  `json:"reason,omitempty"`
	JoinRequest *joinRequest            `json:"join_request,omitempty"`
	JoinBundle  *joinBundle             `json:"join_bundle,omitempty"`
	PrivateKey  *privateKeyFile         `json:"private_key,omitempty"`
	Permissions []zone.Permission       `json:"permissions,omitempty"`
	Snapshot    *corestate.ZoneSnapshot `json:"snapshot,omitempty"`
	Apply       bool                    `json:"apply,omitempty"`
	IncludeAll  bool                    `json:"include_all,omitempty"`
	Verbose     bool                    `json:"verbose,omitempty"`
	Orphans     bool                    `json:"orphans,omitempty"`
	NetNS       string                  `json:"netns,omitempty"`
	Host        bool                    `json:"host,omitempty"`
	BirdView    string                  `json:"bird_view,omitempty"`
	EndpointACL *endpointACL            `json:"endpoint_acl,omitempty"`
	IPAM        *ipamMutationRequest    `json:"ipam,omitempty"`
	Route       *routeMutationRequest   `json:"route,omitempty"`
	Service     *serviceMutationRequest `json:"service,omitempty"`
}

type controlResponse struct {
	OK             bool                    `json:"ok"`
	Error          string                  `json:"error,omitempty"`
	CleanedLinks   int                     `json:"cleaned_links,omitempty"`
	CleanedOrphans int                     `json:"cleaned_orphans,omitempty"`
	Version        uint64                  `json:"version,omitempty"`
	Message        string                  `json:"message,omitempty"`
	Zone           zone.ZonePath           `json:"zone,omitempty"`
	RootPublicKey  ed25519.PublicKey       `json:"root_public_key,omitempty"`
	JoinBundle     *joinBundle             `json:"join_bundle,omitempty"`
	PortRotate     *manualPortRotateResult `json:"port_rotate,omitempty"`
	RecordsApplied int                     `json:"records_applied,omitempty"`
	Delegations    int                     `json:"delegations,omitempty"`
	Revocations    int                     `json:"revocations,omitempty"`
	NetworkChanged bool                    `json:"network_changed,omitempty"`
	PurgePlan      *purgePlan              `json:"purge_plan,omitempty"`
	StateGC        *stateGCPlan            `json:"state_gc,omitempty"`
}

// controlViewResponse is the transport envelope for read-only queries. View
// is already the canonical inspect DTO; the control layer must not reshape it
// into another resource-specific response.
type controlViewResponse[T any] struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	View  T      `json:"view,omitempty"`
}

// healthLinkJSON is the JSON representation of health.LinkHealth for the
// control API. It keeps time.Duration fields as millisecond integers for
// compact serialization.
type healthLinkJSON struct {
	ProbeID         string `json:"probe_id,omitempty"`
	InstanceID      string `json:"instance_id"`
	ProbeRole       string `json:"probe_role,omitempty"`
	InterfaceName   string `json:"interface_name,omitempty"`
	State           string `json:"state"`
	ProbeType       string `json:"probe_type"`
	Sent            int    `json:"sent"`
	Received        int    `json:"received"`
	Lost            int    `json:"lost"`
	LossRatio       int    `json:"loss_ratio_pct"`
	LastRTTMs       int64  `json:"last_rtt_ms"`
	EWMARTTMs       int64  `json:"ewma_rtt_ms"`
	P50RTTMs        int64  `json:"p50_rtt_ms"`
	P95RTTMs        int64  `json:"p95_rtt_ms"`
	P99RTTMs        int64  `json:"p99_rtt_ms"`
	JitterMs        int64  `json:"jitter_ms"`
	ConsecutiveFail int    `json:"consecutive_fail"`
	LastError       string `json:"last_error,omitempty"`
	NextProbeUnix   int64  `json:"next_probe_unix,omitempty"`
	CutoverBlocking bool   `json:"cutover_blocking,omitempty"`
}

func healthLinkJSONFromHealth(h healthLinkHealthView) healthLinkJSON {
	return healthLinkJSON{
		ProbeID:         h.ProbeID,
		InstanceID:      h.InstanceID,
		ProbeRole:       h.ProbeRole,
		InterfaceName:   h.InterfaceName,
		State:           h.State,
		ProbeType:       h.ProbeType,
		Sent:            h.Sent,
		Received:        h.Received,
		Lost:            h.Lost,
		LossRatio:       int(h.LossRatio * 100),
		LastRTTMs:       h.LastRTT.Milliseconds(),
		EWMARTTMs:       h.EWMARTT.Milliseconds(),
		P50RTTMs:        h.P50RTT.Milliseconds(),
		P95RTTMs:        h.P95RTT.Milliseconds(),
		P99RTTMs:        h.P99RTT.Milliseconds(),
		JitterMs:        h.Jitter.Milliseconds(),
		ConsecutiveFail: h.ConsecutiveFail,
		LastError:       h.LastError,
		NextProbeUnix:   h.NextProbeUnix,
		CutoverBlocking: h.CutoverBlocking,
	}
}

// healthLinkHealthView is a local view type used to convert health.LinkHealth
// without importing pkg/health in control.go (kept for layered imports).
type healthLinkHealthView struct {
	ProbeID         string
	InstanceID      string
	ProbeRole       string
	InterfaceName   string
	State           string
	ProbeType       string
	Sent            int
	Received        int
	Lost            int
	LossRatio       float64
	LastRTT         time.Duration
	EWMARTT         time.Duration
	P50RTT          time.Duration
	P95RTT          time.Duration
	P99RTT          time.Duration
	Jitter          time.Duration
	ConsecutiveFail int
	LastError       string
	NextProbeUnix   int64
	CutoverBlocking bool
}

func controlSocketPath(config *appConfig) string {
	if path := os.Getenv("PHOTON_CONTROL_SOCKET"); path != "" {
		return path
	}
	if os.Getenv("PHOTON_CONTROL_SOCKET_SCOPE") == "data-dir" {
		return dataDirControlSocketPath(config)
	}
	if os.Geteuid() == 0 {
		return filepath.Join("/run/photon", controlSocketName)
	}
	return dataDirControlSocketPath(config)
}

func dataDirControlSocketPath(config *appConfig) string {
	dataDir := "."
	if config != nil && config.DataDir != "" {
		dataDir = config.DataDir
	}
	return filepath.Join(dataDir, controlSocketName)
}

func sendControlRequest(path string, request controlRequest) (*controlResponse, error) {
	var response controlResponse
	if err := controlapi.Send(path, request, &response); err != nil {
		return nil, err
	}
	if !response.OK {
		if response.Error == "" {
			response.Error = "daemon control request failed"
		}
		return &response, errors.New(response.Error)
	}
	return &response, nil
}

func daemonStatusViaControl(rt *AppContext) (inspect.DaemonStatusView, bool, error) {
	return readCanonicalViewViaControl[inspect.DaemonStatusView](rt, controlRequest{Method: "daemon_status_view"})
}

func rootPublicKeyViaControl(rt *AppContext) (ed25519.PublicKey, bool, error) {
	return readCanonicalViewViaControl[ed25519.PublicKey](rt, controlRequest{Method: "root_public_key"})
}

func readCanonicalViewViaControl[T any](rt *AppContext, request controlRequest) (T, bool, error) {
	var zero T
	if rt == nil || rt.DisableControl {
		return zero, false, nil
	}
	var response controlViewResponse[T]
	if err := controlapi.Send(controlSocketPath(rt.Config), request, &response); err != nil {
		if isControlSocketUnavailable(err) {
			return zero, false, nil
		}
		return zero, true, err
	}
	if !response.OK {
		if response.Error == "" {
			response.Error = "daemon control query failed"
		}
		return zero, true, errors.New(response.Error)
	}
	return response.View, true, nil
}

func verifyChainViaControl(rt *AppContext, path zone.ZonePath) (bool, error) {
	_, online, err := readCanonicalViewViaControl[bool](rt, controlRequest{Method: "verify_chain", Zone: path.String()})
	return online, err
}

func routingReloadViaControl(rt *AppContext) (*controlResponse, bool, error) {
	path := controlSocketPath(rt.Config)
	response, err := sendControlRequest(path, controlRequest{Method: "routing_reload"})
	if err != nil && isControlSocketUnavailable(err) {
		return nil, false, nil
	}
	return response, true, err
}

func admissionStatusViaControl(rt *AppContext) (inspect.AdmissionDiagnosis, bool, error) {
	return readCanonicalViewViaControl[inspect.AdmissionDiagnosis](rt, controlRequest{Method: "admission_status"})
}

func stateGCViaControl(rt *AppContext, apply bool) (*controlResponse, bool, error) {
	if rt != nil && rt.DisableControl {
		return nil, false, nil
	}
	path := controlSocketPath(rt.Config)
	response, err := sendControlRequest(path, controlRequest{Method: "state_gc", Apply: apply})
	if err != nil && isControlSocketUnavailable(err) {
		if !apply {
			return nil, false, nil
		}
		return nil, true, fmt.Errorf("daemon control socket unavailable; use --direct for an explicit offline write: %w", err)
	}
	return response, true, err
}

func (d *Daemon) birdRoutesForControl(ctx context.Context, dump *inspect.RoutesResponse, instances []RoutingInstance, birdStates map[string]*BirdInstanceState) []inspect.BirdRoutesView {
	if d == nil || dump == nil {
		return nil
	}
	views := make([]inspect.BirdRoutesView, 0, len(instances))
	for _, inst := range instances {
		if !inst.Enabled || inst.Mode == ipsec.RoutingModeDisabled {
			continue
		}
		state := birdStates[inst.NetNS]
		view := inspect.BirdRoutesView{
			NetNS:      inst.NetNS,
			InstanceID: inst.ID,
		}
		socketPath := inst.ControlSocket
		if state != nil {
			view.State = state.State
			if state.LastError != "" {
				view.Error = state.LastError
			}
			if state.ControlSocket != "" {
				socketPath = state.ControlSocket
			}
		}
		if socketPath == "" {
			if view.Error == "" {
				view.Error = "control socket not configured"
			}
			views = append(views, view)
			continue
		}
		observed, err := d.linuxDriver.ObserveBird(ctx, socketPath, bird.InternalRouteTableNames(inst.NetNS)...)
		if err != nil {
			view.Error = err.Error()
			views = append(views, view)
			continue
		}
		if observed != nil {
			view.Routes = inspect.BuildBirdRouteViews(dump, observed.Routes)
		}
		views = append(views, view)
	}
	sort.Slice(views, func(i, j int) bool {
		if views[i].NetNS != views[j].NetNS {
			return views[i].NetNS < views[j].NetNS
		}
		return views[i].InstanceID < views[j].InstanceID
	})
	return views
}

func putRecordViaControl(rt *AppContext, path zone.ZonePath, key string, value []byte, recordType string) (uint64, bool, error) {
	if rt != nil && rt.DisableControl {
		return 0, false, nil
	}
	socketPath := controlSocketPath(rt.Config)
	response, err := sendControlRequest(socketPath, controlRequest{
		Method: "record_put",
		Zone:   path.String(),
		Key:    key,
		Value:  value,
		Type:   recordType,
	})
	if err != nil {
		if isControlSocketUnavailable(err) {
			return 0, true, fmt.Errorf("daemon control socket unavailable; use --direct for an explicit offline write: %w", err)
		}
		return 0, true, err
	}
	return response.Version, true, nil
}

func mutateIPAMViaControl(rt *AppContext, request ipamMutationRequest) (uint64, bool, error) {
	response, ok, err := sendMutationControlRequest(rt, controlRequest{Method: "ipam_mutate", IPAM: &request})
	if err != nil || !ok {
		return 0, ok, err
	}
	return response.Version, true, nil
}

func mutateRouteViaControl(rt *AppContext, request routeMutationRequest) (uint64, bool, error) {
	response, ok, err := sendMutationControlRequest(rt, controlRequest{Method: "route_mutate", Route: &request})
	if err != nil || !ok {
		return 0, ok, err
	}
	return response.Version, true, nil
}

func mutateServiceViaControl(rt *AppContext, request serviceMutationRequest) (uint64, bool, error) {
	response, ok, err := sendMutationControlRequest(rt, controlRequest{Method: "service_mutate", Service: &request})
	if err != nil || !ok {
		return 0, ok, err
	}
	return response.Version, true, nil
}

func sendMutationControlRequest(rt *AppContext, request controlRequest) (*controlResponse, bool, error) {
	if rt != nil && rt.DisableControl {
		return nil, false, nil
	}
	socketPath := controlSocketPath(nil)
	if rt != nil {
		socketPath = controlSocketPath(rt.Config)
	}
	response, err := sendControlRequest(socketPath, request)
	if err != nil && isControlSocketUnavailable(err) {
		return nil, true, fmt.Errorf("daemon control socket unavailable; use --direct for an explicit offline write: %w", err)
	}
	return response, true, err
}

func getRecordViaControl(rt *AppContext, path zone.ZonePath, key string, history int) (*inspect.RecordDetailView, bool, error) {
	record, ok, err := readCanonicalViewViaControl[*inspect.RecordDetailView](rt, controlRequest{
		Method:  "record_get",
		Zone:    path.String(),
		Key:     key,
		History: history,
	})
	if err != nil || !ok {
		return nil, ok, err
	}
	if record == nil {
		return nil, true, errors.New("daemon record_get response missing record")
	}
	return record, true, nil
}

func rotateIPsecPortViaControl(rt *AppContext) (*manualPortRotateResult, bool, error) {
	socketPath := controlSocketPath(rt.Config)
	response, err := sendControlRequest(socketPath, controlRequest{Method: "ipsec_rotate_port"})
	if err != nil {
		if isControlSocketUnavailable(err) {
			return nil, false, nil
		}
		return nil, true, err
	}
	if response.PortRotate == nil {
		return nil, true, errors.New("daemon ipsec_rotate_port response missing result")
	}
	return response.PortRotate, true, nil
}

func issueDelegationViaControl(rt *AppContext, request *joinRequest, permissions []zone.Permission) (*joinBundle, bool, error) {
	response, ok, err := sendAdminControlRequest(rt, controlRequest{
		Method:      "delegate_issue",
		JoinRequest: request,
		Permissions: permissions,
	})
	if err != nil || !ok {
		return nil, ok, err
	}
	if response.JoinBundle == nil {
		return nil, true, errors.New("daemon delegate_issue response missing join bundle")
	}
	return response.JoinBundle, true, nil
}

func grantDelegationPermissionsViaControl(rt *AppContext, path zone.ZonePath, permissions []zone.Permission) (*joinBundle, bool, error) {
	response, ok, err := sendAdminControlRequest(rt, controlRequest{
		Method:      "delegate_grant",
		Zone:        path.String(),
		Permissions: permissions,
	})
	if err != nil || !ok {
		return nil, ok, err
	}
	return response.JoinBundle, true, nil
}

func importRecoveryZoneViaControl(rt *AppContext, snapshot *corestate.ZoneSnapshot) (*corestate.ApplyResult, int, bool, error) {
	response, ok, err := sendAdminControlRequest(rt, controlRequest{
		Method:   "recovery_import_zone",
		Snapshot: snapshot,
	})
	if err != nil || !ok {
		return nil, 0, ok, err
	}
	return &corestate.ApplyResult{
		Zone:           response.Zone,
		Records:        response.RecordsApplied,
		Delegation:     response.Delegations,
		NetworkChanged: response.NetworkChanged,
	}, response.Revocations, true, nil
}

func revokeDelegationViaControl(rt *AppContext, path zone.ZonePath, reason string) (bool, error) {
	_, ok, err := sendAdminControlRequest(rt, controlRequest{
		Method: "delegate_revoke",
		Zone:   path.String(),
		Reason: reason,
	})
	return ok, err
}

func purgeRevokedViaControl(rt *AppContext, apply bool, target zone.ZonePath) (*purgePlan, bool, error) {
	response, ok, err := sendAdminControlRequest(rt, controlRequest{
		Method: "recovery_purge_revoked",
		Zone:   target.String(),
		Apply:  apply,
	})
	if err != nil || !ok {
		return nil, ok, err
	}
	return response.PurgePlan, true, nil
}

func acceptJoinBundleViaControl(rt *AppContext, bundle *joinBundle, key *privateKeyFile) (bool, error) {
	_, ok, err := sendAdminControlRequest(rt, controlRequest{
		Method:     "join_accept",
		JoinBundle: bundle,
		PrivateKey: key,
	})
	return ok, err
}

func initRootViaControl(rt *AppContext) (ed25519.PublicKey, bool, error) {
	// root init is an offline bootstrap operation. Probe an existing daemon only
	// to prevent resetting state it has already loaded; a missing socket is the
	// normal initialization case and must not require --direct.
	socketPath := controlSocketPath(nil)
	if rt != nil {
		socketPath = controlSocketPath(rt.Config)
	}
	response, err := sendControlRequest(socketPath, controlRequest{Method: "root_init"})
	if err != nil {
		if isControlSocketUnavailable(err) {
			return nil, false, nil
		}
		return nil, true, err
	}
	return response.RootPublicKey, true, nil
}

func sendAdminControlRequest(rt *AppContext, request controlRequest) (*controlResponse, bool, error) {
	if rt != nil && rt.DisableControl {
		return nil, false, nil
	}
	socketPath := controlSocketPath(nil)
	if rt != nil {
		socketPath = controlSocketPath(rt.Config)
	}
	response, err := sendControlRequest(socketPath, request)
	if err != nil {
		if isControlSocketUnavailable(err) {
			return nil, true, fmt.Errorf("daemon control socket unavailable; use --direct for an explicit offline write: %w", err)
		}
		return nil, true, err
	}
	return response, true, nil
}

func endpointACLApplyViaControl(rt *AppContext, acl endpointACL) (bool, error) {
	_, ok, err := sendAdminControlRequest(rt, controlRequest{Method: "endpoint_acl_apply", EndpointACL: &acl})
	return ok, err
}

func endpointACLRemoveViaControl(rt *AppContext, name string) (bool, error) {
	_, ok, err := sendAdminControlRequest(rt, controlRequest{Method: "endpoint_acl_remove", Key: name})
	return ok, err
}

func endpointACLListViaControl(rt *AppContext) ([]endpointACL, bool, error) {
	return readCanonicalViewViaControl[[]endpointACL](rt, controlRequest{Method: "endpoint_acl_list"})
}

func isControlSocketUnavailable(err error) bool {
	// Only errors that positively mean "there is no listener" permit callers
	// to enter an offline/direct fallback. Timeouts, permission failures and
	// connection resets may all come from a live but unhealthy daemon; treating
	// them as absence risks concurrent direct DB writes beside the single writer.
	return controlapi.IsUnavailable(err)
}

func writeControlResponse(conn net.Conn, response any) {
	if legacy, ok := response.(controlResponse); ok && !legacy.OK && legacy.Error == "" {
		legacy.Error = "request failed"
		response = legacy
	}
	_ = conn.SetWriteDeadline(time.Now().Add(controlConnDeadline))
	_ = json.NewEncoder(conn).Encode(response)
}

func writeCanonicalView[T any](conn net.Conn, view T) {
	writeControlResponse(conn, controlViewResponse[T]{OK: true, View: view})
}

func controlError(err error) controlResponse {
	return controlResponse{OK: false, Error: err.Error()}
}

func parseControlRecordValue(request controlRequest) []byte {
	if request.Value != nil {
		return request.Value
	}
	return []byte(request.ValueText)
}

func controlContext(ctx context.Context) context.Context {
	if ctx != nil {
		return ctx
	}
	return context.Background()
}

func validateControlRecordPut(request controlRequest) error {
	if zone.ZonePath(request.Zone) == "" || request.Key == "" {
		return fmt.Errorf("record_put requires zone and key")
	}
	if request.Type == "" {
		return fmt.Errorf("record_put requires type")
	}
	return validateGenericRecordPut(request.Key, request.Type)
}

func validateControlRecordGet(request controlRequest) error {
	if zone.ZonePath(request.Zone) == "" || request.Key == "" {
		return fmt.Errorf("record_get requires zone and key")
	}
	if request.History < 0 {
		return fmt.Errorf("record_get history must be >= 0")
	}
	return nil
}

func validateControlDelegateIssue(request controlRequest) error {
	if request.JoinRequest == nil {
		return errors.New("delegate_issue requires join_request")
	}
	return validateJoinRequest(request.JoinRequest)
}

func validateControlDelegateGrant(request controlRequest) error {
	path := zone.ZonePath(request.Zone)
	if !path.Valid() {
		return fmt.Errorf("invalid delegated zone: %s", request.Zone)
	}
	if len(request.Permissions) == 0 {
		return errors.New("delegate_grant requires permissions")
	}
	for _, permission := range request.Permissions {
		if _, err := parseAuthorityPermission(string(permission)); err != nil {
			return err
		}
	}
	return nil
}

func validateControlRecoveryImportZone(request controlRequest) error {
	if request.Snapshot == nil {
		return errors.New("recovery_import_zone requires snapshot")
	}
	if !request.Snapshot.Zone.Valid() {
		return fmt.Errorf("invalid recovery zone: %s", request.Snapshot.Zone)
	}
	return nil
}

func validateControlDelegateRevoke(request controlRequest) error {
	if zone.ZonePath(request.Zone) == "" {
		return errors.New("delegate_revoke requires zone")
	}
	return nil
}

func validateControlJoinAccept(request controlRequest) error {
	if request.JoinBundle == nil {
		return errors.New("join_accept requires join_bundle")
	}
	if request.PrivateKey == nil {
		return nil
	}
	return validatePrivateKeyFile(request.PrivateKey)
}
