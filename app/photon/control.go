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
	"syscall"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	pingdebug "github.com/HiggsNet/photon/internal/ping"
	photonstate "github.com/HiggsNet/photon/internal/state"
	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

const (
	controlSocketName      = "photon.sock"
	controlDialTimeout     = time.Second
	controlRequestDeadline = 10 * time.Second
	// Bound the whole diagnostic, regardless of target count or probe options.
	controlPingMaxDuration = 5 * time.Minute
)

type controlRequest struct {
	LiveSAs     bool                     `json:"live_sas,omitempty"`
	Method      string                   `json:"method"`
	Zone        string                   `json:"zone,omitempty"`
	Key         string                   `json:"key,omitempty"`
	Value       []byte                   `json:"value,omitempty"`
	ValueText   string                   `json:"value_text,omitempty"`
	Type        string                   `json:"type,omitempty"`
	History     int                      `json:"history,omitempty"`
	Reason      string                   `json:"reason,omitempty"`
	JoinRequest *gossip.JoinRequest      `json:"join_request,omitempty"`
	JoinBundle  *joinBundle              `json:"join_bundle,omitempty"`
	PrivateKey  *privateKeyFile          `json:"private_key,omitempty"`
	Permissions []zone.Permission        `json:"permissions,omitempty"`
	Snapshot    *corestate.ZoneSnapshot  `json:"snapshot,omitempty"`
	Apply       bool                     `json:"apply,omitempty"`
	IncludeAll  bool                     `json:"include_all,omitempty"`
	Verbose     bool                     `json:"verbose,omitempty"`
	Orphans     bool                     `json:"orphans,omitempty"`
	NetNS       string                   `json:"netns,omitempty"`
	Host        bool                     `json:"host,omitempty"`
	BirdView    string                   `json:"bird_view,omitempty"`
	Family      string                   `json:"family,omitempty"`
	EndpointACL *photonstate.EndpointACL `json:"endpoint_acl,omitempty"`
	IPAM        *ipamMutationRequest     `json:"ipam,omitempty"`
	Route       *routeMutationRequest    `json:"route,omitempty"`
	Service     *serviceMutationRequest  `json:"service,omitempty"`
	Ping        *pingdebug.Options       `json:"ping,omitempty"`
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
}

// controlViewResponse is the transport envelope for read-only queries. View
// is already the canonical inspect DTO; the control layer must not reshape it
// into another resource-specific response.
type controlViewResponse[T any] struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	View  T      `json:"view,omitempty"`
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
	ctx, cancel := context.WithTimeout(context.Background(), controlRequestDeadline)
	defer cancel()
	var response controlResponse
	if err := exchangeControl(ctx, path, request, &response); err != nil {
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

func readCanonicalViewViaControl[T any](config *appConfig, request controlRequest, direct bool) (T, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), controlRequestDeadline)
	defer cancel()
	return readCanonicalViewViaControlContext[T](ctx, config, request, direct)
}

func readCanonicalViewViaControlContext[T any](ctx context.Context, config *appConfig, request controlRequest, direct bool) (T, bool, error) {
	var zero T
	if config == nil || direct {
		return zero, false, nil
	}
	var response controlViewResponse[T]
	if err := exchangeControl(ctx, controlSocketPath(config), request, &response); err != nil {
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

// exchangeControl performs one JSON request/response exchange with the local
// daemon. The wire DTOs, transport and fallback policy stay together at the
// executable control boundary until another real client needs a typed API.
func exchangeControl(ctx context.Context, path string, request, response any) error {
	dialer := net.Dialer{Timeout: controlDialTimeout}
	conn, err := dialer.DialContext(ctx, "unix", path)
	if err != nil {
		return err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	stopCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopCancel()
	if err := json.NewEncoder(conn).Encode(request); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	if err := json.NewDecoder(conn).Decode(response); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	return nil
}

func verifyChainViaControl(config *appConfig, path zone.ZonePath, direct bool) (bool, error) {
	_, online, err := readCanonicalViewViaControl[bool](config, controlRequest{Method: "verify_chain", Zone: path.String()}, direct)
	return online, err
}

func routingReloadViaControl(config *appConfig) (*controlResponse, bool, error) {
	path := controlSocketPath(config)
	response, err := sendControlRequest(path, controlRequest{Method: "routing_reload"})
	if err != nil && isControlSocketUnavailable(err) {
		return nil, false, nil
	}
	return response, true, err
}

func admissionStatusViaControl(config *appConfig, direct bool) (gossip.AdmissionDiagnosis, bool, error) {
	return readCanonicalViewViaControl[gossip.AdmissionDiagnosis](config, controlRequest{Method: "admission_status"}, direct)
}

func sendVersionedMutationViaControl(config *appConfig, request controlRequest, direct bool) (uint64, bool, error) {
	response, controlled, err := sendMutationControlRequest(config, request, direct)
	if err != nil || !controlled {
		return 0, controlled, err
	}
	return response.Version, true, nil
}

func sendMutationControlRequest(config *appConfig, request controlRequest, direct bool) (*controlResponse, bool, error) {
	if direct {
		return nil, false, nil
	}
	socketPath := controlSocketPath(nil)
	if config != nil {
		socketPath = controlSocketPath(config)
	}
	response, err := sendControlRequest(socketPath, request)
	if err != nil && isControlSocketUnavailable(err) {
		return nil, true, fmt.Errorf("daemon control socket unavailable; use --direct for an explicit offline write: %w", err)
	}
	return response, true, err
}

func getRecordViaControl(config *appConfig, path zone.ZonePath, key string, history int, direct bool) (*inspect.RecordDetailView, bool, error) {
	record, ok, err := readCanonicalViewViaControl[*inspect.RecordDetailView](config, controlRequest{
		Method:  "record_get",
		Zone:    path.String(),
		Key:     key,
		History: history,
	}, direct)
	if err != nil || !ok {
		return nil, ok, err
	}
	if record == nil {
		return nil, true, errors.New("daemon record_get response missing record")
	}
	return record, true, nil
}

func rotateIPsecPortViaControl(config *appConfig) (*manualPortRotateResult, bool, error) {
	socketPath := controlSocketPath(config)
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

func issueDelegationViaControl(config *appConfig, request *gossip.JoinRequest, permissions []zone.Permission, direct bool) (*joinBundle, bool, error) {
	response, ok, err := sendMutationControlRequest(config, controlRequest{
		Method:      "delegate_issue",
		JoinRequest: request,
		Permissions: permissions,
	}, direct)
	if err != nil || !ok {
		return nil, ok, err
	}
	if response.JoinBundle == nil {
		return nil, true, errors.New("daemon delegate_issue response missing join bundle")
	}
	return response.JoinBundle, true, nil
}

func grantDelegationPermissionsViaControl(config *appConfig, path zone.ZonePath, permissions []zone.Permission, direct bool) (*joinBundle, bool, error) {
	response, ok, err := sendMutationControlRequest(config, controlRequest{
		Method:      "delegate_grant",
		Zone:        path.String(),
		Permissions: permissions,
	}, direct)
	if err != nil || !ok {
		return nil, ok, err
	}
	return response.JoinBundle, true, nil
}

func importRecoveryZoneViaControl(config *appConfig, snapshot *corestate.ZoneSnapshot, direct bool) (*corestate.ApplyResult, int, bool, error) {
	response, ok, err := sendMutationControlRequest(config, controlRequest{
		Method:   "recovery_import_zone",
		Snapshot: snapshot,
	}, direct)
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

func revokeDelegationViaControl(config *appConfig, path zone.ZonePath, reason string, direct bool) (bool, error) {
	_, ok, err := sendMutationControlRequest(config, controlRequest{
		Method: "delegate_revoke",
		Zone:   path.String(),
		Reason: reason,
	}, direct)
	return ok, err
}

func purgeRevokedViaControl(config *appConfig, apply bool, target zone.ZonePath, direct bool) (*purgePlan, bool, error) {
	response, ok, err := sendMutationControlRequest(config, controlRequest{
		Method: "recovery_purge_revoked",
		Zone:   target.String(),
		Apply:  apply,
	}, direct)
	if err != nil || !ok {
		return nil, ok, err
	}
	return response.PurgePlan, true, nil
}

func acceptJoinBundleViaControl(config *appConfig, bundle *joinBundle, key *privateKeyFile, direct bool) (bool, error) {
	_, ok, err := sendMutationControlRequest(config, controlRequest{
		Method:     "join_accept",
		JoinBundle: bundle,
		PrivateKey: key,
	}, direct)
	return ok, err
}

func checkRootInitViaControl(config *appConfig) error {
	// root init is an offline bootstrap operation. Probe an existing daemon only
	// to prevent resetting state it has already loaded; a missing socket is the
	// normal initialization case and must not require --direct.
	socketPath := controlSocketPath(nil)
	if config != nil {
		socketPath = controlSocketPath(config)
	}
	_, err := sendControlRequest(socketPath, controlRequest{Method: "root_init"})
	if err != nil {
		if isControlSocketUnavailable(err) {
			return nil
		}
		return err
	}
	return errors.New("root init requires the daemon to be stopped")
}

func isControlSocketUnavailable(err error) bool {
	// Only errors that positively mean "there is no listener" permit callers
	// to enter an offline/direct fallback. Timeouts, permission failures and
	// connection resets may all come from a live but unhealthy daemon; treating
	// them as absence risks concurrent direct DB writes beside the single writer.
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED)
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
	return nil
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
	return gossip.ValidateJoinRequest(request.JoinRequest)
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
	return request.PrivateKey.Validate()
}
