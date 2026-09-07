package ipsec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	defaultVICIOperationTimeout      = 10 * time.Second
	defaultVICIInitiateServerTimeout = 15 * time.Second
	defaultVICIInitiateClientGrace   = 5 * time.Second
	defaultVICIInitiateConcurrency   = 4
)

type SAState struct {
	Name            string
	UniqueID        uint64
	Initiator       bool
	InitiatorKnown  bool
	IKEAgeSeconds   uint64
	ChildAgeSeconds uint64
	InboundBytes    uint64
	InboundPackets  uint64
	InboundIdleSecs uint64
	InboundKnown    bool
	Peer            string
	ChildSA         string
	IKEState        string
	ChildState      string
	XFRMIfID        uint32
	ReqID           uint32
	LocalIdentity   string
	RemoteIdentity  string
	LocalEndpoint   string
	RemoteEndpoint  string
	Endpoint        string
	Established     bool
}

type ConnectionState struct {
	Name           string
	LocalIdentity  string
	RemoteIdentity string
	RemoteEndpoint string
}

type VICIEvent struct {
	Name           string
	Connection     string
	ChildSA        string
	Up             bool
	XFRMIfID       uint32
	ReqID          uint32
	LocalIdentity  string
	RemoteIdentity string
	LocalEndpoint  string
	RemoteEndpoint string
	Raw            map[string]any
}

type VICIClient interface {
	Call(context.Context, string, map[string]any) (map[string]any, error)
	CallStreaming(context.Context, string, string, map[string]any) ([]map[string]any, error)
}

type VICIEventClient interface {
	SubscribeEvents(context.Context, ...string) (<-chan VICIEvent, func(), error)
}

type IPsecDriver interface {
	LoadConnection(context.Context, TransportLinkSpec) error
	UnloadConnection(context.Context, string) error
	TerminateSA(context.Context, string) error
	ListConnections(context.Context) ([]ConnectionState, error)
	ListSAs(context.Context) ([]SAState, error)
	LoadPrivateKey(ctx context.Context, id string, key []byte, algorithm string) error
	UnloadPrivateKey(ctx context.Context, id string) error
}

type SAUniqueIDTerminator interface {
	TerminateSAByID(context.Context, uint64) error
}

type ChildInitiator interface {
	InitiateChild(context.Context, string) error
}

type XFRMDriver interface {
	EnsureNamespace(context.Context, NetNSSpec) error
	EnsureInterface(context.Context, TransportLinkSpec) error
	DeleteInterface(context.Context, string) error
	AssignAddress(context.Context, TransportLinkSpec, string) error
}

type XFRMExtraAddressAssigner interface {
	AssignExtraAddress(context.Context, TransportLinkSpec, string) error
}

type XFRMLinkState struct {
	NetNS                    NetNSSpec
	InterfaceName            string
	XFRMIfID                 uint32
	NamespaceExists          bool
	InterfaceExists          bool
	FlagsKnown               bool
	InterfaceUp              bool
	Multicast                bool
	IPv6AddrGenModeKnown     bool
	IPv6AddrGenDisabled      bool
	NamespaceForwardingKnown bool
	NamespaceForwarding      bool
	InterfaceForwardingKnown bool
	InterfaceForwarding      bool
	Addresses                []netip.Prefix
}

type XFRMLinkInspector interface {
	InspectLink(context.Context, TransportLinkSpec) (XFRMLinkState, error)
}

// XFRMLinkBatchInspector observes all requested interfaces with a bounded
// number of namespace-wide reads. Link results are aligned with specs; the
// inventory contains every XFRM interface found in the requested namespaces.
type XFRMLinkBatchInspector interface {
	InspectLinks(context.Context, []TransportLinkSpec, []NetNSSpec) ([]XFRMLinkState, []XFRMLinkState, error)
}

type XFRMObservedInterface struct {
	Spec  TransportLinkSpec
	State XFRMLinkState
}

// XFRMObservedEnsurer applies only drift found in a preceding observation.
// A healthy input must be a mutation-free no-op.
type XFRMObservedEnsurer interface {
	EnsureObservedInterfaces(context.Context, []XFRMObservedInterface) error
}

type XFRMSAFilter interface {
	FilterSAsWithMissingLinks(context.Context, []TransportLinkSpec, []SAState) ([]SAState, map[string]TransportLinkSpec, error)
}

type DryRunDriver struct {
	Connections       []TransportLinkSpec
	LoadedConnections []ConnectionState
	Initiated         []string
	Unloaded          []string
	Terminated        []string
	Interfaces        []TransportLinkSpec
	Namespaces        []NetNSSpec
	DeletedIFs        []string
	Addresses         []string
	PrivateKeys       []DryRunPrivateKey
	UnloadedKeys      []string
}

type DryRunPrivateKey struct {
	ID        string
	Algorithm string
	Len       int
}

type ApplyOperation struct {
	Action string
	Target string
	Detail string
}

type ApplyPlan struct {
	Operations []ApplyOperation
}

type StrongSwanDriver struct {
	VICI             VICIClient
	KeyDir           string
	LogConfig        func(event string, fields map[string]any)
	OperationTimeout time.Duration
	InitiateAsync    bool
	// InitiateTimeout is sent to charon in the VICI request.  It bounds the
	// blocking controller callback inside charon; a Go context timeout alone
	// only disconnects the client and does not release charon's worker.
	InitiateTimeout time.Duration
	// InitiateClientTimeout bounds the local VICI call.  It should be longer
	// than InitiateTimeout so charon can detach and return its response first.
	InitiateClientTimeout time.Duration
	// InitiateConcurrency limits blocking initiate callbacks submitted to one
	// charon process.  Zero selects the conservative default.
	InitiateConcurrency   int
	InitiateClientFactory func() (VICIClient, func() error, error)

	privateKeyBindings map[string]string
	privateKeys        map[string]*strongSwanPrivateKeyRef
	privateKeyMu       sync.Mutex
	initiateMu         sync.Mutex
	initiateBusy       map[string]struct{}
	initiateSlots      chan struct{}
}

type strongSwanPrivateKeyRef struct {
	keyID string
	refs  int
}

func PlanApply(spec TransportLinkSpec, netns NetNSSpec) ApplyPlan {
	netns = netns.Normalized()
	plan := ApplyPlan{}
	plan.add("ensure_namespace", netns.Target(), netns.Kind)
	if len(spec.LocalPrivateKey) > 0 {
		plan.add("load_private_key", spec.TransportID, spec.LocalPrivateKeyAlgorithm)
	}
	plan.add("load_connection", spec.TransportID, string(spec.PeerZone))
	plan.add("ensure_interface", spec.InterfaceName, fmt.Sprintf("if_id=%d netns=%s", spec.XFRMIfID, spec.NetNS))
	if spec.LocalTunnelAddr.IsValid() {
		plan.add("assign_address", spec.InterfaceName, FormatScopedTunnelAddress(spec.LocalTunnelAddr, spec.InterfaceName, spec.NetNS))
	}
	return plan
}

func PlanTeardown(spec TransportLinkSpec) ApplyPlan {
	plan := ApplyPlan{}
	plan.add("terminate_sa", spec.TransportID, string(spec.PeerZone))
	plan.add("unload_connection", spec.TransportID, string(spec.PeerZone))
	if len(spec.LocalPrivateKey) > 0 {
		plan.add("unload_private_key", spec.TransportID, spec.LocalPrivateKeyAlgorithm)
	}
	plan.add("delete_interface", spec.InterfaceName, fmt.Sprintf("if_id=%d netns=%s", spec.XFRMIfID, spec.NetNS))
	return plan
}

func ApplyStagedConnection(ctx context.Context, ipsec IPsecDriver, xfrm XFRMDriver, spec TransportLinkSpec, netns NetNSSpec) (ApplyPlan, error) {
	if ipsec == nil {
		return ApplyPlan{}, fmt.Errorf("ipsec driver is required")
	}
	if xfrm == nil {
		return ApplyPlan{}, fmt.Errorf("xfrm driver is required")
	}
	plan := PlanApply(spec, netns)
	var filtered []ApplyOperation
	for _, op := range plan.Operations {
		if op.Action != "load_private_key" {
			filtered = append(filtered, op)
		}
	}
	plan.Operations = filtered
	if err := xfrm.EnsureNamespace(ctx, netns); err != nil {
		return plan, fmt.Errorf("ensure namespace: %w", err)
	}
	// Unload the base connection before loading the staged one. This prevents
	// StrongSwan from matching incoming rotation packets against the base
	// config and creating the staged IKE_SA under the wrong connection name.
	// The base IKE_SA remains established because we only unload the config.
	baseName := BaseConnectionName(spec.TransportID)
	if baseName != spec.TransportID {
		_ = ipsec.UnloadConnection(ctx, baseName)
	}
	if err := ipsec.LoadConnection(ctx, spec); err != nil {
		return plan, fmt.Errorf("load connection: %w", err)
	}
	if err := xfrm.EnsureInterface(ctx, spec); err != nil {
		return plan, fmt.Errorf("ensure interface: %w", err)
	}
	if spec.LocalTunnelAddr.IsValid() {
		if err := xfrm.AssignAddress(ctx, spec, tunnelAddressPrefix(spec.LocalTunnelAddr)); err != nil {
			return plan, fmt.Errorf("assign address: %w", err)
		}
	}
	// Active initiators explicitly trigger the staged CHILD_SA. Loaded child
	// configurations are passive (start_action=none), so responders only
	// accept the peer's negotiation.
	if IsActiveInitiatorRole(spec.InitiatorRole) {
		if err := InitiateTransportChild(ctx, ipsec, spec, &plan); err != nil {
			return plan, fmt.Errorf("initiate staged child: %w", err)
		}
	}
	return plan, nil
}

func ApplyTransportLink(ctx context.Context, ipsec IPsecDriver, xfrm XFRMDriver, spec TransportLinkSpec, netns NetNSSpec) (ApplyPlan, error) {
	if ipsec == nil {
		return ApplyPlan{}, fmt.Errorf("ipsec driver is required")
	}
	if xfrm == nil {
		return ApplyPlan{}, fmt.Errorf("xfrm driver is required")
	}
	plan := PlanApply(spec, netns)
	if err := xfrm.EnsureNamespace(ctx, netns); err != nil {
		return plan, fmt.Errorf("ensure namespace: %w", err)
	}
	if len(spec.LocalPrivateKey) > 0 {
		if err := ipsec.LoadPrivateKey(ctx, spec.TransportID, spec.LocalPrivateKey, spec.LocalPrivateKeyAlgorithm); err != nil {
			return plan, fmt.Errorf("load private key: %w", err)
		}
	}
	if err := ipsec.LoadConnection(ctx, spec); err != nil {
		return plan, fmt.Errorf("load connection: %w", err)
	}
	if err := xfrm.EnsureInterface(ctx, spec); err != nil {
		return plan, fmt.Errorf("ensure interface: %w", err)
	}
	if spec.LocalTunnelAddr.IsValid() {
		if err := xfrm.AssignAddress(ctx, spec, tunnelAddressPrefix(spec.LocalTunnelAddr)); err != nil {
			return plan, fmt.Errorf("assign address: %w", err)
		}
	}
	return plan, nil
}

func InitiateTransportChild(ctx context.Context, ipsec IPsecDriver, spec TransportLinkSpec, plan *ApplyPlan) error {
	if !IsActiveInitiatorRole(spec.InitiatorRole) {
		return nil
	}
	initiator, ok := ipsec.(ChildInitiator)
	if !ok {
		return nil
	}
	child := ChildSAName(spec)
	if plan != nil {
		plan.add("initiate_child", child, spec.TransportID)
	}
	if err := initiator.InitiateChild(ctx, child); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil
		}
		return fmt.Errorf("initiate child: %w", err)
	}
	return nil
}

func tunnelAddressPrefix(addr netip.Addr) string {
	if !addr.IsValid() {
		return ""
	}
	bits := 32
	if addr.Is6() {
		bits = 128
		if addr.IsLinkLocalUnicast() {
			bits = 64
		}
	}
	return netip.PrefixFrom(addr, bits).String()
}

func TeardownTransportLink(ctx context.Context, ipsec IPsecDriver, xfrm XFRMDriver, spec TransportLinkSpec) (ApplyPlan, error) {
	if ipsec == nil {
		return ApplyPlan{}, fmt.Errorf("ipsec driver is required")
	}
	if xfrm == nil {
		return ApplyPlan{}, fmt.Errorf("xfrm driver is required")
	}
	plan := PlanTeardown(spec)
	if err := ipsec.TerminateSA(ctx, spec.TransportID); err != nil {
		return plan, fmt.Errorf("terminate sa: %w", err)
	}
	if err := ipsec.UnloadConnection(ctx, spec.TransportID); err != nil {
		return plan, fmt.Errorf("unload connection: %w", err)
	}
	if len(spec.LocalPrivateKey) > 0 {
		if err := ipsec.UnloadPrivateKey(ctx, spec.TransportID); err != nil {
			return plan, fmt.Errorf("unload private key: %w", err)
		}
	}
	if err := xfrm.DeleteInterface(ctx, spec.InterfaceName); err != nil {
		return plan, fmt.Errorf("delete interface: %w", err)
	}
	return plan, nil
}

func TeardownConnectionOnly(ctx context.Context, ipsec IPsecDriver, spec TransportLinkSpec) (ApplyPlan, error) {
	if ipsec == nil {
		return ApplyPlan{}, fmt.Errorf("ipsec driver is required")
	}
	plan := ApplyPlan{}
	plan.add("terminate_sa", spec.TransportID, string(spec.PeerZone))
	plan.add("unload_connection", spec.TransportID, string(spec.PeerZone))
	if err := ipsec.TerminateSA(ctx, spec.TransportID); err != nil {
		return plan, fmt.Errorf("terminate sa: %w", err)
	}
	if err := ipsec.UnloadConnection(ctx, spec.TransportID); err != nil {
		return plan, fmt.Errorf("unload connection: %w", err)
	}
	return plan, nil
}

func (d *StrongSwanDriver) LoadConnection(ctx context.Context, spec TransportLinkSpec) error {
	if d.VICI == nil {
		return fmt.Errorf("vici client is required")
	}
	ctx, cancel := d.viciContext(ctx)
	defer cancel()
	msg, err := d.buildLoadConnMessage(spec)
	if err != nil {
		return err
	}
	d.logVICIConfig("vici_load_conn", spec.TransportID, msg)
	_, err = d.VICI.Call(ctx, "load-conn", msg)
	return err
}

func (d *StrongSwanDriver) UnloadConnection(ctx context.Context, id string) error {
	if d.VICI == nil {
		return fmt.Errorf("vici client is required")
	}
	if id == "" {
		return fmt.Errorf("connection id is required")
	}
	ctx, cancel := d.viciContext(ctx)
	defer cancel()
	_, err := d.VICI.Call(ctx, "unload-conn", map[string]any{"name": id})
	// Idempotent: the connection may already be gone (e.g., unloaded during
	// prepare rotation or manually removed by an operator).
	if err != nil && strings.Contains(err.Error(), "not found") {
		return nil
	}
	return err
}

func (d *StrongSwanDriver) TerminateSA(ctx context.Context, id string) error {
	if d.VICI == nil {
		return fmt.Errorf("vici client is required")
	}
	if id == "" {
		return fmt.Errorf("sa id is required")
	}
	ctx, cancel := d.viciContext(ctx)
	defer cancel()
	_, err := d.VICI.Call(ctx, "terminate", map[string]any{"ike": id, "force": "yes"})
	// Terminating an already-gone SA is a no-op: the caller just wants the
	// SA gone before the next step (e.g. bounded break-before-make rotate).
	if err != nil && strings.Contains(err.Error(), "no matching SAs to terminate found") {
		return nil
	}
	return err
}

func (d *StrongSwanDriver) TerminateSAByID(ctx context.Context, id uint64) error {
	if d.VICI == nil {
		return fmt.Errorf("vici client is required")
	}
	if id == 0 {
		return fmt.Errorf("sa unique id is required")
	}
	ctx, cancel := d.viciContext(ctx)
	defer cancel()
	_, err := d.VICI.Call(ctx, "terminate", map[string]any{"ike-id": fmt.Sprintf("%d", id), "force": "yes"})
	if err != nil && strings.Contains(err.Error(), "no matching SAs to terminate found") {
		return nil
	}
	return err
}

func (d *StrongSwanDriver) InitiateChild(ctx context.Context, child string) error {
	if d.VICI == nil {
		return fmt.Errorf("vici client is required")
	}
	if child == "" {
		return fmt.Errorf("child sa name is required")
	}
	if d.InitiateAsync {
		return d.initiateChildAsync(ctx, child)
	}
	ctx, cancel := d.viciInitiateContext(ctx)
	defer cancel()
	_, err := d.VICI.Call(ctx, "initiate", d.viciInitiateRequest(child))
	return err
}

func (d *StrongSwanDriver) initiateChildAsync(ctx context.Context, child string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if d.markInitiateBusy(child) {
		return nil
	}
	slots := d.asyncInitiateSlots()
	go func() {
		defer d.clearInitiateBusy(child)

		// Do not open a VICI socket until a charon worker slot is available.
		// Waiting locally is cheap; submitting every desired child at once can
		// exhaust charon's worker pool when peers are unreachable.
		slots <- struct{}{}
		defer func() { <-slots }()

		client := d.VICI
		var closeFn func() error
		if d.InitiateClientFactory != nil {
			var err error
			client, closeFn, err = d.InitiateClientFactory()
			if err != nil {
				d.logAsyncInitiateFailure(child, err)
				return
			}
		}
		if client == nil {
			d.logAsyncInitiateFailure(child, fmt.Errorf("vici client is required"))
			return
		}
		// The reconcile context is canceled as soon as a reconcile pass
		// returns.  This operation intentionally outlives that pass, but is
		// still bounded by both the charon-side timeout in the request and the
		// slightly longer local timeout applied here.
		callCtx, cancel := d.viciInitiateContext(context.WithoutCancel(ctx))
		defer cancel()
		if closeFn != nil {
			defer func() { _ = closeFn() }()
		}
		if _, err := client.Call(callCtx, "initiate", d.viciInitiateRequest(child)); err != nil {
			d.logAsyncInitiateFailure(child, err)
		}
	}()
	return nil
}

func (d *StrongSwanDriver) asyncInitiateSlots() chan struct{} {
	d.initiateMu.Lock()
	defer d.initiateMu.Unlock()
	if d.initiateSlots == nil {
		concurrency := d.InitiateConcurrency
		if concurrency <= 0 {
			concurrency = defaultVICIInitiateConcurrency
		}
		d.initiateSlots = make(chan struct{}, concurrency)
	}
	return d.initiateSlots
}

func (d *StrongSwanDriver) markInitiateBusy(child string) bool {
	d.initiateMu.Lock()
	defer d.initiateMu.Unlock()
	if d.initiateBusy == nil {
		d.initiateBusy = make(map[string]struct{})
	}
	if _, ok := d.initiateBusy[child]; ok {
		return true
	}
	d.initiateBusy[child] = struct{}{}
	return false
}

func (d *StrongSwanDriver) clearInitiateBusy(child string) {
	d.initiateMu.Lock()
	defer d.initiateMu.Unlock()
	delete(d.initiateBusy, child)
}

func (d *StrongSwanDriver) ListSAs(ctx context.Context) ([]SAState, error) {
	if d.VICI == nil {
		return nil, fmt.Errorf("vici client is required")
	}
	ctx, cancel := d.viciContext(ctx)
	defer cancel()
	events, err := d.VICI.CallStreaming(ctx, "list-sas", "list-sa", nil)
	if err != nil {
		return nil, err
	}
	states := make([]SAState, 0, len(events))
	for _, event := range events {
		states = append(states, parseSAStates(event)...)
	}
	return states, nil
}

func (d *StrongSwanDriver) ListConnections(ctx context.Context) ([]ConnectionState, error) {
	if d.VICI == nil {
		return nil, fmt.Errorf("vici client is required")
	}
	ctx, cancel := d.viciContext(ctx)
	defer cancel()
	events, err := d.VICI.CallStreaming(ctx, "list-conns", "list-conn", nil)
	if err != nil {
		return nil, err
	}
	states := make([]ConnectionState, 0, len(events))
	for _, event := range events {
		states = append(states, parseConnectionStates(event)...)
	}
	return states, nil
}

func (d *StrongSwanDriver) SubscribeLifecycleEvents(ctx context.Context) (<-chan VICIEvent, func(), error) {
	client, ok := d.VICI.(VICIEventClient)
	if !ok {
		return nil, nil, fmt.Errorf("vici client does not support lifecycle events")
	}
	return client.SubscribeEvents(ctx, "child-updown", "ike-updown")
}

func parseVICIEvent(name string, raw map[string]any) VICIEvent {
	ev := VICIEvent{Name: name, Raw: raw}
	if raw == nil {
		return ev
	}
	ev.Connection = firstString(raw["ike"], raw["ike-name"], raw["conn"], raw["name"])
	ev.ChildSA = stripChildSAReqidSuffix(firstString(raw["child"], raw["child-name"], raw["child-sa"]))
	ev.Up = boolLike(raw["up"]) || strings.EqualFold(firstString(raw["state"]), "up") || strings.EqualFold(firstString(raw["child-state"]), "INSTALLED")
	ev.XFRMIfID = firstUint32(raw["if_id_out"], raw["if-id-out"], raw["if_id_in"], raw["if-id-in"])
	ev.ReqID = firstUint32(raw["reqid"], raw["req-id"])
	ev.LocalIdentity = firstString(raw["local_id"], raw["local-id"], raw["local"])
	ev.RemoteIdentity = firstString(raw["remote_id"], raw["remote-id"], raw["remote"])
	ev.LocalEndpoint = joinEndpoint(firstString(raw["local-host"], raw["local_host"]), firstString(raw["local-port"], raw["local_port"]))
	ev.RemoteEndpoint = joinEndpoint(firstString(raw["remote-host"], raw["remote_host"]), firstString(raw["remote-port"], raw["remote_port"]))
	return ev
}

func firstString(values ...any) string {
	for _, value := range values {
		if s := stringValue(value); s != "" {
			return s
		}
	}
	return ""
}

func boolLike(value any) bool {
	switch v := value.(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(v, "yes") || strings.EqualFold(v, "true") || v == "1"
	case []byte:
		return boolLike(string(v))
	default:
		return false
	}
}

func (d *StrongSwanDriver) LoadPrivateKey(ctx context.Context, id string, key []byte, algorithm string) error {
	if d.VICI == nil {
		return fmt.Errorf("vici client is required")
	}
	if id == "" {
		return fmt.Errorf("private key id is required")
	}
	if len(key) == 0 {
		return fmt.Errorf("private key data is required")
	}
	if algorithm == "" {
		algorithm = AlgorithmEd25519
	}
	publicKey, err := DeriveTransportPublicKey(key, algorithm)
	if err != nil {
		return err
	}
	fingerprint := TransportKeyFingerprint(algorithm, publicKey)

	d.privateKeyMu.Lock()
	defer d.privateKeyMu.Unlock()
	if d.privateKeyBindings == nil {
		d.privateKeyBindings = make(map[string]string)
	}
	if d.privateKeys == nil {
		d.privateKeys = make(map[string]*strongSwanPrivateKeyRef)
	}
	oldFingerprint := d.privateKeyBindings[id]
	if oldFingerprint == fingerprint {
		return nil
	}
	if err := d.acquirePrivateKeyLocked(ctx, fingerprint, key, algorithm); err != nil {
		return err
	}
	if oldFingerprint != "" {
		if err := d.releasePrivateKeyLocked(ctx, oldFingerprint); err != nil {
			rollbackErr := d.releasePrivateKeyLocked(ctx, fingerprint)
			if rollbackErr != nil {
				return fmt.Errorf("replace private key for %q: release old key: %v; rollback new key: %w", id, err, rollbackErr)
			}
			return fmt.Errorf("replace private key for %q: %w", id, err)
		}
	}
	d.privateKeyBindings[id] = fingerprint
	return nil
}

func (d *StrongSwanDriver) UnloadPrivateKey(ctx context.Context, id string) error {
	if d.VICI == nil {
		return fmt.Errorf("vici client is required")
	}
	if id == "" {
		return fmt.Errorf("private key id is required")
	}
	if d.KeyDir != "" {
		_ = os.Remove(filepath.Join(d.KeyDir, id+"-peer.pub.pem"))
	}
	d.privateKeyMu.Lock()
	defer d.privateKeyMu.Unlock()
	fingerprint := d.privateKeyBindings[id]
	if fingerprint == "" {
		return nil
	}
	if err := d.releasePrivateKeyLocked(ctx, fingerprint); err != nil {
		return err
	}
	delete(d.privateKeyBindings, id)
	return nil
}

func (d *StrongSwanDriver) acquirePrivateKeyLocked(ctx context.Context, fingerprint string, key []byte, algorithm string) error {
	if ref := d.privateKeys[fingerprint]; ref != nil {
		ref.refs++
		return nil
	}
	pemBytes, err := PEMEncodePrivateKey(key)
	if err != nil {
		return err
	}
	callCtx, cancel := d.viciContext(ctx)
	defer cancel()
	resp, err := d.VICI.Call(callCtx, "load-key", map[string]any{
		"type": KeyTypeForAlgorithm(algorithm),
		"data": string(pemBytes),
	})
	if err != nil {
		return err
	}
	d.privateKeys[fingerprint] = &strongSwanPrivateKeyRef{
		keyID: stringValue(resp["id"]),
		refs:  1,
	}
	return nil
}

func (d *StrongSwanDriver) releasePrivateKeyLocked(ctx context.Context, fingerprint string) error {
	ref := d.privateKeys[fingerprint]
	if ref == nil {
		return nil
	}
	if ref.refs > 1 {
		ref.refs--
		return nil
	}
	if ref.keyID != "" {
		callCtx, cancel := d.viciContext(ctx)
		defer cancel()
		if _, err := d.VICI.Call(callCtx, "unload-key", map[string]any{"id": ref.keyID}); err != nil && !isVICIKeyNotFound(err) {
			return err
		}
	}
	delete(d.privateKeys, fingerprint)
	return nil
}

func isVICIKeyNotFound(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "key not found")
}

func (d *StrongSwanDriver) viciContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	timeout := defaultVICIOperationTimeout
	if d != nil && d.OperationTimeout > 0 {
		timeout = d.OperationTimeout
	}
	return context.WithTimeout(ctx, timeout)
}

func (d *StrongSwanDriver) viciInitiateRequest(child string) map[string]any {
	timeout := defaultVICIInitiateServerTimeout
	if d != nil && d.InitiateTimeout > 0 {
		timeout = d.InitiateTimeout
	}
	timeoutMillis := max(timeout.Milliseconds(), 1)
	return map[string]any{
		"child":   child,
		"timeout": fmt.Sprintf("%d", timeoutMillis),
	}
}

func (d *StrongSwanDriver) viciInitiateContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	serverTimeout := defaultVICIInitiateServerTimeout
	if d != nil && d.InitiateTimeout > 0 {
		serverTimeout = d.InitiateTimeout
	}
	timeout := serverTimeout + defaultVICIInitiateClientGrace
	if d != nil && d.InitiateClientTimeout > 0 {
		timeout = d.InitiateClientTimeout
	}
	return context.WithTimeout(ctx, timeout)
}

func (d *StrongSwanDriver) logAsyncInitiateFailure(child string, err error) {
	if d == nil || d.LogConfig == nil || err == nil {
		return
	}
	d.LogConfig("vici_initiate_failed", map[string]any{
		"child": child,
		"error": err.Error(),
	})
}

func (d *StrongSwanDriver) logVICIConfig(event, connection string, msg map[string]any) {
	if d == nil || d.LogConfig == nil {
		return
	}
	sanitized := sanitizeVICIConfigForLog(msg)
	fields := map[string]any{
		"connection": connection,
		"command":    "load-conn",
		"config":     sanitized,
	}
	if data, err := json.Marshal(sanitized); err == nil {
		fields["config_json"] = string(data)
	}
	d.LogConfig(event, fields)
}

func sanitizeVICIConfigForLog(value any) any {
	switch v := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, item := range v {
			switch key {
			case "pubkeys", "privkey", "private_key", "data":
				out[key] = redactVICIConfigValue(item)
			default:
				out[key] = sanitizeVICIConfigForLog(item)
			}
		}
		return out
	case []any:
		out := make([]any, 0, len(v))
		for _, item := range v {
			out = append(out, sanitizeVICIConfigForLog(item))
		}
		return out
	case []string:
		out := make([]any, 0, len(v))
		for _, item := range v {
			out = append(out, sanitizeVICIConfigForLog(item))
		}
		return out
	default:
		return v
	}
}

func redactVICIConfigValue(value any) any {
	switch v := value.(type) {
	case []string:
		if len(v) == 0 {
			return nil
		}
		return fmt.Sprintf("present:%d", len(v))
	case []any:
		if len(v) == 0 {
			return nil
		}
		return fmt.Sprintf("present:%d", len(v))
	case string:
		if v == "" {
			return ""
		}
		return "present"
	default:
		if v == nil {
			return nil
		}
		return "present"
	}
}

func (p *ApplyPlan) add(action, target, detail string) {
	p.Operations = append(p.Operations, ApplyOperation{Action: action, Target: target, Detail: detail})
}

func (d *DryRunDriver) LoadConnection(_ context.Context, spec TransportLinkSpec) error {
	d.Connections = append(d.Connections, spec)
	return nil
}

func (d *DryRunDriver) InitiateChild(_ context.Context, child string) error {
	d.Initiated = append(d.Initiated, child)
	return nil
}

func (d *DryRunDriver) UnloadConnection(_ context.Context, id string) error {
	d.Unloaded = append(d.Unloaded, id)
	return nil
}

func (d *DryRunDriver) TerminateSA(_ context.Context, id string) error {
	d.Terminated = append(d.Terminated, id)
	return nil
}

func (d *DryRunDriver) TerminateSAByID(_ context.Context, id uint64) error {
	d.Terminated = append(d.Terminated, fmt.Sprintf("#%d", id))
	return nil
}

func (d *DryRunDriver) ListSAs(context.Context) ([]SAState, error) {
	return nil, nil
}

func (d *DryRunDriver) ListConnections(context.Context) ([]ConnectionState, error) {
	out := append([]ConnectionState(nil), d.LoadedConnections...)
	for _, spec := range d.Connections {
		out = append(out, ConnectionState{
			Name:           spec.TransportID,
			LocalIdentity:  string(spec.LocalZone),
			RemoteIdentity: string(spec.PeerZone),
		})
	}
	return out, nil
}

func (d *DryRunDriver) LoadPrivateKey(_ context.Context, id string, key []byte, algorithm string) error {
	d.PrivateKeys = append(d.PrivateKeys, DryRunPrivateKey{ID: id, Algorithm: algorithm, Len: len(key)})
	return nil
}

func (d *DryRunDriver) UnloadPrivateKey(_ context.Context, id string) error {
	d.UnloadedKeys = append(d.UnloadedKeys, id)
	return nil
}

func (d *DryRunDriver) EnsureNamespace(_ context.Context, spec NetNSSpec) error {
	d.Namespaces = append(d.Namespaces, spec.Normalized())
	return nil
}

func (d *DryRunDriver) EnsureInterface(_ context.Context, spec TransportLinkSpec) error {
	d.Interfaces = append(d.Interfaces, spec)
	return nil
}

func (d *DryRunDriver) DeleteInterface(_ context.Context, name string) error {
	d.DeletedIFs = append(d.DeletedIFs, name)
	return nil
}

func (d *DryRunDriver) AssignAddress(_ context.Context, spec TransportLinkSpec, address string) error {
	d.Addresses = append(d.Addresses, spec.InterfaceName+"="+address)
	return nil
}

func (d *DryRunDriver) AssignExtraAddress(_ context.Context, spec TransportLinkSpec, address string) error {
	d.Addresses = append(d.Addresses, spec.InterfaceName+"="+address)
	return nil
}
