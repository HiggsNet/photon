package ipsec

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	StrongSwanIKEVersion = "2"
	StrongSwanAuthPubkey = "pubkey"
	StrongSwanChildMode  = "tunnel"
)

func BuildLoadConnMessage(spec TransportLinkSpec) (map[string]any, error) {
	if spec.TransportID == "" {
		return nil, fmt.Errorf("transport id is required")
	}
	if spec.LocalZone == "" {
		return nil, fmt.Errorf("local zone is required")
	}
	if spec.PeerZone == "" {
		return nil, fmt.Errorf("peer zone is required")
	}
	if spec.XFRMIfID == 0 {
		return nil, fmt.Errorf("xfrm if_id is required")
	}
	conn, err := BuildStrongSwanConnection(spec)
	if err != nil {
		return nil, err
	}
	return map[string]any{spec.TransportID: conn}, nil
}

func (d *StrongSwanDriver) buildLoadConnMessage(spec TransportLinkSpec) (map[string]any, error) {
	msg, err := BuildLoadConnMessage(spec)
	if err != nil {
		return nil, err
	}
	if len(spec.PeerPublicKey) == 0 {
		return msg, nil
	}
	// VICI load-conn accepts public keys as PEM encoded key blobs in the list
	// value. Materialize the peer key to KeyDir for diagnostics, but embed the
	// PEM content in the message. Also include the local public key so charon
	// can bind the connection's local identity to the loaded private key.
	if d.KeyDir != "" {
		_, _ = d.materializePeerPublicKey(spec)
	}
	conn, ok := msg[spec.TransportID].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("connection %s missing from load-conn message", spec.TransportID)
	}
	if len(spec.LocalPrivateKey) > 0 {
		localPub, err := DeriveTransportPublicKey(spec.LocalPrivateKey, spec.LocalPrivateKeyAlgorithm)
		if err == nil {
			local, ok := conn["local"].(map[string]any)
			if !ok {
				local = map[string]any{}
				conn["local"] = local
			}
			pemBytes, err := PEMEncodePublicKey(localPub)
			if err == nil {
				local["pubkeys"] = []string{string(pemBytes)}
			}
		}
	}
	remote, ok := conn["remote"].(map[string]any)
	if !ok {
		remote = map[string]any{}
		conn["remote"] = remote
	}
	pemBytes, err := PEMEncodePublicKey(spec.PeerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("encode peer public key for load-conn: %w", err)
	}
	remote["pubkeys"] = []string{string(pemBytes)}
	return msg, nil
}

func (d *StrongSwanDriver) materializePeerPublicKey(spec TransportLinkSpec) (string, error) {
	if d.KeyDir == "" {
		return "", fmt.Errorf("strongswan driver KeyDir is required to materialize peer public key")
	}
	if err := os.MkdirAll(d.KeyDir, 0700); err != nil {
		return "", fmt.Errorf("create key dir: %w", err)
	}
	path := filepath.Join(d.KeyDir, spec.TransportID+"-peer.pub.pem")
	pemBytes, err := PEMEncodePublicKey(spec.PeerPublicKey)
	if err != nil {
		return "", fmt.Errorf("encode peer public key: %w", err)
	}
	if err := os.WriteFile(path, pemBytes, 0600); err != nil {
		return "", fmt.Errorf("write peer public key: %w", err)
	}
	return path, nil
}

func BuildStrongSwanConnection(spec TransportLinkSpec) (map[string]any, error) {
	point, hasPoint := firstContactPoint(spec.ContactPoints)
	if !hasPoint && IsActiveInitiatorRole(spec.InitiatorRole) {
		return nil, fmt.Errorf("at least one contact point is required")
	}
	remoteAddr, err := strongSwanRemoteAddress(spec, point, hasPoint)
	if err != nil {
		return nil, err
	}
	childName := ChildSAName(spec)
	localAddrs := []string{"%any"}
	if spec.LocalAddress != "" {
		localAddrs = []string{spec.LocalAddress}
	}
	conn := map[string]any{
		"version":      StrongSwanIKEVersion,
		"local_addrs":  localAddrs,
		"remote_addrs": []string{remoteAddr},
		"encap":        "yes",
		"mobike":       "no",
		"unique":       "never",
		"local": map[string]any{
			"auth": StrongSwanAuthPubkey,
			"id":   localIdentity(spec),
		},
		"remote": map[string]any{
			"auth": StrongSwanAuthPubkey,
			"id":   remoteIdentity(spec),
		},
		"children": map[string]any{
			childName: routeBasedChildSA(spec),
		},
	}
	if hasPoint {
		remotePort := chooseStrongSwanRemotePort(point)
		conn["remote_port"] = fmt.Sprintf("%d", remotePort)
		if remotePort != DefaultIKEPort && spec.LocalIKEPort == 0 {
			conn["local_port"] = fmt.Sprintf("%d", DefaultNATTPort)
		}
	}
	if spec.LocalIKEPort != 0 {
		conn["local_port"] = fmt.Sprintf("%d", spec.LocalIKEPort)
	}
	return conn, nil
}

func ChildSAName(spec TransportLinkSpec) string {
	if spec.TransportID == "" {
		return "photon-child"
	}
	return spec.TransportID + "-child"
}

func RotateConnectionName(transportID string, generation uint64) string {
	return transportID + "-r" + strconv.FormatUint(generation, 10)
}

// BaseConnectionName returns the original connection name for a rotated
// connection name produced by RotateConnectionName. If the transport ID is not
// a rotated name, it is returned unchanged.
func BaseConnectionName(transportID string) string {
	if i := strings.LastIndex(transportID, "-rot-"); i >= 0 {
		return transportID[:i]
	}
	if i := strings.LastIndex(transportID, "-r"); i >= 0 {
		suffix := transportID[i+2:]
		if suffix != "" {
			if _, err := strconv.ParseUint(suffix, 10, 64); err == nil {
				return transportID[:i]
			}
		}
	}
	return transportID
}

func routeBasedChildSA(spec TransportLinkSpec) map[string]any {
	// Photon drives active CHILD_SA establishment exclusively through its
	// explicit VICI initiate path.  Keep the loaded child passive so a
	// secondary-standby responder can't be promoted implicitly by traffic
	// hitting a trap policy during a rolling or batch restart.
	startAction := "none"
	return map[string]any{
		"mode":         StrongSwanChildMode,
		"local_ts":     broadTrafficSelectors(spec.LocalTunnelAddr),
		"remote_ts":    broadTrafficSelectors(spec.PeerTunnelAddr),
		"if_id_in":     fmt.Sprintf("%d", spec.XFRMIfID),
		"if_id_out":    fmt.Sprintf("%d", spec.XFRMIfID),
		"start_action": startAction,
	}
}

func broadTrafficSelectors(addr netip.Addr) []string {
	if addr.IsValid() && addr.Is4() {
		return []string{"0.0.0.0/0"}
	}
	if addr.IsValid() && addr.Is6() {
		return []string{"::/0"}
	}
	return []string{"0.0.0.0/0", "::/0"}
}

func firstContactPoint(points []ContactPoint) (ContactPoint, bool) {
	if len(points) == 0 {
		return ContactPoint{}, false
	}
	return points[0], true
}

func strongSwanRemoteAddress(spec TransportLinkSpec, point ContactPoint, hasPoint bool) (string, error) {
	if !hasPoint {
		switch pathKeyFamily(spec.PathKey) {
		case FamilyIPv4:
			// Older strongSwan releases only recognize %any.  Use an explicit
			// family-specific subnet so responder matching does not attempt to
			// resolve %any4 as a DNS name on every IKE request.
			return "0.0.0.0/0", nil
		case FamilyIPv6:
			return "::/0", nil
		}
		return "%any", nil
	}
	remoteAddr := point.Address
	if remoteAddr == "" {
		remoteAddr = point.Host
	}
	if remoteAddr == "" {
		return "", fmt.Errorf("contact point address or host is required")
	}
	return remoteAddr, nil
}

func chooseStrongSwanRemotePort(point ContactPoint) uint16 {
	if point.NATTPort != 0 {
		return point.NATTPort
	}
	if point.IKEPort != 0 {
		return point.IKEPort
	}
	return DefaultIKEPort
}

func localIdentity(spec TransportLinkSpec) string {
	if spec.IKEIdentity != "" {
		return spec.IKEIdentity
	}
	return string(spec.LocalZone)
}

func remoteIdentity(spec TransportLinkSpec) string {
	return string(spec.PeerZone)
}

func parseSAStates(event map[string]any) []SAState {
	var states []SAState
	for name, raw := range event {
		body, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		state := SAState{Name: name}
		state.UniqueID = uint64Value(body["uniqueid"])
		state.IKEAgeSeconds = uint64Value(body["established"])
		state.Initiator, state.InitiatorKnown = boolValue(body["initiator"])
		remoteHost := stringValue(body["remote-host"])
		remotePort := stringValue(body["remote-port"])
		localHost := stringValue(body["local-host"])
		localPort := stringValue(body["local-port"])
		state.Peer = remoteHost
		state.IKEState = stringValue(body["state"])
		state.LocalIdentity = stringValue(body["local-id"])
		state.RemoteIdentity = stringValue(body["remote-id"])
		state.LocalEndpoint = joinEndpoint(localHost, localPort)
		state.RemoteEndpoint = joinEndpoint(remoteHost, remotePort)
		state.Endpoint = state.RemoteEndpoint
		children, _ := body["child-sas"].(map[string]any)
		for childName, childRaw := range children {
			child, _ := childRaw.(map[string]any)
			childState := state
			childState.ChildSA = stripChildSAReqidSuffix(childName)
			childState.ChildState = stringValue(child["state"])
			childState.XFRMIfID = firstHexUint32(child["if-id-out"], child["if-id-in"])
			childState.ReqID = uint32Value(child["reqid"])
			childState.ChildAgeSeconds = uint64Value(child["install-time"])
			childState.InboundBytes, _ = firstUint64Value(child, "bytes-in", "bytes_in")
			inboundPackets, packetsKnown := firstUint64Value(child, "packets-in", "packets_in")
			inboundIdle, idleKnown := firstUint64Value(child, "use-in", "use_in")
			childState.InboundPackets = inboundPackets
			childState.InboundIdleSecs = inboundIdle
			childState.InboundKnown = packetsKnown && (childState.InboundPackets == 0 || idleKnown)
			childState.Established = strongSwanSAEstablished(childState.IKEState, childState.ChildState)
			states = append(states, childState)
		}
		if len(children) == 0 {
			state.Established = strongSwanSAEstablished(state.IKEState, "")
			states = append(states, state)
		}
	}
	return states
}

func firstUint64Value(values map[string]any, keys ...string) (uint64, bool) {
	for _, key := range keys {
		value, ok := values[key]
		if !ok {
			continue
		}
		return uint64Value(value), true
	}
	return 0, false
}

func parseConnectionStates(event map[string]any) []ConnectionState {
	var states []ConnectionState
	for name, raw := range event {
		body, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		state := ConnectionState{Name: name}
		local, _ := body["local"].(map[string]any)
		remote, _ := body["remote"].(map[string]any)
		state.LocalIdentity = firstString(body["local-id"], body["local_id"], local["id"])
		state.RemoteIdentity = firstString(body["remote-id"], body["remote_id"], remote["id"])
		state.RemoteEndpoint = firstConnectionRemoteEndpoint(body)
		states = append(states, state)
	}
	return states
}

func firstConnectionRemoteEndpoint(body map[string]any) string {
	host := firstString(body["remote-host"], body["remote_host"])
	if host == "" {
		host = firstStringFromList(body["remote_addrs"], body["remote-addrs"])
	}
	port := firstString(body["remote-port"], body["remote_port"])
	return joinEndpoint(host, port)
}

func firstStringFromList(values ...any) string {
	for _, value := range values {
		switch v := value.(type) {
		case []string:
			if len(v) > 0 {
				return v[0]
			}
		case []any:
			if len(v) > 0 {
				if s := stringValue(v[0]); s != "" {
					return s
				}
			}
		}
	}
	return ""
}

func strongSwanSAEstablished(ikeState, childState string) bool {
	return strings.EqualFold(ikeState, "ESTABLISHED") || strings.EqualFold(childState, "INSTALLED")
}

// stripChildSAReqidSuffix removes the StrongSwan VICI child-sa reqid suffix
// (e.g. "ipsec-foo-child{2}" -> "ipsec-foo-child") so that state comparisons
// can use the configured child name.
func stripChildSAReqidSuffix(name string) string {
	if i := strings.LastIndex(name, "{"); i >= 0 {
		return name[:i]
	}
	return name
}

func stringValue(v any) string {
	switch value := v.(type) {
	case string:
		return value
	case []byte:
		return string(value)
	case fmt.Stringer:
		return value.String()
	default:
		return ""
	}
}

func uint32Value(v any) uint32 {
	switch value := v.(type) {
	case uint32:
		return value
	case uint64:
		return uint32(value)
	case uint:
		return uint32(value)
	case int:
		if value > 0 {
			return uint32(value)
		}
	case int64:
		if value > 0 {
			return uint32(value)
		}
	case float64:
		if value > 0 {
			return uint32(value)
		}
	case string:
		parsed, err := strconv.ParseUint(value, 10, 32)
		if err == nil {
			return uint32(parsed)
		}
	case []byte:
		parsed, err := strconv.ParseUint(string(value), 10, 32)
		if err == nil {
			return uint32(parsed)
		}
	}
	return 0
}

func uint64Value(v any) uint64 {
	switch value := v.(type) {
	case uint64:
		return value
	case uint32:
		return uint64(value)
	case uint:
		return uint64(value)
	case int:
		if value > 0 {
			return uint64(value)
		}
	case int64:
		if value > 0 {
			return uint64(value)
		}
	case float64:
		if value > 0 {
			return uint64(value)
		}
	case string:
		parsed, err := strconv.ParseUint(value, 10, 64)
		if err == nil {
			return parsed
		}
	case []byte:
		parsed, err := strconv.ParseUint(string(value), 10, 64)
		if err == nil {
			return parsed
		}
	}
	return 0
}

func boolValue(v any) (bool, bool) {
	switch value := v.(type) {
	case bool:
		return value, true
	case string:
		switch strings.ToLower(value) {
		case "yes", "true", "1":
			return true, true
		case "no", "false", "0":
			return false, true
		}
	case []byte:
		return boolValue(string(value))
	}
	return false, false
}

func firstUint32(values ...any) uint32 {
	for _, value := range values {
		if parsed := uint32Value(value); parsed != 0 {
			return parsed
		}
	}
	return 0
}

func hexUint32Value(v any) uint32 {
	switch value := v.(type) {
	case string:
		parsed, err := strconv.ParseUint(value, 16, 32)
		if err == nil {
			return uint32(parsed)
		}
	case []byte:
		parsed, err := strconv.ParseUint(string(value), 16, 32)
		if err == nil {
			return uint32(parsed)
		}
	default:
		return uint32Value(v)
	}
	return 0
}

func firstHexUint32(values ...any) uint32 {
	for _, value := range values {
		if parsed := hexUint32Value(value); parsed != 0 {
			return parsed
		}
	}
	return 0
}

func joinEndpoint(host, port string) string {
	if host == "" {
		return ""
	}
	if port == "" {
		return host
	}
	return net.JoinHostPort(host, port)
}
