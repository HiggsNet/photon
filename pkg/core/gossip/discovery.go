package gossip

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

const (
	// EndpointRecordKeyPrefix is the prefix for endpoint records in a zone.
	EndpointRecordKeyPrefix = "sync/endpoint/"
	// EndpointRecordKeyUDP is the well-known key for UDP gossip endpoints.
	EndpointRecordKeyUDP = "sync/endpoint/udp"
	// DefaultEndpointTTL is used when an endpoint record does not carry a TTL.
	DefaultEndpointTTL = 3 * time.Hour
	// DefaultEndpointRefresh is the stable-address lease renewal cadence.
	DefaultEndpointRefresh = 30 * time.Minute
	// DefaultEndpointGrace is the old-address retention window after an endpoint changes.
	DefaultEndpointGrace = 10 * time.Minute
)

var ipCandidatePattern = regexp.MustCompile(`[0-9A-Fa-f:.]{3,}`)

var defaultPublicIPReflectors = []string{
	"https://api.ipify.org",
	"https://myip.ipip.net",
	"https://ddns.oray.com/checkip",
	"https://ip.3322.net",
	"https://4.ipw.cn",
	"https://v4.yinghualuo.cn/bejson",
	"https://api64.ipify.org",
	"https://speed.neu6.edu.cn/getIP.php",
	"https://v6.ident.me",
	"https://6.ipw.cn",
	"https://v6.yinghualuo.cn/bejson",
}

// EndpointRecord is the JSON value stored under sync/endpoint/* keys.
type EndpointRecord struct {
	Endpoints    []EndpointEntry `json:"endpoints"`
	TTL          int64           `json:"ttl_seconds,omitempty"`
	GraceSeconds int64           `json:"grace_seconds,omitempty"`
	Source       string          `json:"source,omitempty"`
	UpdatedAt    int64           `json:"updated_at,omitempty"`
}

// EndpointEntry represents a single network endpoint.
type EndpointEntry struct {
	Address      string `json:"address"`
	Port         uint16 `json:"port"`
	Protocol     string `json:"protocol,omitempty"`
	Scope        string `json:"scope,omitempty"`
	Source       string `json:"source,omitempty"`
	Priority     int    `json:"priority,omitempty"`
	LastObserved int64  `json:"last_observed,omitempty"`
}

// UDPAddr resolves the entry to a UDP address.
func (e EndpointEntry) UDPAddr() (*net.UDPAddr, error) {
	ip := net.ParseIP(e.Address)
	if ip == nil {
		return nil, fmt.Errorf("invalid address: %s", e.Address)
	}
	return &net.UDPAddr{IP: ip, Port: int(e.Port)}, nil
}

// ExtractPeerEndpoints scans all verified active zones for endpoint records
// and returns a map from peer ID (zone name) to endpoint entries.
func ExtractPeerEndpoints(ns *zone.NetworkState) map[string][]EndpointEntry {
	return ExtractPeerEndpointsAt(ns, time.Now())
}

// ExtractPeerEndpointsAt scans all verified active zones for endpoint records
// and filters endpoints whose TTL/grace window has elapsed.
func ExtractPeerEndpointsAt(ns *zone.NetworkState, now time.Time) map[string][]EndpointEntry {
	out := make(map[string][]EndpointEntry)
	if ns == nil {
		return out
	}
	for path, zs := range ns.Zones {
		if ns.IsZoneRevoked(path, now) {
			continue
		}
		peerID := string(path)
		for key, record := range zs.Records {
			if !strings.HasPrefix(key, EndpointRecordKeyPrefix) {
				continue
			}
			var er EndpointRecord
			if err := json.Unmarshal(record.Value, &er); err != nil {
				continue
			}
			recordUpdatedAt := er.UpdatedAt
			if recordUpdatedAt == 0 {
				recordUpdatedAt = record.Timestamp
			}
			for _, ep := range er.Endpoints {
				if ep.Protocol == "" {
					ep.Protocol = "udp"
				}
				if ep.LastObserved == 0 {
					ep.LastObserved = recordUpdatedAt
				}
				if endpointExpired(ep, er, now) {
					continue
				}
				out[peerID] = append(out[peerID], ep)
			}
		}
	}
	for _, entries := range out {
		sort.SliceStable(entries, func(i, j int) bool {
			if entries[i].Priority != entries[j].Priority {
				return entries[i].Priority > entries[j].Priority
			}
			return entries[i].LastObserved > entries[j].LastObserved
		})
	}
	return out
}

func endpointExpired(ep EndpointEntry, record EndpointRecord, now time.Time) bool {
	ttl := time.Duration(record.TTL) * time.Second
	if ttl <= 0 {
		ttl = DefaultEndpointTTL
	}
	grace := max(time.Duration(record.GraceSeconds)*time.Second, 0)
	if ep.LastObserved == 0 {
		return false
	}
	expiresAt := time.Unix(ep.LastObserved, 0).Add(ttl + grace)
	return now.After(expiresAt)
}

// LocalEndpointSource indicates how a local endpoint was discovered.
type LocalEndpointSource int

const (
	// SourceAdvertise means the endpoint came from explicit configuration.
	SourceAdvertise LocalEndpointSource = iota
	// SourceInterface means the endpoint came from local interface scanning.
	SourceInterface
	// SourceReflector means the endpoint came from a public IP reflector.
	SourceReflector
)

// LocalEndpoint is a candidate endpoint on this machine.
type LocalEndpoint struct {
	IP       net.IP
	Port     uint16
	Scope    string
	Priority int
	Source   LocalEndpointSource
}

// ResolvePublicIPReflectors expands the "auto" preset while preserving
// explicitly configured reflector order. Values "none", "off", and "disabled"
// are ignored so callers can disable an inherited preset.
func ResolvePublicIPReflectors(reflectors []string) []string {
	var out []string
	seen := make(map[string]bool)
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			return
		}
		seen[value] = true
		out = append(out, value)
	}
	for _, reflector := range reflectors {
		switch strings.ToLower(strings.TrimSpace(reflector)) {
		case "", "none", "off", "disabled":
			continue
		case "auto", "default", "defaults", "builtin", "builtins":
			for _, preset := range defaultPublicIPReflectors {
				add(preset)
			}
		default:
			add(reflector)
		}
	}
	return out
}

// CollectLocalEndpoints combines explicit addresses, previously discovered
// public IPs, and local interfaces. It performs no external query.
// When filterPrivateIPv4 is true, RFC1918 IPv4 addresses from local interfaces
// are excluded.
func CollectLocalEndpoints(listenPort uint16, advertiseAddrs []string, publicIPs []net.IP, filterPrivateIPv4 bool) []LocalEndpoint {
	var out []LocalEndpoint
	for _, addr := range advertiseAddrs {
		ip, port, err := parseHostPortDefault(addr, listenPort)
		if err != nil {
			continue
		}
		out = append(out, LocalEndpoint{
			IP:       ip,
			Port:     port,
			Scope:    "advertise",
			Priority: 100,
			Source:   SourceAdvertise,
		})
	}
	for _, ip := range publicIPs {
		out = append(out, LocalEndpoint{IP: ip, Port: listenPort, Scope: "global", Priority: 50, Source: SourceReflector})
	}
	out = append(out, scanInterfaceEndpoints(listenPort, filterPrivateIPv4)...)
	return dedupLocalEndpoints(out)
}

func parseHostPortDefault(addr string, defaultPort uint16) (net.IP, uint16, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
		portStr = ""
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, 0, fmt.Errorf("invalid ip: %s", host)
	}
	port := defaultPort
	if portStr != "" {
		var p int
		if _, err := fmt.Sscanf(portStr, "%d", &p); err == nil && p > 0 && p <= 65535 {
			port = uint16(p)
		}
	}
	return ip, port, nil
}

func scanInterfaceEndpoints(listenPort uint16, filterPrivateIPv4 bool) []LocalEndpoint {
	var out []LocalEndpoint
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipNet.IP
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
				continue
			}
			if filterPrivateIPv4 && ip.To4() != nil && ip.IsPrivate() {
				continue
			}
			if isTemporaryOrContainerIface(iface.Name) {
				continue
			}
			scope := "site"
			if ip.IsGlobalUnicast() {
				scope = "global"
			}
			priority := 10
			if ip.To4() != nil {
				priority = 20
			}
			out = append(out, LocalEndpoint{
				IP:       ip,
				Port:     listenPort,
				Scope:    scope,
				Priority: priority,
				Source:   SourceInterface,
			})
		}
	}
	return out
}

func isTemporaryOrContainerIface(name string) bool {
	n := strings.ToLower(name)
	return strings.HasPrefix(n, "docker") ||
		strings.HasPrefix(n, "br-") ||
		strings.HasPrefix(n, "veth") ||
		strings.HasPrefix(n, "cali") ||
		strings.HasPrefix(n, "flannel") ||
		strings.HasPrefix(n, "wg")
}

func dedupLocalEndpoints(in []LocalEndpoint) []LocalEndpoint {
	seen := make(map[string]bool)
	var out []LocalEndpoint
	for _, ep := range in {
		key := fmt.Sprintf("%s/%d", ep.IP.String(), ep.Port)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, ep)
	}
	return out
}

// QueryPublicIPs uses one caller-owned budget for all reflector HTTP requests.
func QueryPublicIPs(ctx context.Context, reflectors []string, client *http.Client) ([]net.IP, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	reflectors = ResolvePublicIPReflectors(reflectors)
	if len(reflectors) == 0 {
		return nil, errors.New("no reflectors configured")
	}

	ctx, cancel := context.WithCancel(ctx)
	var requests sync.WaitGroup
	defer func() {
		cancel()
		requests.Wait()
	}()

	type result struct {
		ip  net.IP
		err error
	}
	outCh := make(chan result, len(reflectors))

	for _, r := range reflectors {
		requests.Add(1)
		go func() {
			defer requests.Done()
			ip, err := queryPublicIPCtx(ctx, client, r)
			select {
			case outCh <- result{ip, err}:
			case <-ctx.Done():
			}
		}()
	}

	var out []net.IP
	var have4, have6 bool
	var lastErr error

	for i := 0; i < len(reflectors); i++ {
		var res result
		select {
		case <-ctx.Done():
			return out, ctx.Err()
		case res = <-outCh:
		}
		if res.err != nil {
			lastErr = res.err
			continue
		}
		if appendIPByFamily(&out, res.ip, &have4, &have6) && have4 && have6 {
			return out, nil
		}
	}

	if len(out) > 0 {
		return out, nil
	}
	if lastErr == nil {
		lastErr = errors.New("all reflectors failed")
	}
	return nil, lastErr
}

func appendIPByFamily(out *[]net.IP, ip net.IP, have4, have6 *bool) bool {
	if ip == nil {
		return false
	}
	if ip.To4() != nil {
		if *have4 {
			return false
		}
		*have4 = true
		*out = append(*out, ip)
		return true
	}
	if *have6 {
		return false
	}
	*have6 = true
	*out = append(*out, ip)
	return true
}

func queryPublicIPCtx(ctx context.Context, client *http.Client, reflector string) (net.IP, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reflector, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("reflector %s returned status %s", reflector, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, err
	}
	ip := parseReflectorIP(body)
	if ip == nil {
		return nil, fmt.Errorf("reflector %s returned no valid ip", reflector)
	}
	return ip, nil
}

func parseReflectorIP(body []byte) net.IP {
	text := strings.TrimSpace(string(body))
	if ip := parseIPToken(text); ip != nil {
		return ip
	}
	var value any
	if err := json.Unmarshal(body, &value); err != nil {
		return nil
	}
	return findIPInJSON(value)
}

func findIPInJSON(value any) net.IP {
	switch v := value.(type) {
	case string:
		return parseIPToken(v)
	case []any:
		for _, item := range v {
			if ip := findIPInJSON(item); ip != nil {
				return ip
			}
		}
	case map[string]any:
		for _, key := range []string{"ip", "origin", "query", "address", "public_ip"} {
			if item, ok := v[key]; ok {
				if ip := findIPInJSON(item); ip != nil {
					return ip
				}
			}
		}
		for _, item := range v {
			if ip := findIPInJSON(item); ip != nil {
				return ip
			}
		}
	}
	return nil
}

func parseIPToken(value string) net.IP {
	value = strings.Trim(value, " \t\r\n\"'")
	if ip := net.ParseIP(value); ip != nil {
		return ip
	}
	for _, token := range strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == ' '
	}) {
		token = strings.Trim(token, " \t\r\n\"'")
		if ip := net.ParseIP(token); ip != nil {
			return ip
		}
	}
	for _, candidate := range ipCandidatePattern.FindAllString(value, -1) {
		candidate = strings.Trim(candidate, ".:")
		if ip := net.ParseIP(candidate); ip != nil {
			return ip
		}
	}
	return nil
}

// LocalEndpointsToRecordWithPolicy builds an EndpointRecord and carries recently
// observed old endpoints through the configured grace window.
func LocalEndpointsToRecordWithPolicy(endpoints []LocalEndpoint, previous *EndpointRecord, now time.Time, ttl, grace time.Duration) *EndpointRecord {
	if ttl <= 0 {
		ttl = DefaultEndpointTTL
	}
	if grace < 0 {
		grace = 0
	}
	er := &EndpointRecord{
		Source:       "local",
		UpdatedAt:    now.Unix(),
		TTL:          int64(ttl / time.Second),
		GraceSeconds: int64(grace / time.Second),
	}
	active := make(map[string]bool)
	for _, ep := range endpoints {
		entry := localEndpointEntry(ep, now)
		er.Endpoints = append(er.Endpoints, EndpointEntry{
			Address:      entry.Address,
			Port:         entry.Port,
			Scope:        entry.Scope,
			Source:       entry.Source,
			Priority:     entry.Priority,
			Protocol:     entry.Protocol,
			LastObserved: entry.LastObserved,
		})
		active[endpointKey(entry)] = true
	}
	if previous != nil && grace > 0 {
		for _, ep := range previous.Endpoints {
			if ep.Protocol == "" {
				ep.Protocol = "udp"
			}
			if ep.LastObserved == 0 {
				ep.LastObserved = previous.UpdatedAt
			}
			if ep.LastObserved == 0 || active[endpointKey(ep)] {
				continue
			}
			if now.After(time.Unix(ep.LastObserved, 0).Add(grace)) {
				continue
			}
			ep.Source = mergeEndpointSource(ep.Source, "grace")
			if ep.Priority > 0 {
				ep.Priority--
			}
			er.Endpoints = append(er.Endpoints, ep)
		}
	}
	sort.SliceStable(er.Endpoints, func(i, j int) bool {
		if er.Endpoints[i].Priority != er.Endpoints[j].Priority {
			return er.Endpoints[i].Priority > er.Endpoints[j].Priority
		}
		return er.Endpoints[i].LastObserved > er.Endpoints[j].LastObserved
	})
	return er
}

func localEndpointEntry(ep LocalEndpoint, now time.Time) EndpointEntry {
	return EndpointEntry{
		Address:      ep.IP.String(),
		Port:         ep.Port,
		Scope:        ep.Scope,
		Source:       localEndpointSourceName(ep.Source),
		Priority:     ep.Priority,
		Protocol:     "udp",
		LastObserved: now.Unix(),
	}
}

func localEndpointSourceName(source LocalEndpointSource) string {
	switch source {
	case SourceAdvertise:
		return "advertise"
	case SourceInterface:
		return "interface"
	case SourceReflector:
		return "reflector"
	default:
		return "unknown"
	}
}

func mergeEndpointSource(source, suffix string) string {
	if source == "" {
		return suffix
	}
	if strings.Contains(source, suffix) {
		return source
	}
	return source + "+" + suffix
}

func endpointKey(ep EndpointEntry) string {
	protocol := ep.Protocol
	if protocol == "" {
		protocol = "udp"
	}
	return fmt.Sprintf("%s/%s/%d", protocol, ep.Address, ep.Port)
}

// EndpointRecordEndpointsEqual reports whether two endpoint records describe
// the same set of endpoints, ignoring timestamps and record metadata that
// change every publish cycle.
func EndpointRecordEndpointsEqual(a, b *EndpointRecord) bool {
	if a == nil || b == nil {
		return a == b
	}
	if len(a.Endpoints) != len(b.Endpoints) {
		return false
	}
	counts := make(map[string]int, len(a.Endpoints))
	for _, ep := range a.Endpoints {
		counts[endpointCompareKey(ep)]++
	}
	for _, ep := range b.Endpoints {
		counts[endpointCompareKey(ep)]--
	}
	for _, v := range counts {
		if v != 0 {
			return false
		}
	}
	return true
}

func endpointCompareKey(ep EndpointEntry) string {
	protocol := ep.Protocol
	if protocol == "" {
		protocol = "udp"
	}
	return fmt.Sprintf("%s/%s/%d/%s/%s/%d", protocol, ep.Address, ep.Port, ep.Scope, ep.Source, ep.Priority)
}
