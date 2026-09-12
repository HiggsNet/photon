package inspect

import (
	"sort"
	"strings"

	photonstate "github.com/HiggsNet/photon/internal/state"
	"github.com/HiggsNet/photon/pkg/routing/bird"
)

const (
	RoutingModeManaged           = "managed"
	RoutingModeExternal          = "external"
	RoutingModeDisabled          = "disabled"
	RoutingShutdownPolicyPersist = "persist"
)

type BirdDumpResponse struct {
	Instances map[string]BirdDumpInstance `json:"instances"`
}

type BirdDumpInstance struct {
	NetNS             string                 `json:"netns"`
	InstanceID        string                 `json:"instance_id"`
	ControlSocket     string                 `json:"control_socket"`
	ConfigPath        string                 `json:"config_path,omitempty"`
	FilterDefinitions string                 `json:"filter_definitions,omitempty"`
	FilterFailure     *FailureView           `json:"filter_failure,omitempty"`
	Raw               map[string]string      `json:"raw,omitempty"`
	Interfaces        []BirdInterfaceContext `json:"interfaces,omitempty"`
	Neighbors         []BirdBabelNeighbor    `json:"neighbors,omitempty"`
	BabelRoutes       []BirdBabelRoute       `json:"babel_routes,omitempty"`
	BabelEntries      []BirdBabelEntry       `json:"babel_entries,omitempty"`
	Failure           *FailureView           `json:"failure,omitempty"`
}

// BirdInterfaceContext connects BIRD's kernel-facing interface name to the
// Photon link that owns it. Family is the underlay path family, not the
// address family of the Babel prefix.
type BirdInterfaceContext struct {
	Name        string `json:"name"`
	Zone        string `json:"zone,omitempty"`
	Family      string `json:"family,omitempty"`
	LinkID      string `json:"link_id,omitempty"`
	RuntimeRole string `json:"runtime_role,omitempty"`
}

func BuildBirdInterfaceContexts(outputs []photonstate.LinkOutput, netnsName string) map[string]BirdInterfaceContext {
	contexts := make(map[string]BirdInterfaceContext)
	for _, output := range outputs {
		if output.InterfaceName == "" || (output.NetNS != "" && netnsName != "" && output.NetNS != netnsName) {
			continue
		}
		contexts[output.InterfaceName] = BirdInterfaceContext{
			Name:        output.InterfaceName,
			Zone:        string(output.PeerZone),
			Family:      photonstate.LinkPathFamily(output.PathKey),
			LinkID:      output.ID,
			RuntimeRole: output.RuntimeRole,
		}
	}
	return contexts
}

type BirdBabelNeighbor struct {
	Protocol  string `json:"protocol,omitempty"`
	Address   string `json:"address"`
	Interface string `json:"interface"`
	Zone      string `json:"zone,omitempty"`
	Family    string `json:"family,omitempty"`
	Metric    string `json:"metric,omitempty"`
	Routes    string `json:"routes,omitempty"`
	Hellos    string `json:"hellos,omitempty"`
	Expires   string `json:"expires,omitempty"`
	Auth      string `json:"auth,omitempty"`
	RTT       string `json:"rtt_ms,omitempty"`
}

type BirdBabelRoute struct {
	Protocol  string `json:"protocol,omitempty"`
	Prefix    string `json:"prefix"`
	Nexthop   string `json:"nexthop,omitempty"`
	Interface string `json:"interface,omitempty"`
	Zone      string `json:"zone,omitempty"`
	Family    string `json:"family,omitempty"`
	Metric    string `json:"metric,omitempty"`
	Flag      string `json:"flag,omitempty"`
	Seqno     string `json:"seqno,omitempty"`
	Expires   string `json:"expires,omitempty"`
}

type BirdBabelEntry struct {
	Protocol  string `json:"protocol,omitempty"`
	Prefix    string `json:"prefix"`
	RouterID  string `json:"router_id,omitempty"`
	Metric    string `json:"metric,omitempty"`
	Seqno     string `json:"seqno,omitempty"`
	Routes    string `json:"routes,omitempty"`
	Sources   string `json:"sources,omitempty"`
	Interface string `json:"selected_interface,omitempty"`
	Zone      string `json:"zone,omitempty"`
	Family    string `json:"family,omitempty"`
}

func ParseBirdBabelNeighbors(raw string, contexts map[string]BirdInterfaceContext) []BirdBabelNeighbor {
	var out []BirdBabelNeighbor
	protocol := ""
	inTable := false
	for line := range strings.SplitSeq(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasSuffix(trimmed, ":") && len(strings.Fields(trimmed)) == 1 {
			protocol = strings.TrimSuffix(trimmed, ":")
			inTable = false
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) >= 3 && fields[0] == "IP" && fields[1] == "address" {
			inTable = true
			continue
		}
		if !inTable || len(fields) < 8 {
			continue
		}
		context := contexts[fields[1]]
		out = append(out, BirdBabelNeighbor{
			Protocol: protocol, Address: fields[0], Interface: fields[1], Zone: context.Zone, Family: context.Family,
			Metric: fields[2], Routes: fields[3], Hellos: fields[4], Expires: fields[5], Auth: fields[6], RTT: fields[7],
		})
		// Some BIRD versions render the RTT unit as a separate final token;
		// the value itself is always the penultimate or final numeric field.
		out[len(out)-1].RTT = fields[len(fields)-1]
	}
	return out
}

func ParseBirdBabelRoutes(raw string, contexts map[string]BirdInterfaceContext) []BirdBabelRoute {
	var out []BirdBabelRoute
	protocol := ""
	inTable := false
	for line := range strings.SplitSeq(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasSuffix(trimmed, ":") && len(strings.Fields(trimmed)) == 1 {
			protocol = strings.TrimSuffix(trimmed, ":")
			inTable = false
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) >= 2 && fields[0] == "Prefix" && fields[1] == "Nexthop" {
			inTable = true
			continue
		}
		if !inTable || len(fields) < 6 {
			continue
		}
		flag := ""
		seqIndex := 4
		if fields[4] == "*" || fields[4] == "+" {
			flag = fields[4]
			seqIndex = 5
		}
		if len(fields) <= seqIndex+1 {
			continue
		}
		context := contexts[fields[2]]
		out = append(out, BirdBabelRoute{
			Protocol: protocol, Prefix: fields[0], Nexthop: fields[1], Interface: fields[2], Zone: context.Zone,
			Family: context.Family, Metric: fields[3], Flag: flag, Seqno: fields[seqIndex], Expires: fields[seqIndex+1],
		})
	}
	return out
}

func ParseBirdBabelEntries(raw string, routes []BirdBabelRoute, contexts map[string]BirdInterfaceContext) []BirdBabelEntry {
	selected := map[string]BirdBabelRoute{}
	for _, route := range routes {
		if route.Flag == "*" {
			selected[route.Protocol+"\x00"+route.Prefix] = route
		}
	}
	var out []BirdBabelEntry
	protocol := ""
	inTable := false
	for line := range strings.SplitSeq(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasSuffix(trimmed, ":") && len(strings.Fields(trimmed)) == 1 {
			protocol = strings.TrimSuffix(trimmed, ":")
			inTable = false
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) >= 2 && fields[0] == "Prefix" && fields[1] == "Router" {
			inTable = true
			continue
		}
		if !inTable || len(fields) < 6 {
			continue
		}
		route := selected[protocol+"\x00"+fields[0]]
		context := contexts[route.Interface]
		out = append(out, BirdBabelEntry{
			Protocol: protocol, Prefix: fields[0], RouterID: fields[1], Metric: fields[2], Seqno: fields[3],
			Routes: fields[4], Sources: fields[5], Interface: route.Interface, Zone: context.Zone, Family: context.Family,
		})
	}
	return out
}

func EnrichBirdDumpInstance(item *BirdDumpInstance, contexts map[string]BirdInterfaceContext) {
	if item == nil {
		return
	}
	item.Interfaces = make([]BirdInterfaceContext, 0, len(contexts))
	for _, context := range contexts {
		item.Interfaces = append(item.Interfaces, context)
	}
	sort.Slice(item.Interfaces, func(i, j int) bool { return item.Interfaces[i].Name < item.Interfaces[j].Name })
	if raw, ok := item.Raw["show babel neighbors"]; ok {
		item.Neighbors = ParseBirdBabelNeighbors(raw, contexts)
	}
	if raw, ok := item.Raw["show babel routes"]; ok {
		item.BabelRoutes = ParseBirdBabelRoutes(raw, contexts)
	}
	if raw, ok := item.Raw["show babel entries"]; ok {
		item.BabelEntries = ParseBirdBabelEntries(raw, item.BabelRoutes, contexts)
	}
}

func ExtractBirdFilterDefinitions(config string) string {
	var definitions strings.Builder
	inFilter := false
	depth := 0
	for line := range strings.SplitSeq(config, "\n") {
		trimmed := strings.TrimSpace(line)
		if !inFilter {
			if !strings.HasPrefix(trimmed, "filter ") || !strings.HasSuffix(trimmed, "{") {
				continue
			}
			inFilter = true
		}
		if definitions.Len() > 0 {
			definitions.WriteByte('\n')
		}
		definitions.WriteString(line)
		depth += strings.Count(line, "{") - strings.Count(line, "}")
		if inFilter && depth == 0 {
			inFilter = false
		}
	}
	return strings.TrimSpace(definitions.String())
}

type BabelDebugView struct {
	LastReconcileFailure *FailureView
	Instances            []BabelInstanceView
}

type BabelDebugInput struct {
	LastReconcileFailure error
	Instances            []BabelInstanceInput
	LinuxStates          map[string]*bird.InstanceObservation
}

type BabelInstanceInput struct {
	NetNS          string
	InstanceID     string
	Mode           string
	ShutdownPolicy string
	Enabled        bool
}

type BabelInstanceView struct {
	NetNS          string
	InstanceID     string
	Mode           string
	ShutdownPolicy string
	Enabled        bool
	RouterID       uint32
	ControlSocket  string
	ConfigPath     string
	PIDFile        string
	LastConfigHash string
	Overlays       []string
	State          string
	LastFailure    *FailureView
	HasState       bool
}

func BuildBabelDebug(input BabelDebugInput) BabelDebugView {
	view := BabelDebugView{LastReconcileFailure: BuildFailure(FailureCodeRoutingReconcile, input.LastReconcileFailure)}
	for _, inst := range input.Instances {
		mode := inst.Mode
		if mode == "" {
			mode = RoutingModeManaged
		}
		if !inst.Enabled {
			mode = RoutingModeDisabled
		}
		instView := BabelInstanceView{
			NetNS:      inst.NetNS,
			InstanceID: inst.InstanceID,
			Mode:       mode,
			Enabled:    inst.Enabled,
		}
		if inst.Mode != RoutingModeExternal && inst.Mode != RoutingModeDisabled {
			instView.ShutdownPolicy = normalizedRoutingShutdownPolicy(inst.ShutdownPolicy)
		}
		if !inst.Enabled {
			view.Instances = append(view.Instances, instView)
			continue
		}
		runtime, ok := input.LinuxStates[inst.NetNS]
		if ok && runtime != nil {
			instView.HasState = true
			instView.RouterID = runtime.RouterID
			instView.ControlSocket = runtime.ControlSocket
			instView.ConfigPath = runtime.ConfigPath
			instView.PIDFile = runtime.PIDFile
			instView.LastConfigHash = runtime.LastConfigHash
			instView.Overlays = append([]string(nil), runtime.Overlays...)
			instView.State = runtime.State
			instView.LastFailure = BuildFailure(FailureCodeBirdInstance, runtime.LastFailure)
		}
		view.Instances = append(view.Instances, instView)
	}
	return view
}

func normalizedRoutingShutdownPolicy(policy string) string {
	if policy == "" {
		return RoutingShutdownPolicyPersist
	}
	return policy
}
