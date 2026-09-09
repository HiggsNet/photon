package inspect

import "github.com/HiggsNet/photon/pkg/routing/bird"

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
	FilterError       string                 `json:"filter_error,omitempty"`
	Raw               map[string]string      `json:"raw,omitempty"`
	Interfaces        []BirdInterfaceContext `json:"interfaces,omitempty"`
	Neighbors         []BirdBabelNeighbor    `json:"neighbors,omitempty"`
	BabelRoutes       []BirdBabelRoute       `json:"babel_routes,omitempty"`
	BabelEntries      []BirdBabelEntry       `json:"babel_entries,omitempty"`
	Error             string                 `json:"error,omitempty"`
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

type BabelDebugView struct {
	LastReconcileError string
	Instances          []BabelInstanceView
}

type BabelDebugInput struct {
	LastReconcileError string
	Instances          []BabelInstanceInput
	RuntimeStates      map[string]*bird.InstanceObservation
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
	LastError      string
	HasState       bool
}

func BuildBabelDebug(input BabelDebugInput) BabelDebugView {
	view := BabelDebugView{LastReconcileError: input.LastReconcileError}
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
		runtime, ok := input.RuntimeStates[inst.NetNS]
		if ok && runtime != nil {
			instView.HasState = true
			instView.RouterID = runtime.RouterID
			instView.ControlSocket = runtime.ControlSocket
			instView.ConfigPath = runtime.ConfigPath
			instView.PIDFile = runtime.PIDFile
			instView.LastConfigHash = runtime.LastConfigHash
			instView.Overlays = append([]string(nil), runtime.Overlays...)
			instView.State = runtime.State
			instView.LastError = runtime.LastError
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
