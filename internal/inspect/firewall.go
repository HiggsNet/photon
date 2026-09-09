package inspect

import "github.com/HiggsNet/photon/pkg/firewall"

const FirewallModeManaged = "managed"

type FirewallDebugView struct {
	Backend   string
	LastError string
	Instances []FirewallInstanceView
}

type FirewallDebugInput struct {
	Instances []FirewallInstanceInput
	Reconcile *firewall.FirewallObservation
}

type FirewallInstanceInput struct {
	ID            string
	Scope         string
	Enabled       bool
	Mode          string
	Backend       string
	DefaultPolicy string
	OwnerPrefix   string
	Transit       bool
	AllowPrefixes int
	DenyPrefixes  int
	AllowFilters  []string
	DenyFilters   []string
	AllowPeers    []string
	DenyPeers     []string
	MetricHint    uint
	LocalServices []FirewallLocalServiceView
	IsHost        bool
	HostIKE       bool
	HostNATT      bool
	RedirectGrace bool
	InlineHooks   []FirewallInlineHookView
}

type FirewallInstanceView struct {
	ID              string
	Scope           string
	Mode            string
	Backend         string
	DefaultPolicy   string
	OwnerPrefix     string
	Transit         bool
	AllowPrefixes   int
	DenyPrefixes    int
	AllowFilters    []string
	DenyFilters     []string
	AllowPeers      []string
	DenyPeers       []string
	MetricHint      uint
	LocalServices   []FirewallLocalServiceView
	IsHost          bool
	HostIKE         bool
	HostNATT        bool
	RedirectGrace   bool
	ResolvedBackend string
	InlineHooks     []FirewallInlineHookView
	Generation      uint64
	OwnedObjects    int
	PolicyHash      string
	LastError       string
}

type FirewallLocalServiceView struct {
	Proto string
	Port  uint16
}

type FirewallInlineHookView struct {
	Backend    string
	Family     string
	Point      string
	Expression string
	State      string
}

func BuildFirewallDebug(input FirewallDebugInput) FirewallDebugView {
	view := FirewallDebugView{}
	if input.Reconcile != nil {
		view.Backend = input.Reconcile.Backend
		view.LastError = input.Reconcile.LastError
	}
	if len(input.Instances) == 0 {
		return view
	}
	for _, inst := range input.Instances {
		mode := inst.Mode
		if mode == "" {
			mode = FirewallModeManaged
		}
		if !inst.Enabled {
			mode = "disabled"
		}
		scope := inst.Scope
		if inst.IsHost {
			scope = "host"
		}
		instView := FirewallInstanceView{
			ID:            inst.ID,
			Scope:         scope,
			Mode:          mode,
			Backend:       inst.Backend,
			DefaultPolicy: inst.DefaultPolicy,
			OwnerPrefix:   inst.OwnerPrefix,
			Transit:       inst.Transit,
			AllowPrefixes: inst.AllowPrefixes,
			DenyPrefixes:  inst.DenyPrefixes,
			AllowFilters:  append([]string(nil), inst.AllowFilters...),
			DenyFilters:   append([]string(nil), inst.DenyFilters...),
			AllowPeers:    append([]string(nil), inst.AllowPeers...),
			DenyPeers:     append([]string(nil), inst.DenyPeers...),
			MetricHint:    inst.MetricHint,
			LocalServices: append([]FirewallLocalServiceView(nil), inst.LocalServices...),
			IsHost:        inst.IsHost,
			HostIKE:       inst.HostIKE,
			HostNATT:      inst.HostNATT,
			RedirectGrace: inst.RedirectGrace,
			InlineHooks:   append([]FirewallInlineHookView(nil), inst.InlineHooks...),
		}
		if snapshot, ok := firewallReconcileInstance(input.Reconcile, inst.ID); ok {
			instView.ResolvedBackend = snapshot.Backend
			instView.Generation = snapshot.Generation
			instView.OwnedObjects = snapshot.OwnedObjects
			instView.PolicyHash = snapshot.PolicyHash
			instView.LastError = snapshot.LastError
		}
		for i := range instView.InlineHooks {
			hook := &instView.InlineHooks[i]
			switch {
			case instView.ResolvedBackend == "":
				hook.State = "pending"
			case hook.Backend == instView.ResolvedBackend:
				hook.State = "active"
			default:
				hook.State = "inactive"
			}
		}
		view.Instances = append(view.Instances, instView)
	}
	return view
}

func firewallReconcileInstance(reconcile *firewall.FirewallObservation, id string) (*firewall.FirewallInstanceObservation, bool) {
	if reconcile == nil || reconcile.Instances == nil {
		return nil, false
	}
	snapshot, ok := reconcile.Instances[id]
	return snapshot, ok && snapshot != nil
}
