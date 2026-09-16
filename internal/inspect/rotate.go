package inspect

import (
	"net"
	"strings"

	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

type ManualPortRotateView struct {
	Zone               zone.ZonePath
	PreviousGeneration uint64
	CurrentGeneration  uint64
	PreviousIKE        uint16
	PreviousNATT       uint16
	CurrentIKE         uint16
	CurrentNATT        uint16
	PreviousValidUntil int64
}

type RotateDebugView struct {
	LastRunUnix       int64
	LinkInstances     int
	PlannedDesired    int
	ReplanIgnored     bool
	LastDesiredLinks  int
	DesiredPlanSource string
	Filter            string
	StoredLabel       string
	LiveLabel         string
	ReconcileSACount  int
	LiveSACount       int
	LiveSAError       string
	Links             []RotateDebugLink
}

type RotateDebugInput struct {
	Inspection        LinkInspection
	PlannedSpecs      map[string]ipsec.TransportLinkSpec
	LastDesiredCount  int
	ReplanIgnored     bool
	LastDesiredLinks  int
	DesiredPlanSource string
	Filter            string
	StoredLabel       string
	LiveLabel         string
	ReconcileSAs      []LinkSA
	LiveSAs           []LinkSA
	LiveSAError       string
}

type RotateDebugLink struct {
	Link                  LinkView
	PortGenerationSummary string
	PortSummary           string
	Current               RotateRuntimeView
	Staged                RotateRuntimeView
	HasStaged             bool
	ReconcileMatchingSAs  []LinkSA
	LiveMatchingSAs       []LinkSA
}

type RotateRuntimeView struct {
	State           string
	Generation      uint64
	Port            string
	RuntimeID       string
	ChildSAName     string
	InterfaceName   string
	XFRMIfID        uint32
	Endpoint        string
	LocalTunnelAddr string
	PeerTunnelAddr  string
}

func BuildRotateDebug(input RotateDebugInput) RotateDebugView {
	links := FilterLinkViews(input.Inspection.Links, input.Filter)
	view := RotateDebugView{
		LastRunUnix:       input.Inspection.LastRunUnix,
		LinkInstances:     input.Inspection.LinkInstances,
		PlannedDesired:    input.LastDesiredCount,
		ReplanIgnored:     input.ReplanIgnored,
		LastDesiredLinks:  input.LastDesiredLinks,
		DesiredPlanSource: input.DesiredPlanSource,
		Filter:            strings.TrimSpace(input.Filter),
		StoredLabel:       input.StoredLabel,
		LiveLabel:         input.LiveLabel,
		ReconcileSACount:  len(input.ReconcileSAs),
		LiveSACount:       len(input.LiveSAs),
		LiveSAError:       input.LiveSAError,
	}
	allSAs := append(append([]LinkSA(nil), input.ReconcileSAs...), input.LiveSAs...)
	for _, link := range links {
		spec, hasSpec := input.PlannedSpecs[link.ID]
		var specPtr *ipsec.TransportLinkSpec
		if hasSpec {
			specPtr = &spec
		}
		staged := RotateRuntimeStaged(link, specPtr, allSAs)
		view.Links = append(view.Links, RotateDebugLink{
			Link:                  link,
			PortGenerationSummary: DebugPortGenerationSummary(specPtr, link.Rotation),
			PortSummary:           DebugPortSummary(specPtr, link.Endpoint, link.Endpoint, link.Rotation.StagedGeneration),
			Current:               RotateRuntimeCurrent(link, specPtr),
			Staged:                staged,
			HasStaged:             !RotateRuntimeEmpty(staged),
			ReconcileMatchingSAs:  MatchingRotateSAs(link, input.ReconcileSAs),
			LiveMatchingSAs:       MatchingRotateSAs(link, input.LiveSAs),
		})
	}
	return view
}

func RotateRuntimeEmpty(v RotateRuntimeView) bool {
	return v.RuntimeID == "" && v.ChildSAName == "" && v.InterfaceName == "" && v.XFRMIfID == 0 && v.State == ""
}

func RotateRuntimeCurrent(link LinkView, spec *ipsec.TransportLinkSpec) RotateRuntimeView {
	out := RotateRuntimeView{
		State:           "expected_current",
		Generation:      link.Rotation.RemoteGeneration,
		Port:            DebugEndpointPort(link.Endpoint),
		RuntimeID:       firstNonEmpty(link.IKEName, link.TransportID),
		ChildSAName:     link.ChildSAName,
		InterfaceName:   link.InterfaceName,
		XFRMIfID:        link.XFRMIfID,
		Endpoint:        link.Endpoint,
		LocalTunnelAddr: link.LocalTunnelAddr,
		PeerTunnelAddr:  link.PeerTunnelAddr,
	}
	if link.Desired != nil {
		out.RuntimeID = firstNonEmpty(out.RuntimeID, link.Desired.TransportID)
		out.InterfaceName = firstNonEmpty(out.InterfaceName, link.Desired.InterfaceName)
		out.XFRMIfID = firstNonZeroUint32(out.XFRMIfID, link.Desired.XFRMIfID)
		out.Endpoint = firstNonEmpty(out.Endpoint, link.Desired.Endpoint)
		out.Port = firstNonEmpty(out.Port, DebugEndpointPort(link.Desired.Endpoint))
		if rotateRuntimeMatchesDesired(out, *link.Desired) {
			out.LocalTunnelAddr = firstNonEmpty(out.LocalTunnelAddr, link.Desired.LocalTunnelAddr)
			out.PeerTunnelAddr = firstNonEmpty(out.PeerTunnelAddr, link.Desired.PeerTunnelAddr)
		}
	}
	if spec != nil {
		out.Generation = firstNonZeroUint64(out.Generation, spec.Generation)
		out.Port = firstNonEmpty(out.Port, DebugRemotePort(spec, ""))
		out.RuntimeID = firstNonEmpty(out.RuntimeID, spec.TransportID)
		out.ChildSAName = firstNonEmpty(out.ChildSAName, ipsec.ChildSAName(*spec))
		out.InterfaceName = firstNonEmpty(out.InterfaceName, spec.InterfaceName)
		out.XFRMIfID = firstNonZeroUint32(out.XFRMIfID, spec.XFRMIfID)
		out.Endpoint = firstNonEmpty(out.Endpoint, debugContactEndpoint(spec.ContactPoints))
		if rotateRuntimeMatchesSpec(out, *spec) {
			out.LocalTunnelAddr = firstNonEmpty(out.LocalTunnelAddr, ipsec.FormatScopedTunnelAddress(spec.LocalTunnelAddr, spec.InterfaceName, spec.NetNS))
			out.PeerTunnelAddr = firstNonEmpty(out.PeerTunnelAddr, ipsec.FormatScopedTunnelAddress(spec.PeerTunnelAddr, spec.InterfaceName, spec.NetNS))
		}
	}
	return out
}

func RotateRuntimeStaged(link LinkView, spec *ipsec.TransportLinkSpec, sas []LinkSA) RotateRuntimeView {
	generation := link.Rotation.StagedGeneration
	if generation == 0 {
		return RotateRuntimeView{}
	}
	out := RotateRuntimeView{
		State:           "expected_new",
		Generation:      generation,
		Port:            DebugStagedPort(spec, generation),
		RuntimeID:       link.Rotation.StagedIKEName,
		ChildSAName:     link.Rotation.StagedChildSAName,
		InterfaceName:   link.Rotation.StagedInterfaceName,
		XFRMIfID:        link.Rotation.StagedXFRMIfID,
		LocalTunnelAddr: link.Rotation.StagedLocalTunnelAddr,
		PeerTunnelAddr:  link.Rotation.StagedPeerTunnelAddr,
	}
	linkID := link.LinkID
	provider := ipsec.ProviderStrongSwan
	if spec != nil {
		linkID = firstNonEmpty(linkID, spec.LinkID)
		provider = firstNonEmpty(spec.Provider, provider)
	}
	if linkID != "" {
		out.RuntimeID = firstNonEmpty(out.RuntimeID, ipsec.RuntimeConnectionID(linkID, generation, provider))
		out.XFRMIfID = firstNonZeroUint32(out.XFRMIfID, ipsec.RuntimeXFRMIfID(linkID, generation, provider))
		out.InterfaceName = firstNonEmpty(out.InterfaceName, ipsec.StableInterfaceName(out.XFRMIfID))
	}
	if out.RuntimeID != "" {
		out.ChildSAName = firstNonEmpty(out.ChildSAName, out.RuntimeID+"-child")
	}
	if sa, ok := stagedSAForRuntime(out, sas); ok {
		out.Endpoint = firstNonEmpty(out.Endpoint, firstNonEmpty(sa.RemoteEndpoint, sa.Endpoint))
		out.Port = firstNonEmpty(out.Port, DebugEndpointPort(firstNonEmpty(sa.RemoteEndpoint, sa.Endpoint)))
	}
	return out
}

func MatchingRotateSAs(link LinkView, sas []LinkSA) []LinkSA {
	out := make([]LinkSA, 0, len(sas))
	for _, sa := range sas {
		if RotateSAMatchesLink(link, sa) {
			out = append(out, sa)
		}
	}
	return out
}

func RotateSAMatchesLink(link LinkView, sa LinkSA) bool {
	if !linkSAMatchesPathKey(link, sa) {
		return false
	}
	if sa.XFRMIfID != 0 && (sa.XFRMIfID == link.XFRMIfID || sa.XFRMIfID == link.Rotation.StagedXFRMIfID) {
		return true
	}
	return nonEmptyMatches(link.ID, sa.Name, sa.ChildSA) ||
		nonEmptyMatches(link.IKEName, sa.Name, sa.ChildSA) ||
		nonEmptyMatches(link.TransportID, sa.Name, sa.ChildSA) ||
		nonEmptyMatches(link.ChildSAName, sa.Name, sa.ChildSA) ||
		nonEmptyMatches(link.Rotation.StagedIKEName, sa.Name, sa.ChildSA) ||
		nonEmptyMatches(link.Rotation.StagedChildSAName, sa.Name, sa.ChildSA)
}

func stagedSAForRuntime(runtime RotateRuntimeView, sas []LinkSA) (LinkSA, bool) {
	for _, sa := range sas {
		if runtime.XFRMIfID != 0 && sa.XFRMIfID == runtime.XFRMIfID {
			return sa, true
		}
		if nonEmptyMatches(runtime.RuntimeID, sa.Name, sa.ChildSA) ||
			nonEmptyMatches(runtime.ChildSAName, sa.Name, sa.ChildSA) {
			return sa, true
		}
	}
	return LinkSA{}, false
}

func rotateRuntimeMatchesDesired(runtime RotateRuntimeView, desired DesiredLink) bool {
	if desired.InterfaceName != "" && runtime.InterfaceName != "" && desired.InterfaceName != runtime.InterfaceName {
		return false
	}
	if desired.XFRMIfID != 0 && runtime.XFRMIfID != 0 && desired.XFRMIfID != runtime.XFRMIfID {
		return false
	}
	if desired.TransportID != "" && runtime.RuntimeID != "" && desired.TransportID != runtime.RuntimeID {
		return false
	}
	return true
}

func rotateRuntimeMatchesSpec(runtime RotateRuntimeView, spec ipsec.TransportLinkSpec) bool {
	if spec.InterfaceName != "" && runtime.InterfaceName != "" && spec.InterfaceName != runtime.InterfaceName {
		return false
	}
	if spec.XFRMIfID != 0 && runtime.XFRMIfID != 0 && spec.XFRMIfID != runtime.XFRMIfID {
		return false
	}
	if spec.TransportID != "" && runtime.RuntimeID != "" && spec.TransportID != runtime.RuntimeID {
		return false
	}
	return true
}

func linkSAMatchesPathKey(link LinkView, sa LinkSA) bool {
	family := debugPathKeyFamily(link.PathKey)
	if family == "" {
		return true
	}
	endpointFamily := debugSAEndpointFamily(sa)
	return endpointFamily == "" || endpointFamily == family
}

func debugPathKeyFamily(pathKey string) string {
	if !strings.HasPrefix(pathKey, "family:") {
		return ""
	}
	family := strings.TrimPrefix(pathKey, "family:")
	if family == ipsec.FamilyIPv4 || family == ipsec.FamilyIPv6 {
		return family
	}
	return ""
}

func debugSAEndpointFamily(sa LinkSA) string {
	endpoint := firstNonEmpty(sa.RemoteEndpoint, sa.Endpoint)
	host := debugEndpointHost(endpoint)
	if host == "" {
		return ""
	}
	return debugIPsecFamily(host)
}

func debugEndpointHost(endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(endpoint); err == nil {
		return strings.Trim(host, "[]")
	}
	if strings.HasPrefix(endpoint, "[") {
		if end := strings.Index(endpoint, "]"); end > 1 {
			return endpoint[1:end]
		}
	}
	return endpoint
}

func debugIPsecFamily(addr string) string {
	ip := net.ParseIP(strings.Trim(addr, "[]"))
	if ip == nil {
		return ""
	}
	if ip.To4() != nil {
		return ipsec.FamilyIPv4
	}
	return ipsec.FamilyIPv6
}

func debugContactEndpoint(points []ipsec.ContactPoint) string {
	for _, point := range points {
		host := firstNonEmpty(point.Address, point.Host)
		port := point.NATTPort
		if port == 0 {
			port = point.IKEPort
		}
		if host == "" || port == 0 {
			continue
		}
		return net.JoinHostPort(host, uint16String(port))
	}
	return ""
}

func nonEmptyMatches(filter string, values ...string) bool {
	filter = strings.ToLower(strings.TrimSpace(filter))
	if filter == "" {
		return false
	}
	for _, value := range values {
		if strings.Contains(strings.ToLower(value), filter) {
			return true
		}
	}
	return false
}

func firstNonZeroUint64(values ...uint64) uint64 {
	for _, value := range values {
		if value != 0 {
			return value
		}
	}
	return 0
}
