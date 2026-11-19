package photonwindows

import (
	"hash/fnv"
	"net/netip"
	"time"

	"github.com/HiggsNet/photon/internal/photonclient/babel"
	"github.com/HiggsNet/photon/internal/photonclient/sadr"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

const (
	meshRouteSwitchMargin = 24
	meshRouteSwitchDelay  = 30 * time.Second
	meshRouteSelectionTTL = 2 * time.Minute
)

// The actual local address matters when peers have different signed policies.
// One history covers all destinations in the same destination/source prefix pair.
type meshRouteKey struct {
	source netip.Addr
	origin babel.Origin
}

type meshRoutePath struct {
	leaf     *babel.Leaf
	identity babel.RouteIdentity
	routerID [8]byte
}

type meshRouteCandidate struct {
	path   meshRoutePath
	metric uint16
}

type meshRouteSelection struct {
	current  meshRoutePath
	better   map[meshRoutePath]time.Time
	lastUsed time.Time
}

func newMeshRouteCandidate(leaf *babel.Leaf, origin babel.Origin, route sadr.Route) meshRouteCandidate {
	return meshRouteCandidate{path: meshRoutePath{leaf, leaf.RouteIdentity(origin), route.RouterID}, metric: route.Metric}
}

// selectMetric keeps an available incumbent while measuring each challenger's
// continuous improvement. Callers only pass live paths for the same prefix pair.
func (s *meshRouteSelection) selectMetric(candidates []meshRouteCandidate, now time.Time) uint16 {
	best := candidates[0]
	var current meshRouteCandidate
	for _, candidate := range candidates {
		if candidate.metric < best.metric {
			best = candidate
		}
		if candidate.path.leaf == s.current.leaf && candidate.path.identity == s.current.identity {
			current = candidate
		}
	}
	if current.path.leaf == nil {
		current = best
	}
	if current.path != s.current {
		s.current = current.path
		clear(s.better)
	}

	// Remove timers for paths that disappeared or lost the required advantage.
	for path := range s.better {
		qualifies := false
		for _, candidate := range candidates {
			if candidate.path == path {
				qualifies = int(current.metric)-int(candidate.metric) >= meshRouteSwitchMargin
				break
			}
		}
		if !qualifies {
			delete(s.better, path)
		}
	}
	best = current
	for _, candidate := range candidates {
		if int(current.metric)-int(candidate.metric) < meshRouteSwitchMargin {
			continue
		}
		since, ok := s.better[candidate.path]
		if !ok {
			if s.better == nil {
				s.better = make(map[meshRoutePath]time.Time)
			}
			s.better[candidate.path] = now
		} else if now.Sub(since) >= meshRouteSwitchDelay && candidate.metric < best.metric {
			best = candidate
		}
	}
	if best.path != current.path {
		s.current = best.path
		clear(s.better)
		for _, candidate := range candidates {
			if int(best.metric)-int(candidate.metric) >= meshRouteSwitchMargin {
				s.better[candidate.path] = now
			}
		}
	}
	return best.metric
}

func (m *meshRuntime) chooseMeshRoute(choices []meshChoice, now time.Time) meshChoice {
	first := choices[0]
	key := meshRouteKey{first.flow.source, babel.Origin{Prefix: first.route.Destination, SourcePrefix: first.route.Source}}
	selection := m.routeSelections[key]
	if selection == nil {
		selection = &meshRouteSelection{}
		if len(m.routeSelections) < sadr.MaxRoutes {
			if m.routeSelections == nil {
				m.routeSelections = make(map[meshRouteKey]*meshRouteSelection)
			}
			m.routeSelections[key] = selection
		}
	}
	selection.lastUsed = now
	var buf [4]meshRouteCandidate
	candidates := buf[:0]
	for _, choice := range choices {
		candidates = append(candidates, newMeshRouteCandidate(choice.facts.owner.leaf, key.origin, choice.route))
	}
	metric := selection.selectMetric(candidates, now)
	// Preserve the stable address hash for paths at the selected cost.
	ties := choices[:0]
	for _, choice := range choices {
		if choice.route.Metric == metric {
			ties = append(ties, choice)
		}
	}
	if len(ties) == 1 {
		return ties[0]
	}
	hash := fnv.New32a()
	_, _ = hash.Write(first.flow.source.AsSlice())
	_, _ = hash.Write(first.flow.destination.AsSlice())
	return ties[int(hash.Sum32()%uint32(len(ties)))]
}

// Control changes and the existing tunnel timer keep active prefix histories
// current even if there is no host traffic or the peer repeats its last Update.
func (m *meshRuntime) refreshRouteSelections(view corestate.View, now time.Time) {
	if len(m.routeSelections) == 0 {
		return
	}
	var prepared [4]packetAuthorization
	peers := prepared[:0]
	for _, p := range m.ordered() {
		var facts packetAuthorization
		if m.packetFacts(p, view, now, &facts) {
			peers = append(peers, facts)
		}
	}
	var buf [4]meshRouteCandidate
	for key, selection := range m.routeSelections {
		if now.Sub(selection.lastUsed) >= meshRouteSelectionTTL {
			delete(m.routeSelections, key)
			continue
		}
		candidates := buf[:0]
		for _, facts := range peers {
			pipeline := facts.owner
			if !pipeline.localAddress(key.source, facts.localOrigins) {
				continue
			}
			route, ok := pipeline.leaf.CandidateForOrigin(key.origin, now)
			if ok && (facts.projection != nil || facts.authorizeRoute(route)) {
				candidates = append(candidates, newMeshRouteCandidate(pipeline.leaf, key.origin, route))
			}
		}
		if len(candidates) == 0 {
			delete(m.routeSelections, key)
			continue
		}
		selection.selectMetric(candidates, now)
	}
}
